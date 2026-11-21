//! The `reede` CLI's request and response logic for the lifecycle verbs:
//! argument parsing, configuration, URL building, the status -> exit-code mapping and the output
//! lines. Pure and always compiled; the HTTP calls themselves live in the binary behind the `cli`
//! feature, so a build without it carries no HTTP client.
//!
//! The verbs speak to the host-runs lifecycle API (`/api/v1/reede/tasks`, mounted in the host application
//! behind `REEDE_LIFECYCLE_API`). Its credential is a host application tenant credential (a JWT or an
//! API key), sent only as an `Authorization: Bearer` header: it is never printed, never logged,
//! never part of a URL and never part of an error message.

use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use url::Url;
use uuid::Uuid;

use crate::lease::CredentialLease;
use crate::task::Task;

/// The base URL of the lifecycle API (scheme, host, optional path prefix).
pub const ENV_API_URL: &str = "REEDE_API_URL";
/// The bearer credential: a host application tenant credential.
pub const ENV_TOKEN: &str = "REEDE_TOKEN";

/// The request succeeded (200/202), or `kill --wait` saw the run end.
pub const EXIT_OK: i32 = 0;
/// The server refused the request for what it is (404, 409, 501, other 4xx), or `kill --wait`
/// timed out.
pub const EXIT_REFUSED: i32 = 1;
/// Nothing was sent, or the credential was refused: a missing or invalid configuration, a usage
/// error, 401 or 403.
pub const EXIT_CONFIG: i32 = 2;
/// The server failed (5xx), answered something unexpected, or could not be reached.
pub const EXIT_SERVER: i32 = 3;

/// How often `kill --wait` reads the task, and for how long at most.
pub const WAIT_POLL_SECS: u64 = 2;
pub const WAIT_TIMEOUT_SECS: u64 = 120;

/// The routes' common prefix.
const TASKS_PATH: &str = "/api/v1/reede/tasks";

/// What `kill`, `tasks` and `lease` print when the binary was built without the HTTP client.
pub const CLI_NOT_AVAILABLE: &str = "NOT AVAILABLE: build reede with --features cli";

/// `policy`: honest about why it does not exist yet.
pub const POLICY_STUB: &str =
    "NOT IMPLEMENTED: no per-run policy is stored; the egress part needs \
the sandbox (F4c, FD3) and the read contract is F7a's OpenAPI";

/// `logs`: honest about why it does not exist.
pub const LOGS_STUB: &str = "NOT IMPLEMENTED: there is no log store; out of scope for F4";

/// The unit of `budget_envelope.reserved_credits` (F4-DESIGN Q2 / K9): metering credits, which
/// are tokens. Printed as is, never converted.
pub const CREDITS_UNIT: &str = "metering credits (tokens)";

/// `reede` with no or an unknown verb: every verb and whether it works.
pub const USAGE: &str = "\
Reede CLI - Sovereign Agent Runtime Control
Usage:
  reede deploy --manifest <agent.toml>          validate an agent manifest
  reede receipt verify --chain <receipts.json> [--pubkey <hex>] [--cafile <ca.pem>]
                                              verify hashes, supplied signatures and timestamps offline
  reede anchor verify --proof <proof.json> [--cafile <ca.pem>]
                                              verify a hosted BYOA proof: chain slice, Merkle inclusion, RFC 3161 anchor
  reede serve [--listen 127.0.0.1:4318] [--out <dir>] [--tenant local] [--allow-remote]
                                              seal OTLP spans into receipts (reported tier; needs --features ingest)
  reede ingest check --out <dir> [--pubkey <hex>]
                                              verify the chain and every span against its receipt (needs --features ingest)
  reede status                                  probe the local runtime environment
  reede tasks [--limit N]                       list this tenant's runs, newest first (needs --features cli)
  reede tasks <id>                              one run, as JSON (needs --features cli)
  reede kill <id> [--wait]                      request a run's cancel; --wait polls until it ends (needs --features cli)
  reede lease <id>                              list a run's credential leases (needs --features cli)
  reede policy                                  not implemented: no per-run policy is stored (F4c, F7a)
  reede logs                                    not implemented: there is no log store

The lifecycle verbs read REEDE_API_URL (or --api-url <url>) and REEDE_TOKEN (or --token <t>), a
tectic-core tenant credential sent as a bearer header. Prefer the variable: a flag's value is
visible to other users of this machine in the process list.
Exit codes: 0 ok; 1 refused (404, 409, 501) or --wait timed out; 2 configuration, usage, 401
or 403; 3 server error (5xx) or unreachable.";

/// A lifecycle verb and its arguments, as parsed from the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    /// `tasks [--limit N]`: `None` lets the server pick its default.
    ListTasks { limit: Option<u32> },
    /// `tasks <id>`.
    GetTask { id: Uuid },
    /// `kill <id> [--wait]`.
    Kill { id: Uuid, wait: bool },
    /// `lease <id>`.
    Leases { id: Uuid },
}

/// A parsed lifecycle invocation: the verb plus the configuration flags given on the command
/// line (which win over the environment).
#[derive(Clone, PartialEq, Eq)]
pub struct Invocation {
    pub verb: Verb,
    pub api_url: Option<String>,
    pub token: Option<String>,
}

impl fmt::Debug for Invocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invocation")
            .field("verb", &self.verb)
            .field("api_url", &self.api_url)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

/// A command line that names a lifecycle verb but cannot be run. The message never contains a
/// flag's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// True for the verbs [`parse_lifecycle`] handles.
pub fn is_lifecycle_verb(verb: &str) -> bool {
    matches!(verb, "tasks" | "kill" | "lease")
}

fn parse_id(raw: &str) -> Result<Uuid, UsageError> {
    Uuid::parse_str(raw).map_err(|_| UsageError(format!("not a task id (a UUID): {raw:?}")))
}

/// Parse `args` (the whole command line, `args[0]` the program, `args[1]` the verb).
pub fn parse_lifecycle(args: &[String]) -> Result<Invocation, UsageError> {
    let verb = args.get(1).map(String::as_str).unwrap_or_default();
    let mut api_url = None;
    let mut token = None;
    let mut limit = None;
    let mut wait = false;
    let mut positional: Vec<&str> = Vec::new();

    let mut rest = args.iter().skip(2);
    while let Some(arg) = rest.next() {
        let mut value = |flag: &str| {
            rest.next()
                .cloned()
                .ok_or_else(|| UsageError(format!("{flag} needs a value")))
        };
        match arg.as_str() {
            "--api-url" => api_url = Some(value("--api-url")?),
            "--token" => token = Some(value("--token")?),
            "--limit" => {
                let raw = value("--limit")?;
                match raw.parse::<u32>() {
                    Ok(n) if n > 0 => limit = Some(n),
                    _ => {
                        return Err(UsageError(format!(
                            "--limit must be a positive integer, not {raw:?}"
                        )))
                    }
                }
            }
            "--wait" => wait = true,
            flag if flag.starts_with("--") => {
                // `--token=SECRET` is not a recognised form: name the flag, never its value.
                let name = flag.split_once('=').map_or(flag, |(name, _)| name);
                return Err(UsageError(format!(
                    "unknown flag for `reede {verb}`: {name}"
                )));
            }
            other => positional.push(other),
        }
    }

    let verb = match (verb, positional.as_slice()) {
        ("tasks", []) => Verb::ListTasks { limit },
        ("tasks", [id]) if limit.is_none() => Verb::GetTask { id: parse_id(id)? },
        ("tasks", [_]) => return Err(UsageError("--limit applies to the listing only".into())),
        ("kill", [id]) => Verb::Kill {
            id: parse_id(id)?,
            wait,
        },
        ("lease", [id]) => Verb::Leases { id: parse_id(id)? },
        ("kill", _) => return Err(UsageError("usage: reede kill <id> [--wait]".into())),
        ("lease", _) => return Err(UsageError("usage: reede lease <id>".into())),
        ("tasks", _) => {
            return Err(UsageError(
                "usage: reede tasks [--limit N] | reede tasks <id>".into(),
            ))
        }
        (other, _) => return Err(UsageError(format!("not a lifecycle verb: {other}"))),
    };
    if wait && !matches!(verb, Verb::Kill { .. }) {
        return Err(UsageError("--wait applies to `reede kill` only".into()));
    }
    if limit.is_some() && !matches!(verb, Verb::ListTasks { .. }) {
        return Err(UsageError("--limit applies to `reede tasks` only".into()));
    }
    Ok(Invocation {
        verb,
        api_url,
        token,
    })
}

/// The lifecycle API's base URL and the credential. `Debug` never shows the credential.
#[derive(Clone)]
pub struct Config {
    base: Url,
    token: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("base", &self.base.as_str())
            .field("token", &"[redacted]")
            .finish()
    }
}

/// Why a configuration is unusable. The message names the variable or flag, never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

impl Config {
    /// The configuration from the flags, else the environment values (`env_url` is
    /// `REEDE_API_URL`, `env_token` is `REEDE_TOKEN`). An empty value counts as missing.
    pub fn resolve(
        flag_url: Option<String>,
        flag_token: Option<String>,
        env_url: Option<String>,
        env_token: Option<String>,
    ) -> Result<Config, ConfigError> {
        let raw_url = non_empty(flag_url).or(non_empty(env_url)).ok_or_else(|| {
            ConfigError(format!(
                "{ENV_API_URL} is not set (or pass --api-url <url>)"
            ))
        })?;
        let token = non_empty(flag_token)
            .or(non_empty(env_token))
            .ok_or_else(|| {
                ConfigError(format!(
                    "{ENV_TOKEN} is not set (or pass --token <credential>)"
                ))
            })?;
        // A header value must be visible ASCII; checked here so the failure is a configuration
        // error that names the variable, not a client error that might describe the value.
        if !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ConfigError(format!(
                "{ENV_TOKEN} is not a valid bearer credential (it must be printable ASCII without spaces)"
            )));
        }
        // The URL is not echoed: a malformed one may carry a credential.
        let base = Url::parse(raw_url.trim())
            .map_err(|_| ConfigError(format!("{ENV_API_URL} is not a valid URL")))?;
        if !matches!(base.scheme(), "http" | "https") || base.host_str().is_none() {
            return Err(ConfigError(format!(
                "{ENV_API_URL} must be an http or https URL with a host"
            )));
        }
        if !base.username().is_empty() || base.password().is_some() {
            return Err(ConfigError(format!(
                "{ENV_API_URL} must not carry credentials; the credential goes in {ENV_TOKEN}"
            )));
        }
        if base.query().is_some() || base.fragment().is_some() {
            return Err(ConfigError(format!(
                "{ENV_API_URL} must not have a query or a fragment"
            )));
        }
        Ok(Config { base, token })
    }

    /// The bearer credential, for the `Authorization` header only.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// `text` with every occurrence of the credential replaced. Applied to everything the CLI
    /// prints that it did not write itself (server bodies, transport errors).
    pub fn redact(&self, text: &str) -> String {
        redact(text, &self.token)
    }

    fn url(&self, tail: &str) -> Url {
        let mut url = self.base.clone();
        let prefix = url.path().trim_end_matches('/').to_owned();
        url.set_path(&format!("{prefix}{TASKS_PATH}{tail}"));
        url
    }

    /// `GET /api/v1/reede/tasks[?limit=N]`.
    pub fn list_url(&self, limit: Option<u32>) -> Url {
        let mut url = self.url("");
        if let Some(limit) = limit {
            url.query_pairs_mut()
                .append_pair("limit", &limit.to_string());
        }
        url
    }

    /// `GET /api/v1/reede/tasks/:id`.
    pub fn task_url(&self, id: Uuid) -> Url {
        self.url(&format!("/{id}"))
    }

    /// `POST /api/v1/reede/tasks/:id/cancel`.
    pub fn cancel_url(&self, id: Uuid) -> Url {
        self.url(&format!("/{id}/cancel"))
    }

    /// `GET /api/v1/reede/tasks/:id/leases`.
    pub fn leases_url(&self, id: Uuid) -> Url {
        self.url(&format!("/{id}/leases"))
    }
}

/// `text` with every occurrence of `secret` replaced by `[redacted]`.
pub fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_owned();
    }
    text.replace(secret, "[redacted]")
}

/// The exit code for an HTTP answer.
pub fn exit_code_for_status(status: u16) -> i32 {
    match status {
        200..=299 => EXIT_OK,
        401 | 403 => EXIT_CONFIG,
        400..=499 | 501 => EXIT_REFUSED,
        // 5xx, and anything a client following no redirects should never see (1xx, 3xx).
        _ => EXIT_SERVER,
    }
}

/// The stderr line for an answer that is not a success. `body` is the server's text, already
/// redacted, shown as the server wrote it (trimmed).
pub fn describe_failure(subject: &str, status: u16, body: &str) -> String {
    let why = match status {
        401 => "the credential was refused (401): check REEDE_TOKEN",
        403 => "the tenant may not do this (403)",
        404 => "not found for this tenant (404)",
        409 => "the run has already ended (409)",
        501 => "the server does not implement this (501)",
        400..=499 => "the request was refused",
        500..=599 => "the server failed",
        _ => "unexpected answer",
    };
    let body = body.trim();
    if body.is_empty() {
        format!("{subject}: {why} [HTTP {status}]")
    } else {
        format!("{subject}: {why} [HTTP {status}]: {body}")
    }
}

fn rfc3339(at: &DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// One line of `reede tasks`: id, state, agent, created, reserved credits, and the cancel
/// request when there is one.
pub fn task_line(task: &Task) -> String {
    let mut line = format!(
        "{}  {:?}  {}  {}  reserved {} {}",
        task.id,
        task.state,
        task.agent_spec_id,
        rfc3339(&task.created_at),
        task.budget_envelope.reserved_credits,
        CREDITS_UNIT,
    );
    if task.cancel_requested_at.is_some() {
        line.push_str("  cancel requested");
    }
    line
}

/// What `reede kill` prints on 202.
pub fn kill_accepted_line(task: &Task) -> String {
    if task.state.is_terminal() {
        format!(
            "cancel requested for task {}: the run has ended: {:?}",
            task.id, task.state
        )
    } else {
        format!(
            "cancel requested for task {}: now {:?}; its host ends the run and settles the {} reserved {}",
            task.id, task.state, task.budget_envelope.reserved_credits, CREDITS_UNIT
        )
    }
}

/// What `reede kill --wait` prints when the run has ended.
pub fn kill_ended_line(task: &Task) -> String {
    format!("task {} ended: {:?}", task.id, task.state)
}

/// What `reede kill --wait` prints when the run is still live after [`WAIT_TIMEOUT_SECS`].
pub fn kill_timeout_line(task: &Task) -> String {
    format!(
        "task {} is still {:?} after {WAIT_TIMEOUT_SECS} s; the cancel request stands and its host will end the run",
        task.id, task.state
    )
}

/// A lease's standing at `now`.
pub fn lease_status(lease: &CredentialLease, now: DateTime<Utc>) -> &'static str {
    if lease.revoked {
        "revoked"
    } else if now >= lease.expires_at {
        "expired"
    } else {
        "live"
    }
}

/// One line of `reede lease`: id, secret reference, issued, expires, standing.
pub fn lease_line(lease: &CredentialLease, now: DateTime<Utc>) -> String {
    format!(
        "{}  {}  issued {}  expires {}  {}",
        lease.id.0,
        lease.secret_ref,
        rfc3339(&lease.issued_at),
        rfc3339(&lease.expires_at),
        lease_status(lease, now),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::LeaseId;
    use crate::task::TaskState;
    use chrono::Duration;

    const TOKEN: &str = "unit-test-credential-0001";

    fn config(base: &str) -> Config {
        Config::resolve(Some(base.into()), Some(TOKEN.into()), None, None).unwrap()
    }

    fn args(list: &[&str]) -> Vec<String> {
        std::iter::once("reede")
            .chain(list.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn an_unknown_flag_with_an_equals_value_is_named_without_its_value() {
        for flag in ["--token=SECRETX", "--api-url=https://u:SECRETX@h"] {
            let err = parse_lifecycle(&args(&[
                "kill",
                flag,
                "6f2c1c3e-8a77-4d0b-9a59-1f3f6c1b2a10",
            ]))
            .unwrap_err();
            assert!(!err.0.contains("SECRETX"), "{}", err.0);
            assert!(err.0.contains(flag.split('=').next().unwrap()), "{}", err.0);
        }
    }

    #[test]
    fn urls_are_built_under_the_base_with_or_without_a_prefix() {
        let id = Uuid::parse_str("6f2c1c3e-8a77-4d0b-9a59-1f3f6c1b2a10").unwrap();
        for base in ["https://api.example.test", "https://api.example.test/"] {
            let c = config(base);
            assert_eq!(
                c.list_url(None).as_str(),
                "https://api.example.test/api/v1/reede/tasks"
            );
            assert_eq!(
                c.list_url(Some(7)).as_str(),
                "https://api.example.test/api/v1/reede/tasks?limit=7"
            );
            assert_eq!(
                c.task_url(id).as_str(),
                format!("https://api.example.test/api/v1/reede/tasks/{id}")
            );
            assert_eq!(
                c.cancel_url(id).as_str(),
                format!("https://api.example.test/api/v1/reede/tasks/{id}/cancel")
            );
            assert_eq!(
                c.leases_url(id).as_str(),
                format!("https://api.example.test/api/v1/reede/tasks/{id}/leases")
            );
        }
        let prefixed = config("http://127.0.0.1:9000/core/");
        assert_eq!(
            prefixed.cancel_url(id).as_str(),
            format!("http://127.0.0.1:9000/core/api/v1/reede/tasks/{id}/cancel")
        );
        for url in [
            prefixed.list_url(Some(3)),
            prefixed.task_url(id),
            prefixed.leases_url(id),
        ] {
            assert!(!url.as_str().contains(TOKEN), "{url}");
        }
    }

    #[test]
    fn statuses_map_to_exit_codes() {
        for (status, code) in [
            (200, EXIT_OK),
            (202, EXIT_OK),
            (401, EXIT_CONFIG),
            (403, EXIT_CONFIG),
            (404, EXIT_REFUSED),
            (409, EXIT_REFUSED),
            (400, EXIT_REFUSED),
            (501, EXIT_REFUSED),
            (500, EXIT_SERVER),
            (502, EXIT_SERVER),
            (503, EXIT_SERVER),
            (599, EXIT_SERVER),
            (302, EXIT_SERVER),
        ] {
            assert_eq!(exit_code_for_status(status), code, "status {status}");
        }
    }

    #[test]
    fn the_stubs_say_why() {
        assert!(POLICY_STUB.starts_with("NOT IMPLEMENTED: "));
        assert!(POLICY_STUB.contains("no per-run policy is stored"));
        assert!(POLICY_STUB.contains("sandbox (F4c, FD3)"));
        assert!(POLICY_STUB.contains("F7a"));
        assert_eq!(
            LOGS_STUB,
            "NOT IMPLEMENTED: there is no log store; out of scope for F4"
        );
        assert_eq!(
            CLI_NOT_AVAILABLE,
            "NOT AVAILABLE: build reede with --features cli"
        );
        for verb in [
            "deploy",
            "receipt verify",
            "status",
            "tasks",
            "kill",
            "lease",
            "policy",
            "logs",
        ] {
            assert!(
                USAGE.contains(&format!("reede {verb}")),
                "{verb} missing from usage"
            );
        }
    }

    #[test]
    fn configuration_needs_both_values_and_never_names_the_credential() {
        let missing_url = Config::resolve(None, None, None, Some(TOKEN.into())).unwrap_err();
        assert!(missing_url.0.contains(ENV_API_URL));
        let missing_token =
            Config::resolve(None, None, Some("https://x.test".into()), Some("  ".into()))
                .unwrap_err();
        assert!(missing_token.0.contains(ENV_TOKEN));

        let with_userinfo = Config::resolve(
            None,
            None,
            Some(format!("https://user:{TOKEN}@x.test")),
            Some(TOKEN.into()),
        )
        .unwrap_err();
        let bad_scheme = Config::resolve(
            None,
            None,
            Some(format!("ftp://x.test/{TOKEN}")),
            Some(TOKEN.into()),
        )
        .unwrap_err();
        let unparsable =
            Config::resolve(None, None, Some(format!("::{TOKEN}")), Some(TOKEN.into()))
                .unwrap_err();
        let with_query = Config::resolve(
            None,
            None,
            Some(format!("https://x.test/?t={TOKEN}")),
            Some(TOKEN.into()),
        )
        .unwrap_err();
        let spaced = Config::resolve(
            None,
            None,
            Some("https://x.test".into()),
            Some(format!("{TOKEN} x")),
        )
        .unwrap_err();
        for error in [with_userinfo, bad_scheme, unparsable, with_query, spaced] {
            assert!(!error.0.contains(TOKEN), "{error}");
        }

        // The flag wins over the environment.
        let c = Config::resolve(
            Some("https://flag.test".into()),
            Some("flag-token".into()),
            Some("https://env.test".into()),
            Some(TOKEN.into()),
        )
        .unwrap();
        assert_eq!(c.token(), "flag-token");
        assert_eq!(c.list_url(None).host_str(), Some("flag.test"));
        assert!(!format!("{c:?}").contains("flag-token"));
    }

    #[test]
    fn arguments_parse_and_bad_ones_are_refused() {
        let id = Uuid::new_v4();
        let s = id.to_string();
        assert_eq!(
            parse_lifecycle(&args(&["tasks"])).unwrap().verb,
            Verb::ListTasks { limit: None }
        );
        assert_eq!(
            parse_lifecycle(&args(&["tasks", "--limit", "7"]))
                .unwrap()
                .verb,
            Verb::ListTasks { limit: Some(7) }
        );
        assert_eq!(
            parse_lifecycle(&args(&["tasks", &s])).unwrap().verb,
            Verb::GetTask { id }
        );
        assert_eq!(
            parse_lifecycle(&args(&["kill", &s])).unwrap().verb,
            Verb::Kill { id, wait: false }
        );
        assert_eq!(
            parse_lifecycle(&args(&["kill", "--wait", &s]))
                .unwrap()
                .verb,
            Verb::Kill { id, wait: true }
        );
        assert_eq!(
            parse_lifecycle(&args(&["lease", &s])).unwrap().verb,
            Verb::Leases { id }
        );

        let flagged = parse_lifecycle(&args(&[
            "lease",
            &s,
            "--api-url",
            "https://x.test",
            "--token",
            TOKEN,
        ]))
        .unwrap();
        assert_eq!(flagged.api_url.as_deref(), Some("https://x.test"));
        assert_eq!(flagged.token.as_deref(), Some(TOKEN));
        assert!(!format!("{flagged:?}").contains(TOKEN));

        for bad in [
            &["kill"][..],
            &["kill", "not-a-uuid"],
            &["kill", &s, &s],
            &["lease"],
            &["tasks", "--limit", "0"],
            &["tasks", "--limit", "-3"],
            &["tasks", "--limit"],
            &["tasks", &s, "--limit", "3"],
            &["lease", &s, "--wait"],
            &["kill", &s, "--bogus"],
            &["kill", &s, "--token"],
        ] {
            let error = parse_lifecycle(&args(bad)).unwrap_err();
            assert!(!error.0.is_empty(), "{bad:?}");
        }
    }

    fn task(state: TaskState, reserved: i64, cancel: bool) -> Task {
        let mut t = Task::new(Uuid::new_v4(), "tenant-a", "factcheck-agent", 1.0);
        t.state = state;
        t.budget_envelope.reserved_credits = reserved;
        if cancel {
            t.cancel_requested_at = Some(Utc::now());
        }
        t
    }

    #[test]
    fn task_lines_label_the_credits_and_the_request() {
        let live = task(TaskState::Running, 100, false);
        let line = task_line(&live);
        assert!(line.starts_with(&live.id.to_string()));
        assert!(line.contains("  Running  factcheck-agent  "));
        assert!(line.contains("reserved 100 metering credits (tokens)"));
        assert!(!line.contains("cancel requested"));
        assert!(task_line(&task(TaskState::Running, 100, true)).ends_with("  cancel requested"));

        assert_eq!(
            kill_accepted_line(&live),
            format!(
                "cancel requested for task {}: now Running; its host ends the run and settles the 100 reserved metering credits (tokens)",
                live.id
            )
        );
        let ended = task(TaskState::Killed, 100, true);
        assert!(kill_accepted_line(&ended).ends_with("the run has ended: Killed"));
        assert!(kill_ended_line(&ended).ends_with("ended: Killed"));
        assert!(kill_timeout_line(&live).contains("still Running after 120 s"));
    }

    #[test]
    fn lease_lines_tell_live_revoked_and_expired_apart() {
        let now = Utc::now();
        let lease = |revoked: bool, expires_in: i64| CredentialLease {
            id: LeaseId(Uuid::new_v4()),
            task_id: Uuid::new_v4(),
            secret_ref: "mcp:gmail".into(),
            issued_at: now - Duration::minutes(5),
            expires_at: now + Duration::minutes(expires_in),
            revoked,
        };
        assert_eq!(lease_status(&lease(false, 10), now), "live");
        assert_eq!(lease_status(&lease(true, 10), now), "revoked");
        assert_eq!(lease_status(&lease(false, -1), now), "expired");
        assert_eq!(lease_status(&lease(true, -1), now), "revoked");
        let l = lease(false, 10);
        let line = lease_line(&l, now);
        assert!(line.starts_with(&l.id.0.to_string()));
        assert!(line.contains("  mcp:gmail  issued "));
        assert!(line.ends_with("  live"));
    }

    #[test]
    fn failures_are_described_and_secrets_redacted() {
        assert_eq!(
            describe_failure("kill x", 409, " the run has ended: Succeeded \n"),
            "kill x: the run has already ended (409) [HTTP 409]: the run has ended: Succeeded"
        );
        assert_eq!(
            describe_failure("kill x", 404, ""),
            "kill x: not found for this tenant (404) [HTTP 404]"
        );
        assert!(describe_failure("tasks", 401, "").contains("REEDE_TOKEN"));
        assert!(!describe_failure("tasks", 401, "").contains(TOKEN));
        assert_eq!(
            redact(&format!("echo {TOKEN} and {TOKEN}"), TOKEN),
            "echo [redacted] and [redacted]"
        );
        assert_eq!(redact("nothing", ""), "nothing");
        assert_eq!(
            config("https://x.test").redact(&format!("a{TOKEN}b")),
            "a[redacted]b"
        );
    }
}
