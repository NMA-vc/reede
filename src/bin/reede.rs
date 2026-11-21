mod verification;

use reede::cli;
use reede::isolation::active_proxies;
use reede::spec::parse_manifest_v1;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{exit, Command};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        match args[1].as_str() {
            "--help" | "-h" => {
                print_usage();
                exit(0);
            }
            "--version" | "-V" => {
                println!("reede {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            _ => {}
        }
    }
    if args.len() < 2 {
        print_usage();
        exit(1);
    }

    match args[1].as_str() {
        "deploy" => {
            let mut manifest_path = None;
            let mut i = 2;
            while i < args.len() {
                if (args[i] == "--manifest" || args[i] == "-m") && i + 1 < args.len() {
                    manifest_path = Some(args[i + 1].as_str());
                    i += 1;
                }
                i += 1;
            }

            let path = match manifest_path {
                Some(p) => p,
                None => {
                    eprintln!("Usage: reede deploy --manifest <agent.toml>");
                    exit(1);
                }
            };

            let content = match fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error reading manifest file '{path}': {e}");
                    exit(1);
                }
            };

            match parse_manifest_v1(&content) {
                Ok(spec) => {
                    println!(
                        "VALIDATED: Agent '{}' (v{}) passed manifest validation; no deployment was performed.",
                        spec.agent.id, spec.agent.version
                    );
                    println!("  Author: {}", spec.meta.author);
                    println!("  Model Provider: {}", spec.agent.model.provider);
                    println!(
                        "  Budget Ceiling: {:.2} EUR",
                        spec.agent.limits.monthly_budget_eur
                    );
                    exit(0);
                }
                Err(e) => {
                    eprintln!("FAIL: Deploy-time validation gate rejected manifest: {e}");
                    exit(1);
                }
            }
        }
        "receipt" => {
            if args.get(2).is_some_and(|arg| arg == "verify") {
                if args.len() == 4 {
                    match args[3].as_str() {
                        "--help" | "-h" => {
                            verification::print_help("reede receipt verify");
                            exit(0);
                        }
                        "--version" | "-V" => {
                            println!("reede receipt verify {}", env!("CARGO_PKG_VERSION"));
                            exit(0);
                        }
                        _ => {}
                    }
                }
                exit(verification::run(&args[2..]));
            }
            print_usage();
            exit(1);
        }
        "anchor" => exit(verification::run_anchor(&args[1..])),
        "serve" | "ingest" => exit(ingest_cli(&args).await),
        "status" => {
            println!("STATUS: Reede Sovereign Runtime Environment Probes");

            // Probe 1: Check runsc binary availability
            let runsc_path = "/usr/local/bin/runsc";
            let runsc_exists = Path::new(runsc_path).exists();
            if runsc_exists {
                match Command::new(runsc_path).arg("--version").output() {
                    Ok(out) if out.status.success() => {
                        let version_str = String::from_utf8_lossy(&out.stdout);
                        let first_line = version_str.lines().next().unwrap_or("runsc present");
                        println!("  gVisor runsc: {}", first_line.trim());
                    }
                    _ => println!("  gVisor runsc: present at {runsc_path} (version check failed)"),
                }
            } else {
                println!("  gVisor runsc: NOT FOUND at {runsc_path}");
            }

            // Probe 2: Check Egress Wall dynamic listener state
            let active_proxies_count = active_proxies().lock().map(|m| m.len()).unwrap_or(0);
            if active_proxies_count > 0 {
                println!("  Egress Wall: Active ({active_proxies_count} container sandbox proxy listener(s))");
            } else {
                println!("  Egress Wall: NOT WIRED (0 active container sandbox proxy listeners)");
            }

            // Probe 3: Check SurrealDB Ledger environment configuration
            let surreal_url = env::var("SURREAL_URL").ok();
            match surreal_url {
                Some(url) => println!("  Ledger Database: Configured target ({url})"),
                None => println!("  Ledger Database: Unset (SURREAL_URL missing)"),
            }

            // Probe 4: Check Signing Key & TSA_URL configuration
            let signing_key = env::var("AGENT_SIGNING_KEY").ok();
            if signing_key.is_some() {
                println!("  Receipt Signing Key: Present (AGENT_SIGNING_KEY set)");
            } else {
                println!("  Receipt Signing Key: Unset (AGENT_SIGNING_KEY missing)");
            }

            let tsa_url = env::var("TSA_URL").ok();
            match tsa_url {
                Some(url) => println!("  TSA Timestamp Authority: Configured ({url})"),
                None => println!("  TSA Timestamp Authority: Unset (TSA_URL missing)"),
            }

            exit(0);
        }
        verb if cli::is_lifecycle_verb(verb) => exit(lifecycle(&args).await),
        "policy" => {
            eprintln!("{}", cli::POLICY_STUB);
            exit(1);
        }
        "logs" => {
            eprintln!("{}", cli::LOGS_STUB);
            exit(1);
        }
        _ => {
            print_usage();
            exit(1);
        }
    }
}

fn print_usage() {
    println!("{}", cli::USAGE);
    println!(
        "Receipt verification options: --strict, --json, --expected-head <hash>, \
         --expected-tenant <id>, --expected-count <n>, --require-genesis.\n\
         Run `reede receipt verify --help` for details."
    );
}

/// `tasks`, `kill`, `lease` without the HTTP client: say how to get it.
#[cfg(not(feature = "cli"))]
async fn lifecycle(_args: &[String]) -> i32 {
    eprintln!("{}", cli::CLI_NOT_AVAILABLE);
    1
}

/// `tasks`, `kill`, `lease` over the lifecycle API. Returns the exit code (see `cli::USAGE`).
#[cfg(feature = "cli")]
async fn lifecycle(args: &[String]) -> i32 {
    let invocation = match cli::parse_lifecycle(args) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("reede: {error}");
            return cli::EXIT_CONFIG;
        }
    };
    let config = match cli::Config::resolve(
        invocation.api_url,
        invocation.token,
        env::var(cli::ENV_API_URL).ok(),
        env::var(cli::ENV_TOKEN).ok(),
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("reede: {error}");
            return cli::EXIT_CONFIG;
        }
    };
    let api = match http::Api::new(config) {
        Ok(api) => api,
        Err(code) => return code,
    };
    let result = match invocation.verb {
        cli::Verb::ListTasks { limit } => http::list_tasks(&api, limit).await,
        cli::Verb::GetTask { id } => http::get_task(&api, id).await,
        cli::Verb::Kill { id, wait } => http::kill(&api, id, wait).await,
        cli::Verb::Leases { id } => http::leases(&api, id).await,
    };
    match result {
        Ok(()) => cli::EXIT_OK,
        Err(code) => code,
    }
}

/// The HTTP side of the lifecycle verbs. Every failure is printed here (to stderr, redacted)
/// and carried out as its exit code.
#[cfg(feature = "cli")]
mod http {
    use std::time::{Duration, Instant};

    use reede::cli::{self, Config};
    use reede::lease::CredentialLease;
    use reede::task::Task;
    use reqwest::{Client, Method};
    use serde::de::DeserializeOwned;
    use uuid::Uuid;

    /// One request's ceiling, so an unresponsive server cannot hang the CLI.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    pub struct Api {
        client: Client,
        config: Config,
    }

    impl Api {
        pub fn new(config: Config) -> Result<Api, i32> {
            // No redirects: a redirect would be followed with the credential attached, to a
            // place the operator did not name.
            let client = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(REQUEST_TIMEOUT)
                .build()
                .map_err(|error| {
                    eprintln!("reede: cannot build the HTTP client: {error}");
                    cli::EXIT_SERVER
                })?;
            Ok(Api { client, config })
        }

        /// Send one request with the bearer credential; the status and the body text, or the
        /// exit code of a transport failure (already printed).
        async fn send(
            &self,
            subject: &str,
            method: Method,
            url: reqwest::Url,
        ) -> Result<(u16, String), i32> {
            let sent = self
                .client
                .request(method, url)
                .bearer_auth(self.config.token())
                .send()
                .await;
            let response = sent.map_err(|error| {
                eprintln!(
                    "{subject}: {}",
                    self.config
                        .redact(&format!("cannot reach the lifecycle API: {error}"))
                );
                cli::EXIT_SERVER
            })?;
            let status = response.status().as_u16();
            let body = response.text().await.map_err(|error| {
                eprintln!(
                    "{subject}: {}",
                    self.config
                        .redact(&format!("cannot read the answer [HTTP {status}]: {error}"))
                );
                cli::EXIT_SERVER
            })?;
            Ok((status, body))
        }

        /// A success's body decoded as `T`; anything else printed and turned into its exit code.
        async fn call<T: DeserializeOwned>(
            &self,
            subject: &str,
            method: Method,
            url: reqwest::Url,
        ) -> Result<(u16, T), i32> {
            let (status, body) = self.send(subject, method, url).await?;
            if !(200..=299).contains(&status) {
                eprintln!(
                    "{}",
                    cli::describe_failure(subject, status, &self.config.redact(&body))
                );
                return Err(cli::exit_code_for_status(status));
            }
            serde_json::from_str(&body)
                .map(|value| (status, value))
                .map_err(|error| {
                    eprintln!(
                        "{subject}: {}",
                        self.config
                            .redact(&format!("unexpected answer [HTTP {status}]: {error}"))
                    );
                    cli::EXIT_SERVER
                })
        }
    }

    pub async fn list_tasks(api: &Api, limit: Option<u32>) -> Result<(), i32> {
        let (_, tasks): (_, Vec<Task>) = api
            .call("tasks", Method::GET, api.config.list_url(limit))
            .await?;
        if tasks.is_empty() {
            eprintln!("no tasks for this tenant");
        }
        for task in &tasks {
            println!("{}", cli::task_line(task));
        }
        Ok(())
    }

    pub async fn get_task(api: &Api, id: Uuid) -> Result<(), i32> {
        let subject = format!("tasks {id}");
        let (_, task): (_, serde_json::Value) = api
            .call(&subject, Method::GET, api.config.task_url(id))
            .await?;
        let pretty = serde_json::to_string_pretty(&task).map_err(|_| cli::EXIT_SERVER)?;
        println!("{pretty}");
        eprintln!(
            "note: budget_envelope.reserved_credits is in {}",
            cli::CREDITS_UNIT
        );
        Ok(())
    }

    pub async fn kill(api: &Api, id: Uuid, wait: bool) -> Result<(), i32> {
        let subject = format!("kill {id}");
        let (_, mut task): (_, Task) = api
            .call(&subject, Method::POST, api.config.cancel_url(id))
            .await?;
        println!("{}", cli::kill_accepted_line(&task));
        if !wait {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(cli::WAIT_TIMEOUT_SECS);
        while !task.state.is_terminal() {
            if Instant::now() >= deadline {
                eprintln!("{}", cli::kill_timeout_line(&task));
                return Err(cli::EXIT_REFUSED);
            }
            tokio::time::sleep(Duration::from_secs(cli::WAIT_POLL_SECS)).await;
            task = api
                .call(&subject, Method::GET, api.config.task_url(id))
                .await?
                .1;
        }
        println!("{}", cli::kill_ended_line(&task));
        Ok(())
    }

    pub async fn leases(api: &Api, id: Uuid) -> Result<(), i32> {
        let subject = format!("lease {id}");
        let (_, leases): (_, Vec<CredentialLease>) = api
            .call(&subject, Method::GET, api.config.leases_url(id))
            .await?;
        if leases.is_empty() {
            eprintln!("no leases for task {id}");
        }
        let now = chrono::Utc::now();
        for lease in &leases {
            println!("{}", cli::lease_line(lease, now));
        }
        Ok(())
    }
}

#[cfg(not(feature = "ingest"))]
async fn ingest_cli(_args: &[String]) -> i32 {
    eprintln!(
        "reede: serve and ingest need the `ingest` feature: cargo install reede --features ingest"
    );
    1
}

#[cfg(feature = "ingest")]
const INGEST_USAGE: &str = "Usage:
  reede serve [--listen 127.0.0.1:4318] [--out <dir>] [--tenant local] [--allow-remote]
  reede ingest check --out <dir> [--pubkey <hex>]
  reede ingest runs --out <dir> [--trace <id>]";

/// Reject help and unknown flags BEFORE anything is created: `Ok(Some(code))` means print usage
/// and exit with `code` (0 for -h/--help, 2 for an unknown flag or stray argument).
#[cfg(feature = "ingest")]
fn ingest_args_verdict(args: &[String]) -> Option<i32> {
    let (valued, rest): (&[&str], &[String]) =
        match (args[1].as_str(), args.get(2).map(String::as_str)) {
            ("serve", _) => (&["--listen", "--out", "--tenant"], &args[2..]),
            ("ingest", Some("check")) => (&["--out", "--pubkey"], &args[3..]),
            ("ingest", Some("runs")) => (&["--out", "--trace"], &args[3..]),
            ("ingest", Some("-h" | "--help")) => return Some(0),
            _ => return Some(2),
        };
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => return Some(0),
            "--allow-remote" if args[1] == "serve" => {}
            f if valued.contains(&f) => {
                if it.next().is_none() {
                    return Some(2);
                }
            }
            _ => return Some(2),
        }
    }
    None
}

/// `serve` and `ingest check|runs`. Reported-tier wording is deliberate: see docs/ingest.md.
#[cfg(feature = "ingest")]
async fn ingest_cli(args: &[String]) -> i32 {
    use reede::ingest;
    if let Some(code) = ingest_args_verdict(args) {
        if code == 0 {
            println!("{INGEST_USAGE}");
        } else {
            eprintln!("{INGEST_USAGE}");
        }
        return code;
    }
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let out = std::path::PathBuf::from(flag("--out").unwrap_or_else(|| "reede-ingest".into()));
    if args[1] == "ingest" {
        if args.get(2).map(String::as_str) == Some("runs") && flag("--out").is_some() {
            let report = ingest::read_span_values(&out).map(|items| {
                let mut r = ingest::runs::map_runs(&items, &ingest::runs::Prices::default());
                if let Some(t) = flag("--trace") {
                    r.traces.retain(|x| x.trace_id == t);
                }
                r
            });
            return match report {
                Ok(r) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&ingest::runs::to_json(&r))
                            .unwrap_or_default()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("FAIL: {e}");
                    1
                }
            };
        }
        if args.get(2).map(String::as_str) != Some("check") || flag("--out").is_none() {
            eprintln!("Usage: reede ingest check --out <dir> [--pubkey <hex>]");
            eprintln!("       reede ingest runs --out <dir> [--trace <id>]");
            return 1;
        }
        return match ingest::check(&out, flag("--pubkey").as_deref()) {
            Ok(n) => {
                println!("OK: {n} reported receipt(s) verify and match their span files.");
                println!("Note: a reported receipt proves what the agent reported and when this machine sealed it, not that it is true. No trusted timestamp is attached.");
                0
            }
            Err(e) => {
                eprintln!("FAIL: {e}");
                1
            }
        };
    }
    let listen = flag("--listen").unwrap_or_else(|| "127.0.0.1:4318".into());
    let tenant = flag("--tenant").unwrap_or_else(|| "local".into());
    let allow_remote = args.iter().any(|a| a == "--allow-remote");
    let addr: std::net::SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("reede serve: invalid --listen {listen:?} (want ip:port): {e}");
            return 1;
        }
    };
    let ingest = match ingest::Ingest::open(&out, &tenant).await {
        Ok(i) => i,
        Err(e) => {
            eprintln!("reede serve: {e}");
            return 1;
        }
    };
    let pubkey = ingest.pubkey_hex();
    let server = match ingest::Server::bind(addr, allow_remote, ingest).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("reede serve: {e}");
            return 1;
        }
    };
    println!(
        "reede serve: listening on http://{} (POST /v1/traces)",
        server.local_addr()
    );
    println!(
        "  output: {}  tenant: {tenant}  public key: {pubkey}",
        out.display()
    );
    println!("  Receipts are 'reported': they prove what the agent reported and when this machine sealed it, not that it is true. No trusted timestamp.");
    server.run().await;
    0
}
