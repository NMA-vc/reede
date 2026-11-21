use crate::egress::{AllowlistEgress, FlagToHuman, LoggingFlagToHuman};
use crate::egress_proxy::{EgressProxy, HostResolver, DEFAULT_DNS_UPSTREAM, DEFAULT_PROXY_PORT};
use crate::error::ReedeError;
use crate::policy::DerivedPolicy;
use crate::task::Task;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Output;
use std::sync::Arc;
use std::sync::{Mutex as StdMutex, OnceLock};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SandboxId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub current_dir: Option<String>,
}

/// Engine program, value-less exec argv, and child-process environment pairs.
///
/// The tuple intentionally allows arbitrary syntactically valid environment names.
/// Callers must enforce a closed approved-name policy before forwarding any
/// untrusted sandbox-controlled environment to a rootful engine client. Name
/// syntax validation alone does not protect engine variables such as `DOCKER_HOST`.
pub type PreparedExec = (String, Vec<String>, Vec<(String, String)>);

/// Primary OCI process configuration for one already-approved local image.
///
/// Callers must authorize every environment name, reject engine-control names,
/// and enforce the SharedCi refusal before invoking the trusted backend API.
/// The default `CommandRunner::run_with_env` ignores the child environment for
/// compatibility, so production runners used for this API must override it.
#[derive(Clone, Default)]
pub struct PrimaryImageLaunch {
    pub program: Option<String>,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl std::fmt::Debug for PrimaryImageLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrimaryImageLaunch")
            .field("program", &self.program)
            .field("args", &format!("<{} arguments>", self.args.len()))
            .field(
                "env_names",
                &self.env.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            )
            .field("env_values", &"<redacted>")
            .finish()
    }
}

/// Fixed, non-TTY attach command for the prepared container's primary process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedPrimaryStart {
    program: String,
    args: Vec<String>,
}

impl PreparedPrimaryStart {
    pub fn program(&self) -> &str {
        &self.program
    }
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

enum ContainerLaunch<'a> {
    Legacy,
    Primary {
        image: &'a str,
        launch: &'a PrimaryImageLaunch,
    },
}

#[async_trait]
pub trait IsolationBackend: Send + Sync {
    fn name(&self) -> &'static str;

    async fn create_sandbox(
        &self,
        task: &Task,
        policy: &DerivedPolicy,
    ) -> Result<SandboxId, ReedeError>;

    async fn destroy_sandbox(&self, id: SandboxId) -> Result<(), ReedeError>;

    async fn exec_in_sandbox(
        &self,
        id: SandboxId,
        cmd: SandboxCommand,
    ) -> Result<Output, ReedeError>;
}

// ---------------------------------------------------------------------------
// CommandRunner — injectable process spawner
// ---------------------------------------------------------------------------
//
// Every external process the `GvisorBackend` runs goes through a `CommandRunner`.
// Production uses `TokioCommandRunner` (a thin wrapper over `tokio::process`).
// Unit tests inject a fake runner that records the exact `(program, args)` it is
// asked to run and returns a canned `Output` — so we can assert the argv/flags
// GvisorBackend builds (`--runtime=runsc`, container naming, resource limits, the
// one-sandbox-per-Task mapping) WITHOUT spawning a real process or needing a
// runsc/docker host. CI therefore stays green with no runsc present.
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`, awaiting completion, returning the captured `Output`.
    async fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output>;

    /// Run a child with additional environment entries that never enter its argv.
    ///
    /// Callers forwarding untrusted values must enforce a closed approved-name
    /// policy first; arbitrary valid names can alter engine behavior (for example,
    /// `DOCKER_HOST`). Syntax validation is not an authorization policy.
    /// The compatibility default ignores `env` and delegates to [`CommandRunner::run`],
    /// so existing runners that only record or execute argv remain source-compatible.
    /// A runner used where these entries must reach the child environment **must**
    /// override this method.
    async fn run_with_env(
        &self,
        program: &str,
        args: &[String],
        _env: &[(String, String)],
    ) -> std::io::Result<Output> {
        self.run(program, args).await
    }
}

/// Production `CommandRunner` backed by `tokio::process::Command`.
pub struct TokioCommandRunner;

#[async_trait]
impl CommandRunner for TokioCommandRunner {
    async fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
        tokio::process::Command::new(program)
            .args(args)
            .output()
            .await
    }

    async fn run_with_env(
        &self,
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> std::io::Result<Output> {
        tokio::process::Command::new(program)
            .args(args)
            .envs(env.iter().map(|(name, value)| (name, value)))
            .output()
            .await
    }
}

/// How the sandbox's network namespace is wired.
///
/// The S9 backend only offered the fail-closed `NetworkNone`. S10 adds
/// `ProxyGated`, which is the enforcement model that the egress-policy claim
/// (plan criterion 2) actually rests on. Selecting `NetworkNone` is still valid
/// and remains the strictest possible setting (an agent that needs no egress).
#[derive(Debug, Clone)]
pub enum EgressMode {
    /// `--network none`: no interfaces, no egress at all (S9 fail-closed).
    NetworkNone,
    /// Allowlisted egress ONLY through the Reede egress proxy, enforced at the
    /// docker network namespace. See [`ProxyGatedConfig`] and the module docs.
    ProxyGated(ProxyGatedConfig),
}

/// Configuration for [`EgressMode::ProxyGated`].
///
/// The sandbox is put on a per-task **`--internal`** docker network (no default
/// route to the internet), and the Reede egress proxy is bound to that network's
/// gateway IP — the one address the sandbox can reach. All egress, including
/// DNS, is forced through it.
#[derive(Clone)]
pub struct ProxyGatedConfig {
    /// Class-B prefix the per-task /24 is carved from. Default `172.30`.
    /// Each task gets `<prefix>.<octet>.0/24`, gateway `<prefix>.<octet>.1`.
    pub subnet_prefix: String,
    /// TCP port the CONNECT proxy listens on (on the gateway IP).
    pub proxy_port: u16,
    /// Upstream resolver (`ip:port`) that allowlisted DNS names are forwarded to.
    pub dns_upstream: String,
    /// Additional IPv4/IPv6 ranges that CONNECT resolution must never reach.
    /// Mandatory special-use ranges are enforced in addition to these entries.
    pub deny_cidrs: Vec<String>,
    /// Optional resolver override for controlled hosts. Production defaults use the system resolver.
    pub host_resolver: Option<Arc<dyn HostResolver>>,
    /// Where denied attempts are reported. Defaults to [`LoggingFlagToHuman`].
    pub flag_to_human: Arc<dyn FlagToHuman>,
}

impl std::fmt::Debug for ProxyGatedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyGatedConfig")
            .field("subnet_prefix", &self.subnet_prefix)
            .field("proxy_port", &self.proxy_port)
            .field("dns_upstream", &self.dns_upstream)
            .field("deny_cidrs", &self.deny_cidrs)
            .field(
                "host_resolver",
                &self.host_resolver.as_ref().map(|_| "<dyn HostResolver>"),
            )
            .field("flag_to_human", &"<dyn FlagToHuman>")
            .finish()
    }
}

impl Default for ProxyGatedConfig {
    fn default() -> Self {
        Self {
            subnet_prefix: "172.30".to_string(),
            proxy_port: DEFAULT_PROXY_PORT,
            dns_upstream: DEFAULT_DNS_UPSTREAM.to_string(),
            deny_cidrs: Vec::new(),
            host_resolver: None,
            flag_to_human: Arc::new(LoggingFlagToHuman),
        }
    }
}

/// Production gVisor (`runsc`) isolation backend.
///
/// Mechanism: gVisor is installed on the host as an additional **Docker runtime**
/// named `runsc` (see the S9 provisioning runbook); `runc` remains the daemon
/// default. Reede task containers opt into the sandbox by launching through
/// `docker run --runtime=runsc …`, so only Reede workloads get the user-space
/// kernel boundary and the platform's other containers are untouched.
///
/// One sandbox per Task: the sandbox handle is `SandboxId(task.id)` and the
/// container is named `reede-sbx-<task.id>`, a deterministic 1:1 mapping that
/// `terminate.rs` relies on to tear a task's sandbox down by task id alone.
///
/// Egress (S10): controlled by [`EgressMode`]. In `ProxyGated` mode the backend,
/// per task, issues:
/// 1. `docker network create --driver bridge --internal --subnet <p>.<o>.0/24
///    --gateway <p>.<o>.1 reede-egr-<task.id>` — an internal network with no
///    route to the internet, so raw sockets and direct-IP connects have nowhere
///    to go (namespace-layer enforcement).
/// 2. Binds the Reede egress proxy (CONNECT filter + DNS filter) to the gateway
///    `<p>.<o>.1` — the single address the sandbox can reach.
/// 3. `docker run -d --runtime=runsc --network reede-egr-<task.id>
///    --dns <p>.<o>.1 --env HTTP(S)_PROXY=http://<p>.<o>.1:<port>
///    --env REEDE_EGRESS_ALLOWLIST=… …` — the sandbox, whose only next-hop is
///    the proxy.
///
/// Teardown reverses it: `docker rm --force`, then `docker network rm`, and the
/// proxy task is aborted from `active_proxies`.
#[derive(Clone, Debug)]
struct SandboxLimits {
    memory_bytes: u64,
    pids: u32,
    cpus: String,
    cgroup_parent: Option<String>,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 268_435_456,
            pids: 256,
            cpus: "1.0".to_string(),
            cgroup_parent: None,
        }
    }
}

/// Default prefix a primary-image entrypoint program must carry. Hosts that ship their own
/// MCP binaries set theirs with [`GvisorBackend::with_program_prefixes`].
pub const DEFAULT_PROGRAM_PREFIX: &str = "reede-mcp-";

pub struct GvisorBackend {
    /// Path to (or name of) the docker client binary. Default `docker`.
    pub docker_path: String,
    /// Name of the runsc runtime registered with the Docker daemon. Default `runsc`.
    pub runtime_name: String,
    /// Image the task sandbox runs. Default `alpine:3.20`.
    pub image: String,
    /// How the sandbox network namespace is wired (S10).
    pub egress_mode: EgressMode,
    /// Injected process spawner (real in prod, fake in tests).
    runner: Arc<dyn CommandRunner>,
    limits: SandboxLimits,
    /// Prefixes a primary-image entrypoint program must carry. Host-supplied; the neutral
    /// default is [`DEFAULT_PROGRAM_PREFIX`].
    program_prefixes: Vec<String>,
    config_error: Option<String>,
}

impl GvisorBackend {
    /// Construct with an explicit configuration and the production command runner.
    ///
    /// Defaults to [`EgressMode::NetworkNone`] (S9 fail-closed). Use
    /// [`GvisorBackend::with_egress_mode`] or [`GvisorBackend::from_env`] for the
    /// S10 proxy-gated network.
    pub fn new(
        docker_path: impl Into<String>,
        runtime_name: impl Into<String>,
        image: impl Into<String>,
    ) -> Self {
        Self {
            docker_path: docker_path.into(),
            runtime_name: runtime_name.into(),
            image: image.into(),
            egress_mode: EgressMode::NetworkNone,
            runner: Arc::new(TokioCommandRunner),
            limits: SandboxLimits::default(),
            program_prefixes: vec![DEFAULT_PROGRAM_PREFIX.to_string()],
            config_error: None,
        }
    }

    /// Replace the allowed primary-image program prefixes (host configuration).
    pub fn with_program_prefixes<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.program_prefixes = prefixes.into_iter().map(Into::into).collect();
        self
    }

    /// Replace only the command runner, retaining all operator-derived configuration.
    ///
    /// Hosts can inject a bounded, cancellation-safe runner after `from_env`.
    /// This does not clear a configuration error or widen egress/resource policy.
    pub fn with_command_runner(mut self, runner: Arc<dyn CommandRunner>) -> Self {
        self.runner = runner;
        self
    }

    /// Set per-sandbox resource limits without changing trusted engine configuration.
    ///
    /// The host-agent create API supplies these values for each sandbox. The
    /// cgroup parent remains operator-owned and is preserved from `from_env`.
    /// Invalid environment configuration is never repaired by a request override.
    pub fn with_resource_limits(
        mut self,
        memory_bytes: u64,
        pids: u32,
        cpus: f64,
    ) -> Result<Self, ReedeError> {
        if let Some(error) = &self.config_error {
            return Err(ReedeError::IsolationFailed {
                reason: format!("invalid sandbox configuration: {error}"),
            });
        }
        if memory_bytes == 0
            || memory_bytes > i64::MAX as u64
            || pids == 0
            || pids > i32::MAX as u32
            || !cpus.is_finite()
            || cpus <= 0.0
        {
            return Err(ReedeError::IsolationFailed {
                reason: "sandbox resource limits require bounded positive memory and pids, and finite positive CPUs".to_string(),
            });
        }
        self.limits.memory_bytes = memory_bytes;
        self.limits.pids = pids;
        self.limits.cpus = cpus.to_string();
        Ok(self)
    }

    /// Set the egress mode (builder style).
    pub fn with_egress_mode(mut self, mode: EgressMode) -> Self {
        self.egress_mode = mode;
        self
    }

    /// Construct with an injected `CommandRunner` (used by unit tests to capture argv).
    pub fn with_runner(
        docker_path: impl Into<String>,
        runtime_name: impl Into<String>,
        image: impl Into<String>,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        Self {
            docker_path: docker_path.into(),
            runtime_name: runtime_name.into(),
            image: image.into(),
            egress_mode: EgressMode::NetworkNone,
            runner,
            limits: SandboxLimits::default(),
            program_prefixes: vec![DEFAULT_PROGRAM_PREFIX.to_string()],
            config_error: None,
        }
    }

    /// Build from environment, defaulting sensibly:
    /// - `DOCKER_BIN`             → docker client path   (default `docker`)
    /// - `REEDE_RUNSC_RUNTIME`    → docker runtime name  (default `runsc`)
    /// - `REEDE_SANDBOX_IMAGE`    → task sandbox image   (default `alpine:3.20`)
    /// - `REEDE_EGRESS_MODE`      → `proxy` (default) or `none`
    /// - `REEDE_EGRESS_SUBNET_PREFIX` → per-task /24 prefix (default `172.30`)
    /// - `REEDE_EGRESS_PROXY_PORT`    → CONNECT proxy port (default `13128`)
    /// - `REEDE_EGRESS_DNS_UPSTREAM`  → upstream resolver  (default `1.1.1.1:53`)
    ///
    /// The S10 default is `ProxyGated`: allowlisted egress through the Reede
    /// proxy. Set `REEDE_EGRESS_MODE=none` to fall back to S9's no-egress mode.
    pub fn from_env() -> Self {
        let docker_path = std::env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string());
        let runtime_name =
            std::env::var("REEDE_RUNSC_RUNTIME").unwrap_or_else(|_| "runsc".to_string());
        let image =
            std::env::var("REEDE_SANDBOX_IMAGE").unwrap_or_else(|_| "alpine:3.20".to_string());

        let mut config_error = None;
        let egress_selection = std::env::var("REEDE_EGRESS_MODE")
            .unwrap_or_else(|_| "proxy".to_string())
            .to_ascii_lowercase();
        let egress_mode = match egress_selection.as_str() {
            "none" => EgressMode::NetworkNone,
            "proxy" => {
                let mut cfg = ProxyGatedConfig::default();
                if let Ok(p) = std::env::var("REEDE_EGRESS_SUBNET_PREFIX") {
                    cfg.subnet_prefix = p;
                }
                if let Ok(raw) = std::env::var("REEDE_EGRESS_PROXY_PORT") {
                    match raw.parse::<u16>() {
                        Ok(port) if port != 0 => cfg.proxy_port = port,
                        _ => {
                            config_error = Some(
                                "REEDE_EGRESS_PROXY_PORT must be a valid nonzero port".to_string(),
                            )
                        }
                    }
                }
                if let Ok(up) = std::env::var("REEDE_EGRESS_DNS_UPSTREAM") {
                    cfg.dns_upstream = up;
                }
                if let Ok(raw) = std::env::var("REEDE_EGRESS_DENY_CIDRS") {
                    cfg.deny_cidrs = raw.split(',').map(str::trim).map(str::to_string).collect();
                }
                EgressMode::ProxyGated(cfg)
            }
            _ => {
                config_error = Some("REEDE_EGRESS_MODE must be `proxy` or `none`".to_string());
                EgressMode::NetworkNone
            }
        };

        let mut limits = SandboxLimits::default();
        if let Ok(raw) = std::env::var("REEDE_SANDBOX_PIDS") {
            match raw.parse::<u32>() {
                Ok(value) if value > 0 && value <= i32::MAX as u32 => limits.pids = value,
                _ => {
                    config_error = Some("REEDE_SANDBOX_PIDS must be a positive integer".to_string())
                }
            }
        }
        if let Ok(raw) = std::env::var("REEDE_SANDBOX_CPUS") {
            match raw.parse::<f64>() {
                Ok(value) if value.is_finite() && value > 0.0 => limits.cpus = raw,
                _ => {
                    config_error =
                        Some("REEDE_SANDBOX_CPUS must be a finite positive number".to_string())
                }
            }
        }
        if let Ok(raw) = std::env::var("REEDE_SANDBOX_MEMORY_BYTES") {
            match raw.parse::<u64>() {
                Ok(value) if value > 0 && value <= i64::MAX as u64 => limits.memory_bytes = value,
                _ => {
                    config_error =
                        Some("REEDE_SANDBOX_MEMORY_BYTES must be a positive integer".to_string())
                }
            }
        }
        if let Ok(raw) = std::env::var("REEDE_SANDBOX_CGROUP_PARENT") {
            if raw.trim().is_empty() || raw.bytes().any(|b| b.is_ascii_control()) {
                config_error = Some("REEDE_SANDBOX_CGROUP_PARENT must be non-empty and contain no control characters".to_string());
            } else {
                limits.cgroup_parent = Some(raw);
            }
        }
        let mut backend = Self::new(docker_path, runtime_name, image).with_egress_mode(egress_mode);
        backend.limits = limits;
        backend.config_error = config_error;
        backend
    }

    /// Deterministic container name for a sandbox resource.
    fn container_name(id: SandboxId) -> String {
        format!("reede-sbx-{}", id.0)
    }

    /// Deterministic per-resource docker network name.
    fn network_name(id: SandboxId) -> String {
        format!("reede-egr-{}", id.0)
    }

    /// Deterministic per-resource /24 subnet + gateway from its UUID.
    ///
    /// The third octet is derived from the task UUID so concurrent sandboxes get
    /// distinct networks without a shared allocator. Collisions are possible in
    /// principle (one octet of entropy); the operator can widen the space via
    /// `subnet_prefix`, and docker itself rejects an overlapping subnet loudly.
    fn subnet_for(prefix: &str, id: SandboxId) -> (String, Ipv4Addr) {
        // Use a byte from the uuid, avoiding .0 (network) and .255 (broadcast)
        // ranges by mapping into 1..=254.
        let octet = (id.0.as_bytes()[0] % 254) + 1;
        let subnet = format!("{prefix}.{octet}.0/24");
        let gateway_str = format!("{prefix}.{octet}.1");
        let gateway = gateway_str
            .parse::<Ipv4Addr>()
            .expect("subnet prefix is validated before network creation");
        (subnet, gateway)
    }

    fn subnet_for_attempt(prefix: &str, id: SandboxId, attempt: u8) -> (String, Ipv4Addr) {
        let first = id.0.as_bytes()[0] % 254;
        let octet = ((first as u16 + attempt as u16) % 254 + 1) as u8;
        let subnet = format!("{prefix}.{octet}.0/24");
        let gateway = format!("{prefix}.{octet}.1")
            .parse::<Ipv4Addr>()
            .expect("subnet prefix is validated before network creation");
        (subnet, gateway)
    }

    fn valid_subnet_prefix(prefix: &str) -> bool {
        let mut pieces = prefix.split('.');
        matches!(
            (pieces.next(), pieces.next(), pieces.next()),
            (Some(_), Some(_), None)
        ) && format!("{prefix}.1.1").parse::<Ipv4Addr>().is_ok()
    }

    fn is_overlap_error(stderr: &str) -> bool {
        let stderr = stderr.to_ascii_lowercase();
        stderr.contains("overlap")
    }

    /// Argv for `docker network create` of a per-task internal egress network.
    /// Pure (no spawning) so it is asserted directly in tests.
    fn build_network_create_args(id: SandboxId, subnet: &str, gateway: Ipv4Addr) -> Vec<String> {
        vec![
            "network".to_string(),
            "create".to_string(),
            "--driver".to_string(),
            "bridge".to_string(),
            // No route to the internet: the namespace-layer wall.
            "--internal".to_string(),
            "--subnet".to_string(),
            subnet.to_string(),
            "--gateway".to_string(),
            gateway.to_string(),
            Self::network_name(id),
        ]
    }

    /// Argv for `docker network rm` of the per-task egress network.
    fn build_network_rm_args(id: SandboxId) -> Vec<String> {
        vec![
            "network".to_string(),
            "rm".to_string(),
            Self::network_name(id),
        ]
    }

    /// Argv for `docker run` that launches the runsc-isolated task sandbox.
    /// Kept pure (no spawning) so it is asserted directly in tests.
    #[cfg(test)]
    fn build_run_args(&self, id: SandboxId, policy: &DerivedPolicy) -> Vec<String> {
        self.build_run_args_with_gateway(id, policy, None)
    }

    fn build_run_args_with_gateway(
        &self,
        id: SandboxId,
        policy: &DerivedPolicy,
        selected_gateway: Option<Ipv4Addr>,
    ) -> Vec<String> {
        let name = Self::container_name(id);
        let mut args: Vec<String> = vec![
            "run".to_string(),
            "-d".to_string(),
            format!("--runtime={}", self.runtime_name),
            "--name".to_string(),
            name,
        ];

        // Network model: fail-closed `none`, or the S10 proxy-gated internal net.
        match &self.egress_mode {
            EgressMode::NetworkNone => {
                args.push("--network".to_string());
                args.push("none".to_string());
            }
            EgressMode::ProxyGated(cfg) => {
                let (_subnet, derived_gateway) = Self::subnet_for(&cfg.subnet_prefix, id);
                let gateway = selected_gateway.unwrap_or(derived_gateway);
                // The sandbox's ONLY network is the per-task internal one, whose
                // sole reachable next-hop is the proxy on the gateway IP.
                args.push("--network".to_string());
                args.push(Self::network_name(id));
                // Resolver = the gateway, where the Reede DNS filter listens.
                args.push("--dns".to_string());
                args.push(gateway.to_string());
                // Cooperative HTTP(S) clients also get pointed at the proxy;
                // enforcement does NOT depend on this — the internal network is
                // what makes bypass impossible — but it lets well-behaved apps
                // work without per-app config.
                let proxy_url = format!("http://{gateway}:{}", cfg.proxy_port);
                args.push("--env".to_string());
                args.push(format!("HTTP_PROXY={proxy_url}"));
                args.push("--env".to_string());
                args.push(format!("HTTPS_PROXY={proxy_url}"));
                args.push("--env".to_string());
                args.push(format!("http_proxy={proxy_url}"));
                args.push("--env".to_string());
                args.push(format!("https_proxy={proxy_url}"));
            }
        }

        // Immutable root filesystem.
        args.push("--read-only".to_string());
        // Hard resource limits apply to every sandbox.
        args.push("--memory".to_string());
        args.push(self.limits.memory_bytes.to_string());
        args.push("--pids-limit".to_string());
        args.push(self.limits.pids.to_string());
        args.push("--cpus".to_string());
        args.push(self.limits.cpus.clone());
        if let Some(parent) = &self.limits.cgroup_parent {
            args.push("--cgroup-parent".to_string());
            args.push(parent.clone());
        }
        args.push("--tmpfs".to_string());
        args.push("/tmp:rw,size=64m,noexec".to_string());
        args.push("--user".to_string());
        args.push("65534:65534".to_string());
        args.push("--pull=never".to_string());
        // Drop all Linux capabilities and forbid privilege escalation. This is
        // also what blocks in-sandbox route/namespace rewrites: no NET_ADMIN,
        // no way to add a default route or move netns.
        args.push("--cap-drop".to_string());
        args.push("ALL".to_string());
        args.push("--security-opt".to_string());
        args.push("no-new-privileges".to_string());

        // Propagate the derived egress allowlist into the sandbox as an env var
        // (informational; the proxy is the authority on what is allowed).
        args.push("--env".to_string());
        args.push(format!(
            "REEDE_EGRESS_ALLOWLIST={}",
            policy.egress_allowlist.join(",")
        ));

        // The image, then a long-lived entrypoint so the container stays up for `exec`.
        args.push(self.image.clone());
        args.push("sleep".to_string());
        args.push("infinity".to_string());

        args
    }

    fn validate_exec_env(env: &[(String, String)]) -> Result<(), ReedeError> {
        let valid = |name: &str| {
            let mut chars = name.chars();
            matches!(chars.next(), Some('A'..='Z' | 'a'..='z' | '_'))
                && chars.all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_'))
        };
        if env.iter().any(|(name, _)| !valid(name)) {
            return Err(ReedeError::IsolationFailed {
                reason: "sandbox command contains an invalid environment name".to_string(),
            });
        }
        Ok(())
    }

    fn valid_env_name(name: &str) -> bool {
        let mut chars = name.chars();
        matches!(chars.next(), Some('A'..='Z' | 'a'..='z' | '_'))
            && chars.all(|c| matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '_'))
    }

    fn validate_primary_launch(&self, launch: &PrimaryImageLaunch) -> Result<(), ReedeError> {
        if let Some(program) = &launch.program {
            let valid = self
                .program_prefixes
                .iter()
                .filter_map(|prefix| program.strip_prefix(prefix.as_str()))
                .any(|suffix| {
                    !suffix.is_empty()
                        && suffix
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
            if !valid {
                return Err(ReedeError::IsolationFailed {
                    reason: "primary image program is invalid".to_string(),
                });
            }
        }
        let mut names = std::collections::HashSet::new();
        for (name, _) in &launch.env {
            if !Self::valid_env_name(name) || !names.insert(name.as_str()) {
                return Err(ReedeError::IsolationFailed {
                    reason: "primary image environment names are invalid or duplicated".to_string(),
                });
            }
        }
        Ok(())
    }

    fn build_primary_create_args(
        &self,
        id: SandboxId,
        image: &str,
        launch: &PrimaryImageLaunch,
        selected_gateway: Option<Ipv4Addr>,
    ) -> Vec<String> {
        let mut args = vec![
            "create".to_string(),
            "-i".to_string(),
            "--http-proxy=false".to_string(),
            "--tty=false".to_string(),
            format!("--runtime={}", self.runtime_name),
            "--name".to_string(),
            Self::container_name(id),
        ];
        match &self.egress_mode {
            EgressMode::NetworkNone => {
                args.extend(["--network".to_string(), "none".to_string()]);
            }
            EgressMode::ProxyGated(cfg) => {
                let (_, derived_gateway) = Self::subnet_for(&cfg.subnet_prefix, id);
                let gateway = selected_gateway.unwrap_or(derived_gateway);
                args.extend([
                    "--network".to_string(),
                    Self::network_name(id),
                    "--dns".to_string(),
                    gateway.to_string(),
                ]);
                for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                    args.extend(["--env".to_string(), name.to_string()]);
                }
            }
        }
        args.extend([
            "--read-only".to_string(),
            "--memory".to_string(),
            self.limits.memory_bytes.to_string(),
            "--pids-limit".to_string(),
            self.limits.pids.to_string(),
            "--cpus".to_string(),
            self.limits.cpus.clone(),
        ]);
        if let Some(parent) = &self.limits.cgroup_parent {
            args.extend(["--cgroup-parent".to_string(), parent.clone()]);
        }
        args.extend([
            "--tmpfs".to_string(),
            "/tmp:rw,size=64m,noexec".to_string(),
            "--user".to_string(),
            "65534:65534".to_string(),
            "--pull=never".to_string(),
            "--cap-drop".to_string(),
            "ALL".to_string(),
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
            "--env".to_string(),
            "REEDE_EGRESS_ALLOWLIST".to_string(),
        ]);
        for (name, _) in &launch.env {
            args.extend(["--env".to_string(), name.clone()]);
        }
        if let Some(program) = &launch.program {
            args.extend(["--entrypoint".to_string(), program.clone()]);
        }
        args.push(image.to_string());
        args.extend(launch.args.iter().cloned());
        args
    }

    fn primary_engine_env(
        &self,
        launch: &PrimaryImageLaunch,
        policy: &DerivedPolicy,
        selected_gateway: Option<Ipv4Addr>,
    ) -> Vec<(String, String)> {
        let mut env = launch.env.clone();
        env.push((
            "REEDE_EGRESS_ALLOWLIST".to_string(),
            policy.egress_allowlist.join(","),
        ));
        if let (EgressMode::ProxyGated(cfg), Some(gateway)) = (&self.egress_mode, selected_gateway)
        {
            let proxy = format!("http://{gateway}:{}", cfg.proxy_port);
            for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
                env.push((name.to_string(), proxy.clone()));
            }
        }
        env
    }

    async fn create_sandbox_for_resource(
        &self,
        task: &Task,
        sandbox_id: SandboxId,
        policy: &DerivedPolicy,
        mode: ContainerLaunch<'_>,
    ) -> Result<SandboxId, ReedeError> {
        let primary = matches!(&mode, ContainerLaunch::Primary { .. });
        if let Some(error) = &self.config_error {
            return Err(ReedeError::IsolationFailed {
                reason: if primary {
                    "invalid primary sandbox configuration".to_string()
                } else {
                    format!("invalid sandbox configuration: {error}")
                },
            });
        }
        if let ContainerLaunch::Primary { image, launch } = &mode {
            if image.is_empty()
                || image.starts_with('-')
                || image.bytes().any(|b| b.is_ascii_control())
            {
                return Err(ReedeError::IsolationFailed {
                    reason: "primary image is invalid".to_string(),
                });
            }
            self.validate_primary_launch(launch)?;
            let internal = match &self.egress_mode {
                EgressMode::NetworkNone => vec!["REEDE_EGRESS_ALLOWLIST"],
                EgressMode::ProxyGated(_) => vec![
                    "REEDE_EGRESS_ALLOWLIST",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "http_proxy",
                    "https_proxy",
                ],
            };
            if launch
                .env
                .iter()
                .any(|(name, _)| internal.contains(&name.as_str()))
            {
                return Err(ReedeError::IsolationFailed {
                    reason:
                        "primary image environment name conflicts with trusted engine configuration"
                            .to_string(),
                });
            }
        }
        let mut selected_gateway = None;
        if let EgressMode::ProxyGated(cfg) = &self.egress_mode {
            if !Self::valid_subnet_prefix(&cfg.subnet_prefix) {
                return Err(ReedeError::IsolationFailed {
                    reason: if primary {
                        "invalid primary egress configuration".to_string()
                    } else {
                        "REEDE_EGRESS_SUBNET_PREFIX must contain two IPv4 octets".to_string()
                    },
                });
            }
            if cfg.proxy_port == 0 {
                return Err(ReedeError::IsolationFailed {
                    reason: if primary {
                        "invalid primary egress configuration".to_string()
                    } else {
                        "REEDE_EGRESS_PROXY_PORT must be a valid nonzero port".to_string()
                    },
                });
            }
            if cfg.dns_upstream.parse::<SocketAddr>().is_err() {
                return Err(ReedeError::IsolationFailed {
                    reason: if primary {
                        "invalid primary egress configuration".to_string()
                    } else {
                        "REEDE_EGRESS_DNS_UPSTREAM must be an IP address and port".to_string()
                    },
                });
            }
            let egress_policy = Arc::new(AllowlistEgress::from_policy(policy));
            let proxy = match &cfg.host_resolver {
                Some(resolver) => EgressProxy::for_task_with_resolver(
                    egress_policy,
                    cfg.flag_to_human.clone(),
                    cfg.dns_upstream.clone(),
                    task.id,
                    &cfg.deny_cidrs,
                    resolver.clone(),
                ),
                None => EgressProxy::for_task(
                    egress_policy,
                    cfg.flag_to_human.clone(),
                    cfg.dns_upstream.clone(),
                    task.id,
                    &cfg.deny_cidrs,
                ),
            }
            .map_err(|error| ReedeError::IsolationFailed {
                reason: if primary {
                    "invalid primary egress policy".to_string()
                } else {
                    format!("invalid egress deny CIDR configuration: {error}")
                },
            })?;
            let prepared_proxy = Arc::new(proxy);
            let mut network_created = false;
            for attempt in 0..8 {
                let (subnet, gateway) =
                    Self::subnet_for_attempt(&cfg.subnet_prefix, sandbox_id, attempt);
                let net_args = Self::build_network_create_args(sandbox_id, &subnet, gateway);
                tracing::info!(
                    task_id = %task.id,
                    network = %Self::network_name(sandbox_id),
                    subnet = %subnet,
                    gateway = %gateway,
                    "Creating per-task internal egress network"
                );
                let net_out = self
                    .runner
                    .run(&self.docker_path, &net_args)
                    .await
                    .map_err(|error| ReedeError::IsolationFailed {
                        reason: if primary {
                            "failed to prepare primary egress network; cleanup may remain uncertain"
                                .to_string()
                        } else {
                            format!(
                                "Failed to spawn `{} network create`: {error}",
                                self.docker_path
                            )
                        },
                    })?;
                if net_out.status.success() {
                    selected_gateway = Some(gateway);
                    network_created = true;
                    break;
                }
                let stderr = String::from_utf8_lossy(&net_out.stderr);
                if !Self::is_overlap_error(&stderr) || attempt == 7 {
                    return Err(ReedeError::IsolationFailed {
                        reason: if primary {
                            "failed to prepare primary egress network; cleanup may remain uncertain"
                                .to_string()
                        } else {
                            format!(
                                "`docker network create` failed after {} attempt(s): {stderr}",
                                attempt + 1
                            )
                        },
                    });
                }
            }
            if !network_created {
                return Err(ReedeError::IsolationFailed {
                    reason: "no egress subnet available after 8 overlap retries".to_string(),
                });
            }
            let gateway = selected_gateway.expect("successful network create sets gateway");
            match prepared_proxy
                .start_on_gateway(IpAddr::V4(gateway), cfg.proxy_port)
                .await
            {
                Ok(handle) => {
                    active_proxies()
                        .lock()
                        .unwrap()
                        .insert(sandbox_id.0, handle);
                }
                Err(error) => {
                    let _ = self
                        .runner
                        .run(&self.docker_path, &Self::build_network_rm_args(sandbox_id))
                        .await;
                    return Err(ReedeError::IsolationFailed {
                        reason: if primary {
                            "failed to prepare primary egress proxy".to_string()
                        } else {
                            format!("Failed to bind egress proxy on {gateway}: {error}")
                        },
                    });
                }
            }
        }

        match mode {
            ContainerLaunch::Legacy => {
                let args = self.build_run_args_with_gateway(sandbox_id, policy, selected_gateway);
                tracing::info!(
                    task_id = %task.id,
                    sandbox_id = %sandbox_id.0,
                    runtime = %self.runtime_name,
                    container = %Self::container_name(sandbox_id),
                    egress_mode = ?self.egress_mode,
                    "Launching gVisor (docker --runtime=runsc) task sandbox"
                );
                let output = self.run_sandbox_command(sandbox_id, &args).await?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let _ = self.teardown_egress_network(sandbox_id).await;
                    return Err(ReedeError::IsolationFailed {
                        reason: format!(
                            "`docker run --runtime={}` failed: {stderr}",
                            self.runtime_name
                        ),
                    });
                }
            }
            ContainerLaunch::Primary { image, launch } => {
                let args =
                    self.build_primary_create_args(sandbox_id, image, launch, selected_gateway);
                let env = self.primary_engine_env(launch, policy, selected_gateway);
                tracing::info!(
                    task_id = %task.id,
                    sandbox_id = %sandbox_id.0,
                    runtime = %self.runtime_name,
                    container = %Self::container_name(sandbox_id),
                    egress_mode = ?self.egress_mode,
                    "Preparing stopped primary-image sandbox container"
                );
                let created = self
                    .runner
                    .run_with_env(&self.docker_path, &args, &env)
                    .await;
                if !matches!(created, Ok(ref output) if output.status.success()) {
                    // A failed CLI response can follow a daemon-side create. Best-effort removal
                    // is not a daemon completion fence; the caller retains cleanup ownership.
                    let _ = self.destroy_sandbox(sandbox_id).await;
                    return Err(ReedeError::IsolationFailed { reason: "failed to prepare primary image container; cleanup may remain uncertain".to_string() });
                }
            }
        }
        Ok(sandbox_id)
    }

    /// Prepare a stopped image-primary container. The caller must have already
    /// authorized env names, rejected engine-control names, and enforced host policy.
    /// Cleanup after uncertain CLI failure is best-effort and is not a daemon fence.
    pub async fn prepare_primary_image(
        &self,
        task: &Task,
        sandbox_id: SandboxId,
        image: &str,
        policy: &DerivedPolicy,
        launch: &PrimaryImageLaunch,
    ) -> Result<SandboxId, ReedeError> {
        self.create_sandbox_for_resource(
            task,
            sandbox_id,
            policy,
            ContainerLaunch::Primary { image, launch },
        )
        .await
    }

    /// Create a legacy keeper container with an explicitly supplied resource ID.
    /// Egress attribution continues to use `task.id`; resource ownership uses `id`.
    pub async fn create_sandbox_with_id(
        &self,
        task: &Task,
        id: SandboxId,
        policy: &DerivedPolicy,
    ) -> Result<SandboxId, ReedeError> {
        self.create_sandbox_for_resource(task, id, policy, ContainerLaunch::Legacy)
            .await
    }

    /// Return the fixed piped, non-TTY primary-process start/attach command.
    pub fn prepare_primary_start(&self, id: SandboxId) -> PreparedPrimaryStart {
        PreparedPrimaryStart {
            program: self.docker_path.clone(),
            args: vec![
                "start".to_string(),
                "--attach".to_string(),
                "--interactive".to_string(),
                "--detach-keys=".to_string(),
                "--sig-proxy=false".to_string(),
                Self::container_name(id),
            ],
        }
    }

    /// Prepare value-less engine argv and the engine process environment.
    fn prepare_exec(
        &self,
        id: SandboxId,
        cmd: &SandboxCommand,
        interactive: bool,
    ) -> Result<PreparedExec, ReedeError> {
        Self::validate_exec_env(&cmd.env)?;
        let mut args: Vec<String> = vec!["exec".to_string()];
        if interactive {
            args.push("-i".to_string());
        }
        if let Some(dir) = &cmd.current_dir {
            args.push("--workdir".to_string());
            args.push(dir.clone());
        }
        for (k, _) in &cmd.env {
            args.push("--env".to_string());
            args.push(k.clone());
        }
        args.push(Self::container_name(id));
        args.push(cmd.program.clone());
        args.extend(cmd.args.iter().cloned());
        Ok((self.docker_path.clone(), args, cmd.env.clone()))
    }

    /// Prepare an interactive sandbox exec without spawning the engine.
    ///
    /// Environment values are returned separately for the caller to apply to
    /// the engine process; the argv contains only validated variable names. Any
    /// caller forwarding untrusted values must first apply a closed approved-name
    /// policy; syntactically valid engine controls such as `DOCKER_HOST` remain
    /// dangerous when supplied by an untrusted sandbox.
    pub fn interactive_exec(
        &self,
        id: SandboxId,
        cmd: &SandboxCommand,
    ) -> Result<PreparedExec, ReedeError> {
        self.prepare_exec(id, cmd, true)
    }

    /// Argv for tearing the sandbox container down.
    fn build_rm_args(id: SandboxId) -> Vec<String> {
        vec![
            "rm".to_string(),
            "--force".to_string(),
            "--volumes".to_string(),
            Self::container_name(id),
        ]
    }

    async fn run_sandbox_command(
        &self,
        id: SandboxId,
        args: &[String],
    ) -> Result<Output, ReedeError> {
        match self.runner.run(&self.docker_path, args).await {
            Ok(output) => Ok(output),
            Err(error) => {
                let _ = self.teardown_egress_network(id).await;
                Err(ReedeError::IsolationFailed {
                    reason: format!("Failed to spawn `{} run`: {error}", self.docker_path),
                })
            }
        }
    }

    /// Abort the sandbox's egress proxy and remove its per-task network.
    /// A no-op (beyond aborting any registered proxy) in `NetworkNone` mode.
    async fn teardown_egress_network(&self, id: SandboxId) -> Result<(), ReedeError> {
        // Remove the handle under the mutex, then abort and await it without
        // holding the global map lock so its listeners are closed on return.
        let handle = { active_proxies().lock().unwrap().remove(&id.0) };
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
        if matches!(self.egress_mode, EgressMode::ProxyGated(_)) {
            let output = self
                .runner
                .run(&self.docker_path, &Self::build_network_rm_args(id))
                .await
                .map_err(|error| ReedeError::IsolationFailed {
                    reason: format!("Failed to spawn owned network removal: {error}"),
                })?;
            if !output.status.success() {
                return Err(ReedeError::IsolationFailed {
                    reason: format!(
                        "Owned network removal failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                });
            }
        }
        Ok(())
    }
}

impl Default for GvisorBackend {
    fn default() -> Self {
        Self::new("docker", "runsc", "alpine:3.20")
    }
}

#[async_trait]
impl IsolationBackend for GvisorBackend {
    fn name(&self) -> &'static str {
        "GvisorBackend (docker --runtime=runsc, one sandbox per Task)"
    }

    async fn create_sandbox(
        &self,
        task: &Task,
        policy: &DerivedPolicy,
    ) -> Result<SandboxId, ReedeError> {
        self.create_sandbox_with_id(task, SandboxId(task.id), policy)
            .await
    }

    async fn destroy_sandbox(&self, id: SandboxId) -> Result<(), ReedeError> {
        let args = Self::build_rm_args(id);

        let result = self.runner.run(&self.docker_path, &args).await;

        // Always stop the owned proxy and attempt network removal, even if spawning
        // `docker rm` itself failed. Preserve the original container-removal error.
        let network_cleanup = self.teardown_egress_network(id).await;
        let output = result.map_err(|error| ReedeError::IsolationFailed {
            reason: format!("Failed to spawn `{} rm`: {error}", self.docker_path),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ReedeError::IsolationFailed {
                reason: format!("`docker rm` failed: {stderr}"),
            });
        }

        network_cleanup
    }

    async fn exec_in_sandbox(
        &self,
        id: SandboxId,
        cmd: SandboxCommand,
    ) -> Result<Output, ReedeError> {
        let (program, args, env) = self.prepare_exec(id, &cmd, false)?;

        self.runner
            .run_with_env(&program, &args, &env)
            .await
            .map_err(|e| ReedeError::IsolationFailed {
                reason: format!("`docker exec` failed: {e}"),
            })
    }
}

/// Select the backend without silently weakening isolation. Production is the
/// default profile. Passthrough requires both an explicit development profile
/// and an explicit passthrough backend.
pub fn isolation_backend_from_config(
    profile: &str,
    backend: &str,
) -> Result<Arc<dyn IsolationBackend>, ReedeError> {
    let production = match profile {
        "production" => true,
        "development" => false,
        _ => {
            return Err(ReedeError::IsolationFailed {
                reason: "REEDE_EXECUTION_PROFILE must be production or development".into(),
            })
        }
    };
    match backend {
        "gvisor" => Ok(Arc::new(GvisorBackend::from_env())),
        "passthrough" if !production => {
            tracing::warn!("development passthrough selected: no container isolation");
            Ok(Arc::new(PassthroughBackend))
        }
        _ => Err(ReedeError::IsolationFailed {
            reason:
                "explicit gvisor backend required; passthrough is permitted only in development"
                    .into(),
        }),
    }
}

/// Compatibility factory. Invalid or missing configuration returns a backend
/// that refuses every operation, rather than running commands without isolation.
pub fn create_isolation_backend() -> Arc<dyn IsolationBackend> {
    let profile = std::env::var("REEDE_EXECUTION_PROFILE").unwrap_or_else(|_| "production".into());
    let selection = std::env::var("REEDE_ISOLATION_BACKEND").unwrap_or_default();
    match isolation_backend_from_config(&profile, &selection) {
        Ok(backend) => backend,
        Err(error) => {
            tracing::error!(%error, "isolation configuration refused");
            Arc::new(RefusedIsolationBackend)
        }
    }
}

struct RefusedIsolationBackend;

#[async_trait]
impl IsolationBackend for RefusedIsolationBackend {
    fn name(&self) -> &'static str {
        "RefusedIsolationBackend"
    }
    async fn create_sandbox(
        &self,
        _task: &Task,
        _policy: &DerivedPolicy,
    ) -> Result<SandboxId, ReedeError> {
        Err(ReedeError::IsolationFailed {
            reason: "isolation configuration refused".into(),
        })
    }
    async fn destroy_sandbox(&self, _id: SandboxId) -> Result<(), ReedeError> {
        Err(ReedeError::IsolationFailed {
            reason: "isolation configuration refused".into(),
        })
    }
    async fn exec_in_sandbox(
        &self,
        _id: SandboxId,
        _cmd: SandboxCommand,
    ) -> Result<Output, ReedeError> {
        Err(ReedeError::IsolationFailed {
            reason: "isolation configuration refused".into(),
        })
    }
}

/// Development & test passthrough backend (clearly marked UNSAFE).
/// Executes commands in current environment without container/gVisor isolation.
pub struct PassthroughBackend;

#[async_trait]
impl IsolationBackend for PassthroughBackend {
    fn name(&self) -> &'static str {
        "PassthroughBackend (UNSAFE - no container isolation)"
    }

    async fn create_sandbox(
        &self,
        task: &Task,
        _policy: &DerivedPolicy,
    ) -> Result<SandboxId, ReedeError> {
        let sandbox_id = SandboxId(task.id);
        tracing::warn!(
            task_id = %task.id,
            "UNSAFE: PassthroughBackend created (no container isolation)"
        );
        Ok(sandbox_id)
    }

    async fn destroy_sandbox(&self, id: SandboxId) -> Result<(), ReedeError> {
        tracing::warn!(sandbox_id = %id.0, "PassthroughBackend destroy_sandbox (noop)");
        Ok(())
    }

    async fn exec_in_sandbox(
        &self,
        _id: SandboxId,
        cmd: SandboxCommand,
    ) -> Result<Output, ReedeError> {
        let mut process_cmd = tokio::process::Command::new(&cmd.program);
        process_cmd.args(&cmd.args);
        for (k, v) in &cmd.env {
            process_cmd.env(k, v);
        }
        if let Some(dir) = &cmd.current_dir {
            process_cmd.current_dir(dir);
        }

        let output = process_cmd
            .output()
            .await
            .map_err(|e| ReedeError::IsolationFailed {
                reason: format!("Passthrough exec failed: {e}"),
            })?;

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// Active egress-proxy registry.
//
// Keyed by sandbox resource id (equal to task id on the legacy path), holds the
// JoinHandle for the per-sandbox egress proxy
// (CONNECT + DNS filter) started by `GvisorBackend` in `ProxyGated` mode. The
// serving logic itself lives in `crate::egress_proxy`. `bin/reede.rs status`
// reads this to report the egress-wall state; `teardown_egress_network` aborts
// and removes an entry when a sandbox is destroyed.
// ---------------------------------------------------------------------------

static ACTIVE_PROXIES: OnceLock<StdMutex<HashMap<Uuid, tokio::task::JoinHandle<()>>>> =
    OnceLock::new();

pub fn active_proxies() -> &'static StdMutex<HashMap<Uuid, tokio::task::JoinHandle<()>>> {
    ACTIVE_PROXIES.get_or_init(|| StdMutex::new(HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DerivedPolicy;
    use std::sync::Mutex as StdMutex;

    fn test_policy() -> DerivedPolicy {
        DerivedPolicy {
            agent_id: "spec-1".to_string(),
            budget_ceiling_eur: 50.0,
            hitl_above_credits: 10,
            egress_allowlist: vec!["api.example.eu".to_string(), "data.example.eu".to_string()],
            resource_grants: vec![],
        }
    }

    /// Fake `CommandRunner` that records every `(program, args)` invocation and
    /// returns a configurable exit status — no real process is ever spawned.
    struct FakeRunner {
        calls: StdMutex<Vec<(String, Vec<String>)>>,
        succeed: bool,
    }

    type EnvCall = (String, Vec<String>, Vec<(String, String)>);

    struct EnvRecordingRunner {
        calls: StdMutex<Vec<EnvCall>>,
    }

    impl EnvRecordingRunner {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: StdMutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl CommandRunner for EnvRecordingRunner {
        async fn run(&self, _program: &str, _args: &[String]) -> std::io::Result<Output> {
            panic!("ordinary exec must use run_with_env")
        }

        async fn run_with_env(
            &self,
            program: &str,
            args: &[String],
            env: &[(String, String)],
        ) -> std::io::Result<Output> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec(), env.to_vec()));
            Ok(fake_output(0, b"", b""))
        }
    }

    struct IoFailRunner {
        calls: StdMutex<Vec<(String, Vec<String>)>>,
        fail_verb: &'static str,
    }

    #[async_trait]
    impl CommandRunner for IoFailRunner {
        async fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            if args
                .first()
                .is_some_and(|verb| verb.as_str() == self.fail_verb)
            {
                return Err(std::io::Error::other(format!(
                    "simulated {} spawn failure",
                    self.fail_verb
                )));
            }
            Ok(fake_output(0, b"", b""))
        }
    }

    async fn register_pending_proxy(id: Uuid) -> tokio::sync::oneshot::Receiver<()> {
        let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            std::future::pending::<()>().await;
            let _ = stopped_tx.send(());
        });
        active_proxies().lock().unwrap().insert(id, handle);
        stopped_rx
    }

    struct OverlapRunner {
        calls: StdMutex<Vec<(String, Vec<String>)>>,
    }

    #[async_trait]
    impl CommandRunner for OverlapRunner {
        async fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            Ok(fake_output(
                1,
                b"",
                b"Pool overlaps with other one on this address space",
            ))
        }
    }

    impl FakeRunner {
        fn new(succeed: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: StdMutex::new(Vec::new()),
                succeed,
            })
        }

        fn calls(&self) -> Vec<(String, Vec<String>)> {
            self.calls.lock().unwrap().clone()
        }

        fn last(&self) -> (String, Vec<String>) {
            self.calls.lock().unwrap().last().cloned().unwrap()
        }
    }

    #[async_trait]
    impl CommandRunner for FakeRunner {
        async fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
            self.calls
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec()));
            let code = if self.succeed { 0 } else { 1 };
            Ok(fake_output(
                code,
                b"",
                if self.succeed { b"" } else { b"boom" },
            ))
        }
    }

    /// Build a `std::process::Output` with a chosen exit code (unix targets).
    fn fake_output(code: i32, stdout: &[u8], stderr: &[u8]) -> Output {
        #[cfg(unix)]
        use std::os::unix::process::ExitStatusExt;
        Output {
            #[cfg(unix)]
            status: std::process::ExitStatus::from_raw(code << 8),
            #[cfg(not(unix))]
            status: Default::default(),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[tokio::test]
    async fn create_run_spawn_error_cleans_proxy_attempts_network_rm_once_and_preserves_error() {
        let id = Uuid::new_v4();
        let stopped_rx = register_pending_proxy(id).await;
        let runner = Arc::new(IoFailRunner {
            calls: StdMutex::new(Vec::new()),
            fail_verb: "run",
        });
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone())
            .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default()));
        let args = vec!["run".to_string()];
        let error = backend
            .run_sandbox_command(SandboxId(id), &args)
            .await
            .expect_err("injected runner error must be preserved");
        assert!(error.to_string().contains("simulated run spawn failure"));
        let calls = runner.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1[0], "run");
        assert_eq!(&calls[1].1[..2], &["network", "rm"]);
        assert!(!active_proxies().lock().unwrap().contains_key(&id));
        assert!(
            stopped_rx.await.is_err(),
            "registered proxy task was not cancelled"
        );
    }

    #[tokio::test]
    async fn destroy_rm_spawn_error_still_cleans_proxy_and_preserves_error() {
        let id = Uuid::new_v4();
        let stopped_rx = register_pending_proxy(id).await;
        let runner = Arc::new(IoFailRunner {
            calls: StdMutex::new(Vec::new()),
            fail_verb: "rm",
        });
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone())
            .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default()));
        let error = backend
            .destroy_sandbox(SandboxId(id))
            .await
            .expect_err("injected container removal error must be preserved");
        assert!(error.to_string().contains("simulated rm spawn failure"));
        let calls = runner.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1[0], "rm");
        assert_eq!(&calls[1].1[..2], &["network", "rm"]);
        assert!(!active_proxies().lock().unwrap().contains_key(&id));
        assert!(
            stopped_rx.await.is_err(),
            "registered proxy task was not cancelled"
        );
    }

    #[tokio::test]
    async fn subnet_overlap_retries_are_bounded_and_choose_distinct_octets() {
        let runner = Arc::new(OverlapRunner {
            calls: StdMutex::new(Vec::new()),
        });
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone())
            .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default()));
        let task = Task::new(Uuid::from_u128(1), "tenant-1", "spec-1", 50.0);
        assert!(backend.create_sandbox(&task, &test_policy()).await.is_err());
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 8);
        let subnets: Vec<_> = calls
            .iter()
            .map(|(_, args)| args[args.iter().position(|a| a == "--subnet").unwrap() + 1].clone())
            .collect();
        assert_eq!(
            subnets
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            8
        );
    }

    #[tokio::test]
    async fn invalid_deny_cidr_fails_before_network_creation() {
        let runner = FakeRunner::new(true);
        let mut cfg = ProxyGatedConfig::default();
        cfg.deny_cidrs.push("invalid".to_string());
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone())
            .with_egress_mode(EgressMode::ProxyGated(cfg));
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        assert!(backend.create_sandbox(&task, &test_policy()).await.is_err());
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn selected_retry_gateway_is_used_for_dns_and_proxy_env() {
        let backend = GvisorBackend::new("docker", "runsc", "image")
            .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default()));
        let id = SandboxId(Uuid::from_u128(1));
        let selected = Ipv4Addr::new(10, 250, 17, 1);
        let args = backend.build_run_args_with_gateway(id, &test_policy(), Some(selected));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--dns" && w[1] == "10.250.17.1"));
        assert!(args
            .iter()
            .any(|arg| arg == "HTTP_PROXY=http://10.250.17.1:13128"));
    }

    fn primary_launch(
        program: Option<&str>,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> PrimaryImageLaunch {
        PrimaryImageLaunch {
            program: program.map(str::to_string),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            env: env
                .iter()
                .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
                .collect(),
        }
    }

    #[tokio::test]
    async fn primary_prepare_creates_stopped_image_without_keeper_and_preserves_limits() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("podman", "runsc", "legacy", runner.clone());
        let task = Task::new(Uuid::from_u128(10), "tenant-1", "spec-1", 50.0);
        let child = SandboxId(Uuid::from_u128(20));
        backend
            .prepare_primary_image(
                &task,
                child,
                "registry.example/image@sha256:abc",
                &test_policy(),
                &primary_launch(None, &[], &[]),
            )
            .await
            .unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        let args = &calls[0].1;
        assert_eq!(&args[..2], &["create", "-i"]);
        assert!(args.contains(&"--runtime=runsc".to_string()));
        assert!(args.windows(2).any(|pair| {
            pair[0] == "--name" && pair[1] == GvisorBackend::container_name(child)
        }));
        assert!(args.contains(&"--read-only".to_string()));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--memory", "268435456"]));
        assert!(args.windows(2).any(|pair| pair == ["--pids-limit", "256"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--user", "65534:65534"]));
        assert!(args.contains(&"--pull=never".to_string()));
        assert!(args.windows(2).any(|pair| pair == ["--cap-drop", "ALL"]));
        assert_eq!(args.last().unwrap(), "registry.example/image@sha256:abc");
        assert!(!args
            .iter()
            .any(|arg| arg == "sleep" || arg == "infinity" || arg == "run" || arg == "start"));
    }

    #[tokio::test]
    async fn primary_launch_modes_keep_image_defaults_and_use_fixed_entrypoint() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("podman", "runsc", "unused", runner.clone());
        let task = Task::new(Uuid::from_u128(30), "tenant-1", "spec-1", 50.0);
        backend
            .prepare_primary_image(
                &task,
                SandboxId(Uuid::from_u128(31)),
                "image:one",
                &test_policy(),
                &primary_launch(None, &[], &[]),
            )
            .await
            .unwrap();
        backend
            .prepare_primary_image(
                &task,
                SandboxId(Uuid::from_u128(32)),
                "image:two",
                &test_policy(),
                &primary_launch(None, &["--version"], &[]),
            )
            .await
            .unwrap();
        backend
            .prepare_primary_image(
                &task,
                SandboxId(Uuid::from_u128(33)),
                "image:three",
                &test_policy(),
                &primary_launch(Some("reede-mcp-server"), &["serve"], &[]),
            )
            .await
            .unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1.last().unwrap(), "image:one");
        assert_eq!(
            &calls[1].1[calls[1].1.len() - 2..],
            &["image:two", "--version"]
        );
        assert!(calls[2]
            .1
            .windows(2)
            .any(|pair| pair == ["--entrypoint", "reede-mcp-server"]));
        assert_eq!(
            &calls[2].1[calls[2].1.len() - 2..],
            &["image:three", "serve"]
        );
    }

    #[tokio::test]
    async fn primary_resource_id_is_independent_from_parent_and_fixed_start_is_narrow() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("podman", "runsc", "unused", runner.clone());
        let task = Task::new(Uuid::from_u128(40), "tenant-1", "spec-1", 50.0);
        let first = SandboxId(Uuid::from_u128(41));
        let second = SandboxId(Uuid::from_u128(42));
        for child in [first, second] {
            assert_eq!(
                backend
                    .prepare_primary_image(
                        &task,
                        child,
                        "image",
                        &test_policy(),
                        &primary_launch(None, &[], &[])
                    )
                    .await
                    .unwrap(),
                child
            );
        }
        let calls = runner.calls();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].1.contains(&GvisorBackend::container_name(first)));
        assert!(calls[1].1.contains(&GvisorBackend::container_name(second)));
        assert_ne!(
            GvisorBackend::network_name(first),
            GvisorBackend::network_name(second)
        );
        // The finite subnet bucket mapping may collide for distinct resource IDs.
        // The overlap-retry test below verifies that the backend advances buckets.
        assert_eq!(
            GvisorBackend::subnet_for("172.30", first).0,
            GvisorBackend::subnet_for("172.30", second).0
        );
        let start = backend.prepare_primary_start(first);
        assert_eq!(start.program(), "podman");
        assert_eq!(
            start.args(),
            &[
                "start".to_string(),
                "--attach".to_string(),
                "--interactive".to_string(),
                "--detach-keys=".to_string(),
                "--sig-proxy=false".to_string(),
                GvisorBackend::container_name(first),
            ]
        );
        assert!(!start
            .args()
            .iter()
            .any(|arg| arg == "--env" || arg == "--entrypoint" || arg == "-t"));
    }

    #[test]
    fn primary_proxy_env_uses_trusted_gateway_and_never_argv_values() {
        let backend = GvisorBackend::new("podman", "runsc", "unused")
            .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default()));
        let launch = primary_launch(None, &[], &[]);
        let gateway = Ipv4Addr::new(10, 250, 17, 1);
        let args = backend.build_primary_create_args(
            SandboxId(Uuid::from_u128(77)),
            "image",
            &launch,
            Some(gateway),
        );
        assert!(args
            .windows(2)
            .any(|pair| { pair[0] == "--env" && pair[1] == "HTTP_PROXY" }));
        assert!(!args.iter().any(|arg| arg.contains("http://")));
        let env = backend.primary_engine_env(&launch, &test_policy(), Some(gateway));
        assert!(env.contains(&(
            "HTTP_PROXY".to_string(),
            "http://10.250.17.1:13128".to_string()
        )));
        assert!(!env
            .iter()
            .any(|(name, value)| { name == "HTTP_PROXY" && value != "http://10.250.17.1:13128" }));
    }

    #[test]
    fn primary_create_disables_automatic_proxy_and_tty_in_both_egress_modes() {
        let launch = primary_launch(None, &[], &[]);
        let id = SandboxId(Uuid::from_u128(78));
        let gateway = Ipv4Addr::new(10, 250, 17, 1);
        let backends = [
            GvisorBackend::new("podman", "runsc", "unused"),
            GvisorBackend::new("podman", "runsc", "unused")
                .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default())),
        ];
        for backend in backends {
            let args = backend.build_primary_create_args(id, "image", &launch, Some(gateway));
            assert!(args.contains(&"--http-proxy=false".to_string()));
            assert!(args.contains(&"--tty=false".to_string()));
            assert!(!args.contains(&"-t".to_string()));
            assert!(!args.contains(&"--tty".to_string()));
        }
    }

    #[tokio::test]
    async fn explicit_legacy_resource_id_preserves_keeper_and_trait_keeps_task_id() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("docker", "runsc", "image", runner.clone());
        let task = Task::new(Uuid::from_u128(80), "tenant-1", "spec-1", 50.0);
        let child = SandboxId(Uuid::from_u128(81));
        assert_eq!(
            backend
                .create_sandbox_with_id(&task, child, &test_policy())
                .await
                .unwrap(),
            child
        );
        let (_, child_args) = runner.last();
        assert_eq!(child_args[0], "run");
        assert!(child_args.contains(&GvisorBackend::container_name(child)));
        assert_eq!(&child_args[child_args.len() - 2..], &["sleep", "infinity"]);
        assert_eq!(
            backend.create_sandbox(&task, &test_policy()).await.unwrap(),
            SandboxId(task.id)
        );
    }

    #[tokio::test]
    async fn proxy_teardown_is_keyed_by_child_resource_not_parent_task() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("docker", "runsc", "image", runner.clone())
            .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default()));
        let parent = Uuid::from_u128(82);
        let child = Uuid::from_u128(83);
        let child_stopped = register_pending_proxy(child).await;
        let parent_stopped = register_pending_proxy(parent).await;
        backend
            .teardown_egress_network(SandboxId(child))
            .await
            .unwrap();
        assert!(!active_proxies().lock().unwrap().contains_key(&child));
        assert!(active_proxies().lock().unwrap().contains_key(&parent));
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1,
            GvisorBackend::build_network_rm_args(SandboxId(child))
        );
        assert!(child_stopped.await.is_err());
        let parent_handle = active_proxies().lock().unwrap().remove(&parent).unwrap();
        parent_handle.abort();
        assert!(parent_stopped.await.is_err());
    }

    #[tokio::test]
    async fn primary_env_values_are_child_only_redacted_and_never_in_argv() {
        let runner = EnvRecordingRunner::new();
        let backend = GvisorBackend::with_runner("podman", "runsc", "unused", runner.clone());
        let task = Task::new(Uuid::from_u128(50), "tenant-1", "spec-1", 50.0);
        let launch = primary_launch(None, &[], &[("API_TOKEN", "super-secret-value")]);
        backend
            .prepare_primary_image(
                &task,
                SandboxId(Uuid::from_u128(51)),
                "image",
                &test_policy(),
                &launch,
            )
            .await
            .unwrap();
        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].1.contains(&"API_TOKEN".to_string()));
        assert!(!calls[0]
            .1
            .iter()
            .any(|arg| arg.contains("super-secret-value") || arg.contains("API_TOKEN=")));
        assert!(calls[0]
            .2
            .contains(&("API_TOKEN".to_string(), "super-secret-value".to_string())));
        assert!(!format!("{launch:?}").contains("super-secret-value"));
    }

    struct SecretStderrRunner;

    #[async_trait]
    impl CommandRunner for SecretStderrRunner {
        async fn run(&self, _program: &str, _args: &[String]) -> std::io::Result<Output> {
            Ok(fake_output(1, b"", b"engine echoed super-secret-value"))
        }

        async fn run_with_env(
            &self,
            _program: &str,
            _args: &[String],
            _env: &[(String, String)],
        ) -> std::io::Result<Output> {
            Ok(fake_output(1, b"", b"engine echoed super-secret-value"))
        }
    }

    #[tokio::test]
    async fn primary_failure_does_not_copy_engine_stderr_into_error() {
        let backend =
            GvisorBackend::with_runner("podman", "runsc", "unused", Arc::new(SecretStderrRunner));
        let task = Task::new(Uuid::from_u128(55), "tenant-1", "spec-1", 50.0);
        let launch = primary_launch(None, &[], &[("API_TOKEN", "super-secret-value")]);
        let error = backend
            .prepare_primary_image(
                &task,
                SandboxId(Uuid::from_u128(56)),
                "image",
                &test_policy(),
                &launch,
            )
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("super-secret-value"));
    }

    #[tokio::test]
    async fn invalid_primary_program_or_environment_fails_before_engine_effects() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("podman", "runsc", "unused", runner.clone());
        let task = Task::new(Uuid::from_u128(60), "tenant-1", "spec-1", 50.0);
        for launch in [
            primary_launch(Some("/bin/sh"), &[], &[]),
            primary_launch(None, &[], &[("BAD-NAME", "x")]),
            primary_launch(None, &[], &[("DUP", "x"), ("DUP", "y")]),
            primary_launch(None, &[], &[("REEDE_EGRESS_ALLOWLIST", "override")]),
        ] {
            assert!(backend
                .prepare_primary_image(
                    &task,
                    SandboxId(Uuid::new_v4()),
                    "image",
                    &test_policy(),
                    &launch
                )
                .await
                .is_err());
        }
        for image in ["", "-image", "image\nname"] {
            assert!(backend
                .prepare_primary_image(
                    &task,
                    SandboxId(Uuid::new_v4()),
                    image,
                    &test_policy(),
                    &primary_launch(None, &[], &[])
                )
                .await
                .is_err());
        }
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn create_sandbox_builds_docker_run_with_runsc_runtime() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone());
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);

        let sandbox_id = backend.create_sandbox(&task, &test_policy()).await.unwrap();

        // One-sandbox-per-Task: the handle is exactly the task id.
        assert_eq!(sandbox_id.0, task.id);

        let (program, args) = runner.last();
        assert_eq!(program, "docker");
        // The linchpin flag: the sandbox opts into the gVisor docker runtime.
        assert!(
            args.contains(&"--runtime=runsc".to_string()),
            "argv must force the runsc runtime, got {args:?}"
        );
        assert_eq!(args.first().map(String::as_str), Some("run"));
        assert!(args.contains(&"-d".to_string()));
        // Deterministic per-task container name.
        let name_idx = args.iter().position(|a| a == "--name").unwrap();
        assert_eq!(args[name_idx + 1], format!("reede-sbx-{}", task.id));
        // Fail-closed egress default for S9.
        let net_idx = args.iter().position(|a| a == "--network").unwrap();
        assert_eq!(args[net_idx + 1], "none");
        // Hardening flags.
        assert!(args.contains(&"--read-only".to_string()));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--memory" && w[1] == "268435456"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--pids-limit" && w[1] == "256"));
        assert!(args.windows(2).any(|w| w[0] == "--cpus" && w[1] == "1.0"));
        assert!(!args.contains(&"--cpu-shares".to_string()));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--tmpfs" && w[1] == "/tmp:rw,size=64m,noexec"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--user" && w[1] == "65534:65534"));
        assert!(args.contains(&"--pull=never".to_string()));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--cap-drop" && w[1] == "ALL"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--security-opt" && w[1] == "no-new-privileges"));
        // Egress allowlist propagated as env (advisory in S9).
        assert!(args.contains(&"REEDE_EGRESS_ALLOWLIST=api.example.eu,data.example.eu".to_string()));
        // Image and long-lived entrypoint are the trailing args, in order.
        assert_eq!(
            &args[args.len() - 3..],
            &[
                "alpine:3.20".to_string(),
                "sleep".to_string(),
                "infinity".to_string()
            ]
        );
    }

    #[test]
    fn from_env_marks_invalid_limits_as_configuration_errors() {
        let previous = std::env::var_os("REEDE_SANDBOX_PIDS");
        std::env::set_var("REEDE_SANDBOX_PIDS", "0");
        let backend = GvisorBackend::from_env();
        if let Some(value) = previous {
            std::env::set_var("REEDE_SANDBOX_PIDS", value);
        } else {
            std::env::remove_var("REEDE_SANDBOX_PIDS");
        }
        assert!(backend
            .config_error
            .as_deref()
            .unwrap()
            .contains("REEDE_SANDBOX_PIDS"));
    }

    #[tokio::test]
    async fn invalid_limit_configuration_fails_before_engine_invocation() {
        let runner = FakeRunner::new(true);
        let mut backend =
            GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone());
        backend.config_error = Some("REEDE_SANDBOX_PIDS must be a positive integer".to_string());
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        let err = backend
            .create_sandbox(&task, &test_policy())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("REEDE_SANDBOX_PIDS"));
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn command_runner_override_preserves_configured_create_and_destroy() {
        let original = FakeRunner::new(false);
        let replacement = FakeRunner::new(true);
        let mut backend = GvisorBackend::with_runner(
            "configured-engine",
            "configured-runtime",
            "configured-image",
            original.clone(),
        )
        .with_resource_limits(512_000_000, 64, 0.5)
        .unwrap();
        backend.limits.cgroup_parent = Some("configured.slice".to_string());
        let backend = backend.with_command_runner(replacement.clone());
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        let id = backend.create_sandbox(&task, &test_policy()).await.unwrap();
        backend.destroy_sandbox(id).await.unwrap();
        assert!(original.calls().is_empty());
        let calls = replacement.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "configured-engine");
        let args = &calls[0].1;
        for (flag, value) in [
            ("--memory", "512000000"),
            ("--pids-limit", "64"),
            ("--cpus", "0.5"),
            ("--cgroup-parent", "configured.slice"),
            ("--network", "none"),
        ] {
            assert!(args.windows(2).any(|w| w[0] == flag && w[1] == value));
        }
        assert!(args.iter().any(|arg| arg == "--runtime=configured-runtime"));
        assert!(args.iter().any(|arg| arg == "configured-image"));
        assert_eq!(calls[1].0, "configured-engine");
        assert_eq!(calls[1].1[0], "rm");
    }

    #[tokio::test]
    async fn command_runner_override_cannot_repair_invalid_configuration_or_egress() {
        for invalid_egress in [false, true] {
            let replacement = FakeRunner::new(true);
            let mut backend = GvisorBackend::new("configured-engine", "runtime", "image");
            if invalid_egress {
                let mut cfg = ProxyGatedConfig::default();
                cfg.deny_cidrs.push("invalid".to_string());
                backend.egress_mode = EgressMode::ProxyGated(cfg);
            } else {
                backend.config_error = Some("operator configuration invalid".to_string());
            }
            let backend = backend.with_command_runner(replacement.clone());
            let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
            assert!(backend.create_sandbox(&task, &test_policy()).await.is_err());
            assert!(replacement.calls().is_empty());
        }
    }

    #[test]
    fn request_resource_limits_preserve_operator_cgroup_and_reach_run_argv() {
        let mut backend = GvisorBackend::new("docker", "runsc", "image");
        backend.limits.cgroup_parent = Some("operator-owned.slice".to_string());
        let backend = backend.with_resource_limits(512_000_000, 64, 0.5).unwrap();
        let args = backend.build_run_args(SandboxId(Uuid::from_u128(1)), &test_policy());
        for pair in [
            ["--memory", "512000000"],
            ["--pids-limit", "64"],
            ["--cpus", "0.5"],
            ["--cgroup-parent", "operator-owned.slice"],
        ] {
            assert!(args
                .windows(2)
                .any(|actual| actual[0] == pair[0] && actual[1] == pair[1]));
        }
    }

    #[test]
    fn invalid_request_resource_limits_are_rejected_without_engine_calls() {
        for (memory, pids, cpus) in [
            (0, 64, 1.0),
            (u64::MAX, 64, 1.0),
            (268_435_456, 0, 1.0),
            (268_435_456, u32::MAX, 1.0),
            (268_435_456, 64, 0.0),
            (268_435_456, 64, -1.0),
            (268_435_456, 64, f64::NAN),
            (268_435_456, 64, f64::INFINITY),
        ] {
            let runner = FakeRunner::new(true);
            let backend = GvisorBackend::with_runner("docker", "runsc", "image", runner.clone());
            assert!(backend.with_resource_limits(memory, pids, cpus).is_err());
            assert!(runner.calls().is_empty());
        }
    }

    #[test]
    fn request_resource_limits_cannot_repair_invalid_operator_configuration() {
        let runner = FakeRunner::new(true);
        let mut backend = GvisorBackend::with_runner("docker", "runsc", "image", runner.clone());
        backend.config_error = Some("invalid operator configuration".to_string());
        let error = backend
            .with_resource_limits(268_435_456, 64, 1.0)
            .err()
            .unwrap();
        assert!(error.to_string().contains("invalid operator configuration"));
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn configured_hard_limits_and_cgroup_parent_are_in_run_argv() {
        let mut backend = GvisorBackend::new("docker", "runsc", "image");
        backend.limits = SandboxLimits {
            memory_bytes: 512_000_000,
            pids: 64,
            cpus: "0.5".to_string(),
            cgroup_parent: Some("reede-sbx.slice".to_string()),
        };
        let args = backend.build_run_args(SandboxId(Uuid::from_u128(1)), &test_policy());
        for pair in [
            ["--memory", "512000000"],
            ["--pids-limit", "64"],
            ["--cpus", "0.5"],
            ["--cgroup-parent", "reede-sbx.slice"],
        ] {
            assert!(args
                .windows(2)
                .any(|actual| actual[0] == pair[0] && actual[1] == pair[1]));
        }
    }

    #[tokio::test]
    async fn runtime_name_and_docker_path_are_configurable() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner(
            "/opt/podman",
            "runsc-eu",
            "ghcr.io/example/reede-sandbox:latest",
            runner.clone(),
        );
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);

        backend.create_sandbox(&task, &test_policy()).await.unwrap();

        let (program, args) = runner.last();
        assert_eq!(program, "/opt/podman");
        assert!(args.contains(&"--runtime=runsc-eu".to_string()));
        assert!(args.contains(&"ghcr.io/example/reede-sandbox:latest".to_string()));
    }

    #[tokio::test]
    async fn exec_in_sandbox_builds_docker_exec_argv() {
        let runner = EnvRecordingRunner::new();
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone());
        let id = SandboxId(Uuid::new_v4());

        let cmd = SandboxCommand {
            program: "python3".to_string(),
            args: vec!["-c".to_string(), "print(1)".to_string()],
            env: vec![("FOO".to_string(), "bar".to_string())],
            current_dir: Some("/work".to_string()),
        };

        backend.exec_in_sandbox(id, cmd).await.unwrap();

        let calls = runner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (program, args, env) = &calls[0];
        assert_eq!(program, "docker");
        assert_eq!(args[0], "exec");
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--workdir" && w[1] == "/work"));
        assert!(args.windows(2).any(|w| w[0] == "--env" && w[1] == "FOO"));
        assert!(!args.iter().any(|arg| arg.contains("bar")));
        assert_eq!(env, &vec![("FOO".to_string(), "bar".to_string())]);
        // Targets the task's container, then program + its args in order.
        let name = format!("reede-sbx-{}", id.0);
        let name_idx = args.iter().position(|a| a == &name).unwrap();
        assert_eq!(&args[name_idx + 1..], &["python3", "-c", "print(1)"]);
    }

    #[tokio::test]
    async fn malformed_environment_names_are_rejected_before_runner_invocation() {
        let runner = EnvRecordingRunner::new();
        let backend = GvisorBackend::with_runner("engine", "runsc", "image", runner.clone());
        let cmd = SandboxCommand {
            program: "engine-client".to_string(),
            args: vec![],
            env: vec![("BAD-NAME".to_string(), "value".to_string())],
            current_dir: None,
        };
        assert!(backend
            .exec_in_sandbox(SandboxId(Uuid::new_v4()), cmd)
            .await
            .is_err());
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn syntactically_valid_engine_environment_names_are_not_silently_rewritten() {
        let runner = EnvRecordingRunner::new();
        let backend = GvisorBackend::with_runner("engine", "runsc", "image", runner.clone());
        let cmd = SandboxCommand {
            program: "engine-client".to_string(),
            args: vec![],
            env: vec![(
                "DOCKER_HOST".to_string(),
                "tcp://127.0.0.1:2375".to_string(),
            )],
            current_dir: None,
        };
        backend
            .exec_in_sandbox(SandboxId(Uuid::new_v4()), cmd)
            .await
            .unwrap();
        assert_eq!(runner.calls.lock().unwrap()[0].2[0].0, "DOCKER_HOST");
    }

    #[tokio::test]
    async fn exec_preserves_duplicate_env_pairs_and_arbitrary_values() {
        let runner = EnvRecordingRunner::new();
        let backend = GvisorBackend::with_runner("engine", "runsc", "image", runner.clone());
        let id = SandboxId(Uuid::new_v4());
        let env = vec![
            ("FIRST".to_string(), "punctuation =,:!".to_string()),
            ("EMPTY".to_string(), String::new()),
            ("FIRST".to_string(), "last".to_string()),
        ];
        let cmd = SandboxCommand {
            program: "tool".to_string(),
            args: vec!["argument".to_string()],
            env: env.clone(),
            current_dir: None,
        };

        backend.exec_in_sandbox(id, cmd).await.unwrap();

        let calls = runner.calls.lock().unwrap();
        let (_, args, recorded_env) = &calls[0];
        assert_eq!(recorded_env, &env);
        assert_eq!(args.iter().filter(|arg| *arg == "--env").count(), 3);
        assert!(!env
            .iter()
            .any(|(_, value)| !value.is_empty() && args.contains(value)));
    }

    #[test]
    fn interactive_exec_prepares_without_calling_runner() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("/opt/engine", "runsc", "image", runner.clone());
        let id = SandboxId(Uuid::new_v4());
        let env = vec![("TOKEN".to_string(), "synthetic:value".to_string())];
        let cmd = SandboxCommand {
            program: "python3".to_string(),
            args: vec!["script.py".to_string()],
            env: env.clone(),
            current_dir: Some("/workspace".to_string()),
        };

        let (program, args, prepared_env) = backend.interactive_exec(id, &cmd).unwrap();

        assert_eq!(program, "/opt/engine");
        assert_eq!(args.iter().filter(|arg| *arg == "-i").count(), 1);
        assert_eq!(
            args,
            vec![
                "exec".to_string(),
                "-i".to_string(),
                "--workdir".to_string(),
                "/workspace".to_string(),
                "--env".to_string(),
                "TOKEN".to_string(),
                format!("reede-sbx-{}", id.0),
                "python3".to_string(),
                "script.py".to_string(),
            ]
        );
        assert_eq!(prepared_env, env);
        assert!(runner.calls().is_empty());

        let empty_cmd = SandboxCommand {
            program: "true".to_string(),
            args: vec![],
            env: vec![],
            current_dir: None,
        };
        let (_, empty_args, empty_env) = backend.interactive_exec(id, &empty_cmd).unwrap();
        assert_eq!(
            empty_args,
            vec![
                "exec".to_string(),
                "-i".to_string(),
                format!("reede-sbx-{}", id.0),
                "true".to_string(),
            ]
        );
        assert!(empty_env.is_empty());
        assert!(runner.calls().is_empty());
    }

    #[tokio::test]
    async fn invalid_env_names_fail_before_runner_and_do_not_leak_input() {
        for name in ["", "=VALUE", "-OPTION", "BAD-NAME", "9START", "BAD\0NAME"] {
            let runner = EnvRecordingRunner::new();
            let backend = GvisorBackend::with_runner("engine", "runsc", "image", runner.clone());
            let cmd = SandboxCommand {
                program: "tool".to_string(),
                args: vec![],
                env: vec![(name.to_string(), "sensitive-sentinel".to_string())],
                current_dir: None,
            };

            let ordinary = backend
                .exec_in_sandbox(SandboxId(Uuid::new_v4()), cmd.clone())
                .await;
            let interactive = backend.interactive_exec(SandboxId(Uuid::new_v4()), &cmd);
            for error in [ordinary.unwrap_err(), interactive.unwrap_err()] {
                for text in [format!("{error:?}"), error.to_string()] {
                    assert!(
                        name.is_empty() || !text.contains(name),
                        "error leaked invalid name"
                    );
                    assert!(!text.contains("sensitive-sentinel"), "error leaked value");
                    assert!(text.len() < 200);
                }
            }
            assert!(runner.calls.lock().unwrap().is_empty());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tokio_runner_applies_child_only_environment_with_last_value_wins() {
        const NAME: &str = "REEDE_SYNTHETIC_EXEC_ENV_TEST_2049";
        const EMPTY: &str = "REEDE_SYNTHETIC_EMPTY_TEST_2049";
        let parent_before = std::env::var_os(NAME);
        let empty_parent_before = std::env::var_os(EMPTY);
        let first = "synthetic-first=not-in-argv";
        let last = "synthetic-last=not-in-argv;$(never-run)";
        // Only variable names enter the fixed shell script. Expected values
        // are asserted in Rust, so this actually tests their absence from argv.
        let args = vec![
            "-c".to_string(),
            format!("printf '%s\n%s' \"${{{NAME}}}\" \"${{{EMPTY}}}\""),
        ];
        let env = vec![
            (NAME.to_string(), first.to_string()),
            (EMPTY.to_string(), String::new()),
            (NAME.to_string(), last.to_string()),
        ];
        assert!(env
            .iter()
            .all(|(_, value)| { value.is_empty() || args.iter().all(|arg| !arg.contains(value)) }));

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            TokioCommandRunner.run_with_env("/bin/sh", &args, &env),
        )
        .await
        .expect("fixed local environment fixture timed out")
        .unwrap();

        assert!(
            output.status.success(),
            "fixture stderr: {:?}",
            output.stderr
        );
        assert_eq!(output.stdout, format!("{last}\n").as_bytes());
        assert_eq!(std::env::var_os(NAME), parent_before);
        assert_eq!(std::env::var_os(EMPTY), empty_parent_before);
    }

    struct NetworkCleanupFailureRunner {
        io_error: bool,
        container_fails: bool,
        calls: StdMutex<Vec<Vec<String>>>,
    }
    #[async_trait]
    impl CommandRunner for NetworkCleanupFailureRunner {
        async fn run(&self, _program: &str, args: &[String]) -> std::io::Result<Output> {
            self.calls.lock().unwrap().push(args.to_vec());
            if args.first().is_some_and(|arg| arg == "network") {
                if self.io_error {
                    return Err(std::io::Error::other("fixture network cleanup I/O error"));
                }
                return Ok(fake_output(1, b"", b"fixture network cleanup failure"));
            }
            Ok(fake_output(
                if self.container_fails { 1 } else { 0 },
                b"",
                b"fixture container failure",
            ))
        }
    }

    #[tokio::test]
    async fn network_cleanup_failure_is_reported_after_successful_container_removal() {
        for io_error in [false, true] {
            let runner = Arc::new(NetworkCleanupFailureRunner {
                io_error,
                container_fails: false,
                calls: StdMutex::new(Vec::new()),
            });
            let backend = proxy_backend(runner.clone());
            let error = backend
                .destroy_sandbox(SandboxId(Uuid::new_v4()))
                .await
                .unwrap_err();
            assert!(error.to_string().to_lowercase().contains("network"));
            let calls = runner.calls.lock().unwrap();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0][0], "rm");
            assert_eq!(&calls[1][..2], &["network", "rm"]);
        }
    }

    #[tokio::test]
    async fn network_cleanup_failure_preserves_primary_container_removal_error() {
        let runner = Arc::new(NetworkCleanupFailureRunner {
            io_error: true,
            container_fails: true,
            calls: StdMutex::new(Vec::new()),
        });
        let backend = proxy_backend(runner.clone());
        let error = backend
            .destroy_sandbox(SandboxId(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("fixture container failure"));
        assert_eq!(runner.calls.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn destroy_sandbox_builds_docker_rm_force_argv() {
        let runner = FakeRunner::new(true);
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone());
        let id = SandboxId(Uuid::new_v4());

        backend.destroy_sandbox(id).await.unwrap();

        let (program, args) = runner.last();
        assert_eq!(program, "docker");
        assert_eq!(
            args,
            vec![
                "rm".to_string(),
                "--force".to_string(),
                "--volumes".to_string(),
                format!("reede-sbx-{}", id.0),
            ]
        );
    }

    #[tokio::test]
    async fn nonzero_docker_exit_is_isolation_failed() {
        let runner = FakeRunner::new(false); // docker run returns exit 1
        let backend = GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner.clone());
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);

        let res = backend.create_sandbox(&task, &test_policy()).await;
        assert!(matches!(res, Err(ReedeError::IsolationFailed { .. })));
        // Exactly one docker invocation was attempted.
        assert_eq!(runner.calls().len(), 1);
    }

    #[tokio::test]
    async fn isolation_configuration_refuses_missing_and_unknown_backends() {
        for profile in ["production", "development"] {
            for backend in ["", "gvisro", "auto"] {
                assert!(isolation_backend_from_config(profile, backend).is_err());
            }
        }
        assert!(isolation_backend_from_config("production", "passthrough").is_err());
        assert!(isolation_backend_from_config("prod", "gvisor").is_err());
        assert!(isolation_backend_from_config("development", "passthrough")
            .unwrap()
            .name()
            .starts_with("PassthroughBackend"));
        assert!(isolation_backend_from_config("production", "gvisor").is_ok());
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);
        assert!(RefusedIsolationBackend
            .create_sandbox(&task, &test_policy())
            .await
            .is_err());
        let cmd = SandboxCommand {
            program: "echo".into(),
            args: vec![],
            env: vec![],
            current_dir: None,
        };
        assert!(RefusedIsolationBackend
            .exec_in_sandbox(SandboxId(task.id), cmd)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_passthrough_sandbox_lifecycle() {
        let backend = PassthroughBackend;
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);

        let sandbox_id = backend.create_sandbox(&task, &test_policy()).await.unwrap();
        assert_eq!(sandbox_id.0, task.id);

        let cmd = SandboxCommand {
            program: "echo".to_string(),
            args: vec!["reede_isolation_test".to_string()],
            env: vec![],
            current_dir: None,
        };

        let output = backend.exec_in_sandbox(sandbox_id, cmd).await.unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("reede_isolation_test"));

        assert!(backend.destroy_sandbox(sandbox_id).await.is_ok());
    }

    // -----------------------------------------------------------------------
    // S10: proxy-gated egress network argv (pure builders; no host needed).
    // -----------------------------------------------------------------------

    fn proxy_backend(runner: Arc<dyn CommandRunner>) -> GvisorBackend {
        GvisorBackend::with_runner("docker", "runsc", "alpine:3.20", runner)
            .with_egress_mode(EgressMode::ProxyGated(ProxyGatedConfig::default()))
    }

    #[test]
    fn subnet_for_is_deterministic_and_in_range() {
        let id = SandboxId(Uuid::new_v4());
        let (subnet_a, gw_a) = GvisorBackend::subnet_for("172.30", id);
        let (subnet_b, gw_b) = GvisorBackend::subnet_for("172.30", id);
        // Deterministic for a given task id.
        assert_eq!(subnet_a, subnet_b);
        assert_eq!(gw_a, gw_b);
        // Gateway is the .1 of the /24, third octet in 1..=254.
        assert!(subnet_a.starts_with("172.30."));
        assert!(subnet_a.ends_with(".0/24"));
        let octet = gw_a.octets()[2];
        assert!((1..=254).contains(&octet));
        assert_eq!(gw_a.octets()[3], 1);
    }

    #[test]
    fn network_create_args_build_an_internal_network() {
        let id = SandboxId(Uuid::new_v4());
        let (subnet, gateway) = GvisorBackend::subnet_for("172.30", id);
        let args = GvisorBackend::build_network_create_args(id, &subnet, gateway);

        assert_eq!(&args[0..2], &["network", "create"]);
        // The namespace-layer wall: no route to the internet.
        assert!(args.contains(&"--internal".to_string()));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--subnet" && w[1] == subnet));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--gateway" && w[1] == gateway.to_string()));
        // Deterministic per-task network name is the last arg.
        assert_eq!(args.last().unwrap(), &format!("reede-egr-{}", id.0));
    }

    #[tokio::test]
    async fn proxy_gated_run_args_replace_network_none_with_the_egress_net() {
        let runner = FakeRunner::new(true);
        let backend = proxy_backend(runner.clone());
        let id = SandboxId(Uuid::new_v4());
        let (_subnet, gateway) = GvisorBackend::subnet_for("172.30", id);

        let args = backend.build_run_args(id, &test_policy());

        // No `--network none` anymore.
        assert!(
            !args
                .windows(2)
                .any(|w| w[0] == "--network" && w[1] == "none"),
            "proxy-gated mode must not use --network none"
        );
        // The sandbox's only network is its per-task internal one.
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--network" && w[1] == format!("reede-egr-{}", id.0)));
        // DNS points at the gateway (the Reede DNS filter).
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--dns" && w[1] == gateway.to_string()));
        // Cooperative proxy env is pointed at the gateway:port.
        let proxy_url = format!("http://{gateway}:{DEFAULT_PROXY_PORT}");
        assert!(args.contains(&format!("HTTP_PROXY={proxy_url}")));
        assert!(args.contains(&format!("HTTPS_PROXY={proxy_url}")));
        // Hardening flags (route/namespace-rewrite defense) are still present.
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--cap-drop" && w[1] == "ALL"));
        assert!(args
            .windows(2)
            .any(|w| w[0] == "--security-opt" && w[1] == "no-new-privileges"));
        assert!(args.contains(&"--runtime=runsc".to_string()));
    }

    #[test]
    fn from_env_defaults_to_proxy_gated_and_honours_none() {
        std::env::set_var("REEDE_EGRESS_MODE", "proxy");
        let backend = GvisorBackend::from_env();
        assert!(matches!(backend.egress_mode, EgressMode::ProxyGated(_)));

        std::env::set_var("REEDE_EGRESS_MODE", "none");
        let backend = GvisorBackend::from_env();
        assert!(matches!(backend.egress_mode, EgressMode::NetworkNone));
        std::env::remove_var("REEDE_EGRESS_MODE");
    }

    /// Real end-to-end sandbox test. Gated behind BOTH an explicit opt-in
    /// (`REEDE_RUNSC_E2E=1`) and the presence of the docker client, so CI — which
    /// has neither runsc nor the opt-in — SKIPS it cleanly and stays green. It
    /// only actually runs on a host provisioned per the S9 runbook.
    #[tokio::test]
    async fn e2e_real_runsc_sandbox_roundtrip() {
        let require = std::env::var("REEDE_RUNSC_E2E_REQUIRE").as_deref() == Ok("1");
        if !require && std::env::var("REEDE_RUNSC_E2E").as_deref() != Ok("1") {
            eprintln!("SKIP e2e_real_runsc_sandbox_roundtrip: set REEDE_RUNSC_E2E=1 on a runsc host to run");
            return;
        }
        // Secondary guard: need a docker client on PATH (or DOCKER_BIN).
        let docker = std::env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string());
        if which_on_path(&docker).is_none() {
            if require {
                panic!("e2e_real_runsc_sandbox_roundtrip: REEDE_RUNSC_E2E_REQUIRE=1 but docker client `{docker}` is missing");
            }
            eprintln!("SKIP e2e_real_runsc_sandbox_roundtrip: docker client `{docker}` not found");
            return;
        }

        let backend = GvisorBackend::from_env();
        let task = Task::new(Uuid::new_v4(), "tenant-1", "spec-1", 50.0);

        let sandbox_id = backend
            .create_sandbox(&task, &test_policy())
            .await
            .expect("create_sandbox should succeed on a provisioned runsc host");

        let cmd = SandboxCommand {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), "echo gvisor_e2e".to_string()],
            env: vec![],
            current_dir: None,
        };
        let output = backend.exec_in_sandbox(sandbox_id, cmd).await.unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("gvisor_e2e"), "unexpected stdout: {stdout}");

        backend.destroy_sandbox(sandbox_id).await.unwrap();
    }

    /// Minimal PATH lookup for the e2e guard (avoids a `which` crate dependency).
    fn which_on_path(bin: &str) -> Option<String> {
        if bin.contains('/') {
            return std::path::Path::new(bin).exists().then(|| bin.to_string());
        }
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|dir| dir.join(bin))
            .find(|p| p.exists())
            .map(|p| p.to_string_lossy().into_owned())
    }
}
