//! S10 adversarial egress suite (plan criterion 2 proof, M3).
//!
//! These tests prove that a proxy-gated gVisor sandbox lets NOTHING off the
//! allowlist out — by *attacking* the sandbox from the inside and asserting each
//! attempt is blocked, plus one positive test that an allowlisted destination is
//! reachable through the proxy.
//!
//! ## Gating — why CI stays green
//!
//! Tests opt in with `REEDE_RUNSC_E2E=1` and require a docker client on PATH
//! (or `DOCKER_BIN`). `REEDE_RUNSC_E2E_REQUIRE=1` makes the suite eligible
//! without the ordinary opt-in and fails with a named error if the client is missing.
//!
//! CI has neither the opt-in nor a runsc host, so each test prints a SKIP line
//! and returns `Ok`. They only actually run on the App Node provisioned per the
//! S9 runbook, where `REEDE_ISOLATION_BACKEND=gvisor REEDE_RUNSC_E2E=1` is set.
//!
//! ## What each test does (run these on the host to validate)
//!
//! | # | Scenario                         | In-sandbox command (essence)                 | Expect |
//! |---|----------------------------------|----------------------------------------------|--------|
//! | a | raw socket to off-allowlist IP   | `nc -w3 -z 1.1.1.1 80`                        | BLOCKED |
//! | b | direct-IP connect bypassing DNS  | `wget http://1.1.1.1/`                        | BLOCKED |
//! | c | DNS for an off-allowlist host    | `nslookup tracker.evil.example`              | BLOCKED |
//! | d | namespace escape attempt         | `unshare -n true` / `mount -t proc …`        | BLOCKED |
//! | e | route-rewrite attempt            | `ip route add default via <gw2>`             | BLOCKED |
//! | + | allowlisted destination (positive)| `wget https://example.com/`                 | REACHABLE |

use reede::egress::{DeniedEgress, FlagToHuman};
use reede::egress_proxy::HostResolver;
use reede::error::ReedeError;
use reede::isolation::{
    CommandRunner, EgressMode, GvisorBackend, IsolationBackend, ProxyGatedConfig, SandboxCommand,
};
use reede::policy::DerivedPolicy;
use reede::task::Task;
use reede::SandboxId;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{ops::Deref, sync::mpsc};
use uuid::Uuid;

/// The single allowlisted host for the whole suite. Everything else must be
/// blocked; this one must be reachable through the proxy. The positive acceptance
/// case therefore depends on this external destination being available; it is not
/// suitable for an offline readiness probe.
const ALLOWED_HOST: &str = "example.com";

fn require_runsc_e2e() -> bool {
    std::env::var("REEDE_RUNSC_E2E_REQUIRE").as_deref() == Ok("1")
}

/// A live sandbox plus the metadata a test needs to attack it. `None` from
/// [`TestSandbox::setup`] means "skipped" (guards not satisfied).
struct TestSandbox {
    backend: Arc<GvisorBackend>,
    runtime: OwnedTestRuntime,
    id: SandboxId,
    cleaned: bool,
    task_id: Uuid,
    hook: Arc<RecordingHook>,
    pids_limit: usize,
}

#[derive(Default)]
struct RecordingHook(Mutex<Vec<DeniedEgress>>);

impl RecordingHook {
    fn events(&self) -> Vec<DeniedEgress> {
        self.0.lock().expect("recording hook mutex").clone()
    }
}

impl FlagToHuman for RecordingHook {
    fn on_denied(&self, event: &DeniedEgress) {
        self.0
            .lock()
            .expect("recording hook mutex")
            .push(event.clone());
    }
}

struct LoopbackResolver;

#[async_trait::async_trait]
impl HostResolver for LoopbackResolver {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)])
    }
}

struct BoundedDockerRunner;

impl BoundedDockerRunner {
    async fn run_command(
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> std::io::Result<Output> {
        let mut command = tokio::process::Command::new(program);
        command
            .args(args)
            .envs(env.iter().map(|(name, value)| (name, value)));
        command.kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(8), command.output())
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Docker command timed out")
            })?
    }
}

#[async_trait::async_trait]
impl CommandRunner for BoundedDockerRunner {
    async fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
        Self::run_command(program, args, &[]).await
    }

    async fn run_with_env(
        &self,
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> std::io::Result<Output> {
        Self::run_command(program, args, env).await
    }
}

struct OwnedTestRuntime(Option<tokio::runtime::Runtime>);

impl OwnedTestRuntime {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to create owned sandbox test runtime");
        Self(Some(runtime))
    }
}

impl Deref for OwnedTestRuntime {
    type Target = tokio::runtime::Runtime;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("owned test runtime already shut down")
    }
}

impl Drop for OwnedTestRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            // Safe inside an async test: never block waiting for worker threads.
            runtime.shutdown_background();
        }
    }
}

impl TestSandbox {
    /// Returns `Some` only on a provisioned runsc host with the opt-in set;
    /// otherwise prints a SKIP line and returns `None` so the test passes.
    async fn setup(test_name: &str) -> Option<Self> {
        Self::setup_with(test_name, &[ALLOWED_HOST], None).await
    }

    async fn setup_with(
        test_name: &str,
        allowed_hosts: &[&str],
        host_resolver: Option<Arc<dyn HostResolver>>,
    ) -> Option<Self> {
        if !require_runsc_e2e() && std::env::var("REEDE_RUNSC_E2E").as_deref() != Ok("1") {
            eprintln!("SKIP {test_name}: set REEDE_RUNSC_E2E=1 on a runsc host to run");
            return None;
        }
        let docker = std::env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string());
        if which_on_path(&docker).is_none() {
            if require_runsc_e2e() {
                panic!("{test_name}: REEDE_RUNSC_E2E_REQUIRE=1 but docker client `{docker}` is missing");
            }
            eprintln!("SKIP {test_name}: docker client `{docker}` not found");
            return None;
        }

        // Force proxy-gated mode with an explicit allowlist regardless of ambient
        // egress settings. The optional resolver is a controlled test seam; normal
        // setup leaves the production Tokio resolver in place.
        let hook = Arc::new(RecordingHook::default());
        let config = ProxyGatedConfig {
            flag_to_human: hook.clone(),
            host_resolver,
            ..ProxyGatedConfig::default()
        };
        let backend = Arc::new(
            GvisorBackend::from_env()
                .with_egress_mode(EgressMode::ProxyGated(config))
                .with_command_runner(Arc::new(BoundedDockerRunner)),
        );
        let runtime = OwnedTestRuntime::new();

        // One sandbox per task; the sandbox handle is derived from the task id.
        let task = Task::new(Uuid::new_v4(), "tenant-adv", "spec-adv", 50.0);
        let task_id = task.id;
        let policy = policy_allowing(allowed_hosts);
        let pids_limit = std::env::var("REEDE_SANDBOX_PIDS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(256);

        let create_backend = Arc::clone(&backend);
        let id = match runtime
            .spawn(async move { create_backend.create_sandbox(&task, &policy).await })
            .await
            .expect("owned sandbox runtime stopped during creation")
        {
            Ok(id) => id,
            Err(e) => {
                panic!("{test_name}: create_sandbox failed on runsc host: {e}");
            }
        };
        Some(Self {
            backend,
            runtime,
            id,
            cleaned: false,
            task_id,
            hook,
            pids_limit,
        })
    }

    /// Run `sh -c <script>` inside the sandbox, returning stdout+stderr merged.
    async fn exec_output(&self, script: &str) -> Result<String, ReedeError> {
        let cmd = SandboxCommand {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), script.to_string()],
            env: vec![],
            current_dir: None,
        };
        let backend = Arc::clone(&self.backend);
        let id = self.id;
        let out = self
            .runtime
            .spawn(async move { backend.exec_in_sandbox(id, cmd).await })
            .await
            .expect("owned sandbox runtime stopped during exec")?;
        let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.push_str(&String::from_utf8_lossy(&out.stderr));
        Ok(s)
    }

    async fn exec(&self, script: &str) -> String {
        self.exec_output(script)
            .await
            .expect("exec_in_sandbox should run on a provisioned host")
    }

    async fn teardown(mut self) -> Result<(), ReedeError> {
        self.destroy().await
    }

    async fn destroy(&mut self) -> Result<(), ReedeError> {
        let backend = Arc::clone(&self.backend);
        let id = self.id;
        self.runtime
            .spawn(async move { backend.destroy_sandbox(id).await })
            .await
            .expect("owned sandbox runtime stopped during destroy")?;
        self.cleaned = true;
        Ok(())
    }
}

// An assertion panic or cancelled test future must not leave its named container
// or internal network behind. The backend's proxy task runs on this owned runtime
// too, so teardown can abort and await it while this thread waits for the bounded
// result; the runtime that must make progress is never blocked by Drop.
impl Drop for TestSandbox {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        let backend = Arc::clone(&self.backend);
        let id = self.id;
        let (finished, result) = mpsc::sync_channel(1);
        self.runtime.spawn(async move {
            let result = backend
                .destroy_sandbox(id)
                .await
                .map_err(|error| error.to_string());
            let _ = finished.send(result);
        });
        match result.recv_timeout(Duration::from_secs(20)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("best-effort sandbox cleanup failed: {error}"),
            Err(error) => {
                eprintln!("best-effort sandbox cleanup did not finish within 20 seconds: {error}")
            }
        }
    }
}

fn policy_allowing(hosts: &[&str]) -> DerivedPolicy {
    DerivedPolicy {
        agent_id: "spec-adv".to_string(),
        budget_ceiling_eur: 50.0,
        hitl_above_credits: 10,
        egress_allowlist: hosts.iter().map(|h| h.to_string()).collect(),
        resource_grants: vec![],
    }
}

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

#[tokio::test]
async fn owned_test_runtime_can_be_dropped_inside_async_context() {
    let runtime = OwnedTestRuntime::new();
    runtime
        .spawn(async { 7usize })
        .await
        .expect("owned test runtime task failed");
    drop(runtime);
}

// ---------------------------------------------------------------------------
// (a) Raw socket to an off-allowlist IP — no route off the internal network.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_a_raw_socket_off_allowlist_ip_is_blocked() {
    let Some(ctx) = TestSandbox::setup("adversarial_a_raw_socket").await else {
        return;
    };
    // 1.1.1.1:80 is off-allowlist and reached by raw TCP (no proxy, no DNS).
    let out = ctx
        .exec("nc -w3 -z 1.1.1.1 80 && echo OPEN || echo BLOCKED")
        .await;
    ctx.teardown().await.expect("sandbox teardown failed");
    assert!(
        out.contains("BLOCKED") && !out.contains("OPEN"),
        "raw socket to off-allowlist IP must be blocked, got: {out}"
    );
}

// ---------------------------------------------------------------------------
// (b) Direct-IP HTTP connect bypassing DNS.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_b_direct_ip_bypassing_dns_is_blocked() {
    let Some(ctx) = TestSandbox::setup("adversarial_b_direct_ip").await else {
        return;
    };
    // Connect straight to an IP literal — no name lookup involved. Either the
    // internal network drops it or the proxy denies the IP; both are BLOCKED.
    let out = ctx
        .exec("wget -T3 -q -O- http://1.1.1.1/ && echo OPEN || echo BLOCKED")
        .await;
    ctx.teardown().await.expect("sandbox teardown failed");
    assert!(
        out.contains("BLOCKED") && !out.contains("OPEN"),
        "direct-IP connect bypassing DNS must be blocked, got: {out}"
    );
}

// ---------------------------------------------------------------------------
// (c) DNS query for an off-allowlist host — the Reede DNS filter REFUSES it.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_c_dns_off_allowlist_is_blocked() {
    let Some(ctx) = TestSandbox::setup("adversarial_c_dns").await else {
        return;
    };
    let out = ctx
        .exec("nslookup tracker.evil.example 2>&1 && echo RESOLVED || echo BLOCKED")
        .await;
    ctx.teardown().await.expect("sandbox teardown failed");
    assert!(
        out.contains("BLOCKED") && !out.contains("RESOLVED"),
        "DNS for an off-allowlist host must be refused, got: {out}"
    );
}

// ---------------------------------------------------------------------------
// (d) Namespace-escape attempt — no CAP_SYS_ADMIN under cap-drop ALL + runsc.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_d_namespace_escape_is_blocked() {
    let Some(ctx) = TestSandbox::setup("adversarial_d_namespace_escape").await else {
        return;
    };
    // Try to create a fresh network namespace (needs CAP_SYS_ADMIN) and to mount
    // proc — both require capabilities that were dropped.
    let out = ctx
        .exec("( unshare -n true || mount -t proc proc /mnt ) && echo ESCAPED || echo BLOCKED")
        .await;
    ctx.teardown().await.expect("sandbox teardown failed");
    assert!(
        out.contains("BLOCKED") && !out.contains("ESCAPED"),
        "namespace escape must be blocked, got: {out}"
    );
}

// ---------------------------------------------------------------------------
// (e) Route-rewrite attempt — no CAP_NET_ADMIN, cannot add/replace routes.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn adversarial_e_route_rewrite_is_blocked() {
    let Some(ctx) = TestSandbox::setup("adversarial_e_route_rewrite").await else {
        return;
    };
    // Attempt to install a new default route (would need CAP_NET_ADMIN).
    let out = ctx
        .exec("ip route add default via 10.255.255.1 && echo REWROTE || echo BLOCKED")
        .await;
    ctx.teardown().await.expect("sandbox teardown failed");
    assert!(
        out.contains("BLOCKED") && !out.contains("REWROTE"),
        "route-rewrite must be blocked, got: {out}"
    );
}

// ---------------------------------------------------------------------------
// (+) Positive: an ALLOWLISTED destination is reachable through the proxy.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn positive_allowlisted_destination_is_reachable() {
    let Some(ctx) = TestSandbox::setup("positive_allowlisted").await else {
        return;
    };
    // example.com is on the allowlist: DNS is forwarded, CONNECT is permitted.
    // busybox wget honours HTTP(S)_PROXY, which the sandbox env sets to the
    // gateway proxy.
    let script = format!(
        "wget -T8 -q -O- https://{ALLOWED_HOST}/ >/dev/null && echo REACHABLE || echo UNREACHABLE"
    );
    let out = ctx.exec(&script).await;
    ctx.teardown().await.expect("sandbox teardown failed");
    assert!(
        out.contains("REACHABLE") && !out.contains("UNREACHABLE"),
        "allowlisted destination must be reachable through the proxy, got: {out}"
    );
}

// (g) A host-only allowlist entry does not permit SSH on port 22.
#[tokio::test]
async fn adversarial_g_host_only_allowlist_refuses_port_22() {
    let Some(ctx) = TestSandbox::setup("adversarial_g_port_22").await else {
        return;
    };
    let out = ctx
        .exec_output(&format!(
            r#"proxy=${{HTTPS_PROXY#http://}}; proxy_host=${{proxy%:*}}; proxy_port=${{proxy##*:}}; printf 'CONNECT {ALLOWED_HOST}:22 HTTP/1.1\r\nHost: {ALLOWED_HOST}:22\r\n\r\n' | nc -w3 "$proxy_host" "$proxy_port""#
        ))
        .await;
    let events = ctx.hook.events();
    let task_id = ctx.task_id;
    ctx.teardown().await.expect("sandbox teardown failed");
    let out = out.expect("sandbox exec must return output after cleanup");
    assert!(
        out.contains("403 Forbidden"),
        "proxy must reject host-only port 22: {out}"
    );
    assert!(
        events.iter().any(|event| {
            event.task_id == Some(task_id)
                && event.destination == format!("{ALLOWED_HOST}:22")
                && event.reason == "destination not on egress allowlist"
        }),
        "proxy policy denial must reach the task-associated hook: {events:?}"
    );
}

// (f) An allowlisted host resolving to a denied local address is refused by CONNECT.
#[tokio::test]
async fn adversarial_f_allowlisted_host_resolving_to_loopback_is_denied_by_proxy() {
    let Some(ctx) = TestSandbox::setup_with(
        "adversarial_f_denied_resolution",
        &[ALLOWED_HOST],
        Some(Arc::new(LoopbackResolver)),
    )
    .await
    else {
        return;
    };
    let out = ctx
        .exec_output(&format!(
            r#"proxy=${{HTTPS_PROXY#http://}}; proxy_host=${{proxy%:*}}; proxy_port=${{proxy##*:}}; printf 'CONNECT {ALLOWED_HOST}:443 HTTP/1.1\r\nHost: {ALLOWED_HOST}:443\r\n\r\n' | nc -w3 "$proxy_host" "$proxy_port""#
        ))
        .await;
    let events = ctx.hook.events();
    let task_id = ctx.task_id;
    ctx.teardown().await.expect("sandbox teardown failed");
    let out = out.expect("sandbox exec must return output after cleanup");
    assert!(
        out.contains("403 Forbidden"),
        "proxy must reject loopback resolution: {out}"
    );
    assert!(
        events.iter().any(|event| {
            event.task_id == Some(task_id)
                && event.destination == format!("{ALLOWED_HOST}:443")
                && event.reason == "resolved to a denied address"
        }),
        "resolved-address denial must reach the task-associated hook: {events:?}"
    );
}

// (h) Host-process variables never appear in the sandbox's init environment.
#[tokio::test]
async fn adversarial_h_host_environment_is_not_inherited() {
    const NAME: &str = "REEDE_F4C1_SYNTHETIC_HOST_ONLY";
    struct RestoreEnv(Option<std::ffi::OsString>);
    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            if let Some(value) = &self.0 {
                std::env::set_var("REEDE_F4C1_SYNTHETIC_HOST_ONLY", value);
            } else {
                std::env::remove_var("REEDE_F4C1_SYNTHETIC_HOST_ONLY");
            }
        }
    }
    let _restore = RestoreEnv(std::env::var_os(NAME));
    std::env::set_var(NAME, "synthetic-marker");
    let Some(ctx) = TestSandbox::setup("adversarial_h_host_environment").await else {
        return;
    };
    let out = ctx
        .exec_output(r#"if ! tr '\000' '\n' </proc/1/environ >/tmp/reede-proc1-environ; then echo PROC_UNREADABLE; exit 2; fi; if grep -q '^REEDE_F4C1_SYNTHETIC_HOST_ONLY=' /tmp/reede-proc1-environ; then echo LEAKED; else echo CLEAN; fi; echo PROC_READABLE"#)
        .await;
    ctx.teardown().await.expect("sandbox teardown failed");
    let out = out.expect("sandbox exec must return output after cleanup");
    assert!(
        out.contains("PROC_READABLE") && !out.contains("PROC_UNREADABLE"),
        "the test must read /proc/1/environ successfully: {out}"
    );
    assert!(
        out.contains("CLEAN") && !out.contains("LEAKED"),
        "container init inherited a host-only variable: {out}"
    );
}

// (i) A pids-limited fork attempt stops before its bound and the host test task remains responsive.
#[tokio::test]
async fn adversarial_i_fork_bomb_hits_pids_limit_without_stalling_host() {
    let Some(ctx) = TestSandbox::setup("adversarial_i_pids_limit").await else {
        return;
    };
    let pid_bound = ctx.pids_limit;
    let script = format!(
        r#"pids=''; n=0; while [ $n -lt {pid_bound} ]; do sleep 20 >/dev/null 2>&1 & p=$!; if ! kill -0 $p 2>/dev/null; then break; fi; pids="$pids $p"; n=$((n+1)); done; echo spawned=$n; for p in $pids; do kill $p 2>/dev/null || true; done; wait 2>/dev/null || true"#
    );
    let mut heartbeat = tokio::time::interval(Duration::from_millis(50));
    heartbeat.tick().await;
    let started = Instant::now();
    let execution = async {
        tokio::time::timeout(Duration::from_secs(30), async {
            let command = ctx.exec_output(&script);
            tokio::pin!(command);
            let mut ticks = 0usize;
            loop {
                tokio::select! {
                    output = &mut command => break (output, ticks),
                    _ = heartbeat.tick() => ticks += 1,
                }
            }
        })
        .await
    };
    let result = execution.await;
    ctx.teardown().await.expect("sandbox teardown failed");
    let elapsed = started.elapsed();
    let (out, heartbeat_ticks) =
        result.expect("bounded fork attempt must complete within 30 seconds");
    let out = out.expect("sandbox exec must return output");
    let spawned = out
        .split("spawned=")
        .nth(1)
        .and_then(|n| n.split_whitespace().next())
        .and_then(|n| n.parse::<usize>().ok());
    assert!(
        elapsed < Duration::from_secs(30),
        "host deadline exceeded: {elapsed:?}"
    );
    assert!(heartbeat_ticks > 0, "host Tokio heartbeat did not advance");
    assert!(
        spawned.is_some_and(|n| n < pid_bound),
        "process creation did not stop below configured pids limit {pid_bound}: {out}"
    );
}

// (j) The root filesystem is immutable; the explicitly bounded /tmp remains
// writable, but its noexec mount prevents running a file written there.
#[tokio::test]
async fn adversarial_j_filesystem_root_is_read_only_and_tmp_is_noexec() {
    let Some(ctx) = TestSandbox::setup("adversarial_j_filesystem").await else {
        return;
    };
    let out = ctx
        .exec(r#"root_opts=$(awk '$2=="/" {print $4; exit}' /proc/mounts); case ",$root_opts," in *,ro,*) echo ROOT_MOUNT_READONLY;; *) echo ROOT_MOUNT_WRITABLE;; esac; if printf 'probe' >/etc/reede-root-write-probe 2>/dev/null; then echo ROOT_WRITE_ALLOWED; else echo ROOT_WRITE_DENIED; fi; if printf '#!/bin/sh\necho TMP_EXECUTED\n' >/tmp/reede-noexec-probe && test "$(cat /tmp/reede-noexec-probe)" = "$(printf '#!/bin/sh\necho TMP_EXECUTED\n')" && chmod +x /tmp/reede-noexec-probe; then echo TMP_WRITE_READ_OK; (/tmp/reede-noexec-probe >/dev/null 2>&1 && echo TMP_EXEC_ALLOWED || echo TMP_NOEXEC); else echo TMP_WRITE_READ_FAILED; fi"#)
        .await;
    ctx.teardown().await.expect("sandbox teardown failed");
    assert!(
        out.contains("ROOT_MOUNT_READONLY") && !out.contains("ROOT_MOUNT_WRITABLE"),
        "effective root mount is not read-only: {out}"
    );
    assert!(
        out.contains("ROOT_WRITE_DENIED") && !out.contains("ROOT_WRITE_ALLOWED"),
        "root filesystem write was not denied: {out}"
    );
    assert!(
        out.contains("TMP_WRITE_READ_OK") && !out.contains("TMP_WRITE_READ_FAILED"),
        "writable /tmp did not retain and read a file: {out}"
    );
    assert!(
        out.contains("TMP_NOEXEC") && !out.contains("TMP_EXEC_ALLOWED"),
        "execution from writable /tmp was not denied: {out}"
    );
}

// (k) Observe a live child, then require bounded backend destruction and prove
// the owning container is absent. The proof is container removal; this does not
// claim that a particular cgroup counter or kernel termination mechanism fired.
#[tokio::test]
async fn adversarial_k_destroy_removes_container_with_observed_running_child() {
    let Some(mut ctx) = TestSandbox::setup("adversarial_k_destroy_running_child").await else {
        return;
    };
    let out = ctx
        .exec(r#"sleep 120 >/dev/null 2>&1 & child=$!; sleep 0.1; if kill -0 "$child" 2>/dev/null; then echo CHILD_RUNNING; else echo CHILD_NOT_RUNNING; fi"#)
        .await;
    assert!(
        out.contains("CHILD_RUNNING") && !out.contains("CHILD_NOT_RUNNING"),
        "did not observe the child running before destroy: {out}"
    );

    let container_name = format!("reede-sbx-{}", ctx.id.0);
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(18), ctx.destroy())
        .await
        .expect("backend destroy exceeded 18 seconds")
        .expect("backend destroy failed");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(18),
        "backend destroy exceeded its bound: {elapsed:?}"
    );

    let docker = std::env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string());
    let mut inspect = tokio::process::Command::new(docker);
    inspect
        .arg("inspect")
        .arg("--format")
        .arg("{{.State.Running}}")
        .arg(&container_name);
    inspect
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let inspected = tokio::time::timeout(Duration::from_secs(5), inspect.output())
        .await
        .expect("docker inspect exceeded 5 seconds")
        .expect("failed to run docker inspect");
    let inspect_error = String::from_utf8_lossy(&inspected.stderr);
    assert!(
        !inspected.status.success()
            && inspect_error
                .to_ascii_lowercase()
                .contains("no such object"),
        "expected Docker to confirm container absence, status={} stderr={inspect_error}",
        inspected.status
    );

    let network_name = format!("reede-egr-{}", ctx.id.0);
    let mut network_inspect = tokio::process::Command::new(
        std::env::var("DOCKER_BIN").unwrap_or_else(|_| "docker".to_string()),
    );
    network_inspect
        .arg("network")
        .arg("inspect")
        .arg(&network_name)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let inspected_network = tokio::time::timeout(Duration::from_secs(5), network_inspect.output())
        .await
        .expect("docker network inspect exceeded 5 seconds")
        .expect("failed to run docker network inspect");
    let network_error = String::from_utf8_lossy(&inspected_network.stderr);
    assert!(
        !inspected_network.status.success()
            && network_error
                .to_ascii_lowercase()
                .contains("no such network"),
        "expected Docker to confirm network absence, status={} stderr={network_error}",
        inspected_network.status
    );
}
