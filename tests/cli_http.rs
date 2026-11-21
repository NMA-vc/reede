//! The real `reede` binary's `kill`, `tasks` and `lease` verbs against a stub
//! lifecycle API on 127.0.0.1 (a `std::net::TcpListener`, one scripted answer per request).
//!
//! The answers are the shapes F4b-2's host-runs router returns: `Json(task)`, `Json(Vec<Task>)`,
//! `Json(Vec<CredentialLease>)`, plain-text errors.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use chrono::Utc;
use reede::lease::{CredentialLease, LeaseId};
use reede::task::{Task, TaskState};
use serde_json::Value;
use uuid::Uuid;

const TOKEN: &str = "stub-test-credential-0002";

/// One request as the stub received it.
#[derive(Debug, Clone)]
struct Received {
    method: String,
    target: String,
    authorization: Option<String>,
}

/// A stub HTTP server answering requests, in order, with a script of `(status, body)`.
/// Requests beyond the script get 500.
struct Stub {
    port: u16,
    received: Arc<Mutex<Vec<Received>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn handle(stream: TcpStream, answer: (u16, String, &'static str)) -> Option<Received> {
    stream.set_nonblocking(false).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut authorization = None;
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim().to_owned();
            match name.to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value),
                "content-length" => content_length = value.parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;

    let (status, text, content_type) = answer;
    let mut stream = stream;
    let response = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
        reason(status),
        text.len()
    );
    stream.write_all(response.as_bytes()).ok()?;
    stream.flush().ok()?;
    Some(Received {
        method,
        target,
        authorization,
    })
}

impl Stub {
    fn start(script: Vec<(u16, String)>) -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let received = Arc::clone(&received);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut script = script.into_iter();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let answer = match script.next() {
                                Some((status, body)) => {
                                    let json = serde_json::from_str::<Value>(&body).is_ok();
                                    (
                                        status,
                                        body,
                                        if json {
                                            "application/json"
                                        } else {
                                            "text/plain; charset=utf-8"
                                        },
                                    )
                                }
                                None => (
                                    500,
                                    "unscripted request".to_owned(),
                                    "text/plain; charset=utf-8",
                                ),
                            };
                            if let Some(r) = handle(stream, answer) {
                                received.lock().unwrap().push(r);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Stub {
            port,
            received,
            stop,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Stop the server and return what it received.
    fn finish(mut self) -> Vec<Received> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        let received = self.received.lock().unwrap().clone();
        received
    }
}

/// The binary with a clean lifecycle environment, plus `env`.
fn reede(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reede"));
    command
        .args(args)
        .env_remove("REEDE_API_URL")
        .env_remove("REEDE_TOKEN");
    // The stub listens on loopback; a runner's proxy settings must not reroute it.
    for proxy in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        command.env_remove(proxy);
    }
    command.env("NO_PROXY", "*");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn configured(stub: &Stub) -> Vec<(&'static str, String)> {
    vec![
        ("REEDE_API_URL", stub.url()),
        ("REEDE_TOKEN", TOKEN.to_owned()),
    ]
}

fn run(stub: &Stub, args: &[&str]) -> Output {
    let env = configured(stub);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    reede(args, &env)
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_no_token(output: &Output) {
    assert!(
        !stdout(output).contains(TOKEN),
        "token in stdout: {}",
        stdout(output)
    );
    assert!(
        !stderr(output).contains(TOKEN),
        "token in stderr: {}",
        stderr(output)
    );
}

/// Every request carried the bearer credential in its header, and never in its target.
fn assert_bearer(received: &[Received]) {
    assert!(!received.is_empty());
    for r in received {
        assert_eq!(
            r.authorization.as_deref(),
            Some(format!("Bearer {TOKEN}").as_str()),
            "{r:?}"
        );
        assert!(!r.target.contains(TOKEN), "token in the URL: {r:?}");
    }
}

fn task(state: TaskState, reserved: i64, cancel_requested: bool) -> Task {
    let mut t = Task::new(Uuid::new_v4(), "tenant-a", "factcheck-agent", 1.0);
    t.state = state;
    t.budget_envelope.reserved_credits = reserved;
    if cancel_requested {
        t.cancel_requested_at = Some(Utc::now());
    }
    t
}

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

#[test]
fn kill_posts_the_cancel_with_the_bearer_and_exits_0_on_202() {
    let mut t = task(TaskState::Running, 100, true);
    let id = t.id;
    let stub = Stub::start(vec![(202, json(&t))]);
    let out = run(&stub, &["kill", &id.to_string()]);
    let received = stub.finish();

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].method, "POST");
    assert_eq!(
        received[0].target,
        format!("/api/v1/reede/tasks/{id}/cancel")
    );
    assert_bearer(&received);
    assert_no_token(&out);
    assert!(stdout(&out).contains(&format!("cancel requested for task {id}: now Running")));
    assert!(stdout(&out).contains("100 reserved metering credits (tokens)"));

    // A run that ended between the request and the read-back is reported as ended.
    t.state = TaskState::Killed;
    let stub = Stub::start(vec![(202, json(&t))]);
    let out = run(&stub, &["kill", &id.to_string()]);
    stub.finish();
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("the run has ended: Killed"));
}

#[test]
fn kill_maps_every_refusal_to_its_exit_code_with_the_text_on_stderr() {
    let id = Uuid::new_v4();
    for (status, body, code, says) in [
        (
            409,
            "the run has ended: Succeeded",
            1,
            "the run has already ended (409)",
        ),
        (404, "task not found", 1, "not found for this tenant (404)"),
        (501, "not here", 1, "does not implement this (501)"),
        (401, "", 2, "the credential was refused (401)"),
        (403, "tenant suspended", 2, "may not do this (403)"),
        (500, "internal error", 3, "the server failed"),
        (503, "", 3, "the server failed"),
    ] {
        let stub = Stub::start(vec![(status, body.to_owned())]);
        let out = run(&stub, &["kill", &id.to_string()]);
        let received = stub.finish();
        assert_eq!(
            out.status.code(),
            Some(code),
            "HTTP {status}: {}",
            stderr(&out)
        );
        assert_eq!(received.len(), 1, "HTTP {status}");
        assert_eq!(received[0].method, "POST");
        assert_bearer(&received);
        assert_no_token(&out);
        assert!(stdout(&out).is_empty(), "HTTP {status}: {}", stdout(&out));
        let err = stderr(&out);
        assert!(err.contains(says), "HTTP {status}: {err}");
        assert!(
            err.contains(&format!("[HTTP {status}]")),
            "HTTP {status}: {err}"
        );
        assert!(err.contains(body), "HTTP {status}: {err}");
    }
}

#[test]
fn kill_wait_polls_the_task_until_it_ends() {
    let running = task(TaskState::Running, 100, true);
    let id = running.id;
    let mut killed = running.clone();
    killed.state = TaskState::Killed;
    killed.finished_at = Some(Utc::now());
    let stub = Stub::start(vec![(202, json(&running)), (200, json(&killed))]);
    let out = run(&stub, &["kill", &id.to_string(), "--wait"]);
    let received = stub.finish();

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    let calls: Vec<(String, String)> = received
        .iter()
        .map(|r| (r.method.clone(), r.target.clone()))
        .collect();
    assert_eq!(
        calls,
        vec![
            (
                "POST".to_owned(),
                format!("/api/v1/reede/tasks/{id}/cancel")
            ),
            ("GET".to_owned(), format!("/api/v1/reede/tasks/{id}")),
        ]
    );
    assert_bearer(&received);
    assert_no_token(&out);
    assert!(
        stdout(&out).ends_with(&format!("task {id} ended: Killed\n")),
        "{}",
        stdout(&out)
    );
}

#[test]
fn a_missing_configuration_exits_2_and_sends_nothing() {
    let id = Uuid::new_v4().to_string();
    let stub = Stub::start(vec![]);
    let url = stub.url();
    let no_url = reede(&["kill", &id], &[("REEDE_TOKEN", TOKEN)]);
    let no_token = reede(&["kill", &id], &[("REEDE_API_URL", &url)]);
    let empty_token = reede(&["tasks"], &[("REEDE_API_URL", &url), ("REEDE_TOKEN", "")]);
    let bad_id = reede(
        &["kill", "not-a-uuid"],
        &[("REEDE_API_URL", &url), ("REEDE_TOKEN", TOKEN)],
    );
    let url_with_credential = reede(
        &["tasks"],
        &[
            (
                "REEDE_API_URL",
                &format!("http://u:{TOKEN}@127.0.0.1:{}", stub.port),
            ),
            ("REEDE_TOKEN", TOKEN),
        ],
    );
    let received = stub.finish();

    assert!(received.is_empty(), "the stub was called: {received:?}");
    for (name, out) in [
        ("no url", &no_url),
        ("no token", &no_token),
        ("empty token", &empty_token),
        ("bad id", &bad_id),
        ("url with a credential", &url_with_credential),
    ] {
        assert_eq!(out.status.code(), Some(2), "{name}: {}", stderr(out));
        assert_no_token(out);
    }
    assert!(stderr(&no_url).contains("REEDE_API_URL is not set"));
    assert!(stderr(&no_token).contains("REEDE_TOKEN is not set"));
}

#[test]
fn flags_override_the_environment_and_are_never_echoed() {
    let t = task(TaskState::Running, 5, false);
    let stub = Stub::start(vec![(200, json(&vec![t.clone()]))]);
    let url = stub.url();
    let out = reede(
        &["tasks", "--api-url", &url, "--token", TOKEN],
        &[
            ("REEDE_API_URL", "http://127.0.0.1:1"),
            ("REEDE_TOKEN", "the-env-token"),
        ],
    );
    let received = stub.finish();
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_bearer(&received);
    assert_no_token(&out);
}

#[test]
fn a_server_echoing_the_credential_is_redacted() {
    let id = Uuid::new_v4();
    let stub = Stub::start(vec![(500, format!("bad bearer {TOKEN} for you"))]);
    let out = run(&stub, &["lease", &id.to_string()]);
    stub.finish();
    assert_eq!(out.status.code(), Some(3));
    assert_no_token(&out);
    assert!(
        stderr(&out).contains("bad bearer [redacted] for you"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_unreachable_server_exits_3() {
    // Bind, then drop: the port is closed for the binary's connect.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let out = reede(
        &["tasks"],
        &[
            ("REEDE_API_URL", &format!("http://127.0.0.1:{port}")),
            ("REEDE_TOKEN", TOKEN),
        ],
    );
    assert_eq!(out.status.code(), Some(3), "stderr: {}", stderr(&out));
    assert!(stderr(&out).contains("cannot reach the lifecycle API"));
    assert_no_token(&out);
}

#[test]
fn tasks_lists_one_line_per_task_with_the_limit() {
    let live = task(TaskState::Running, 100, false);
    let cancelled = task(TaskState::Killed, 40, true);
    let stub = Stub::start(vec![(200, json(&vec![live.clone(), cancelled.clone()]))]);
    let out = run(&stub, &["tasks", "--limit", "7"]);
    let received = stub.finish();

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].method, "GET");
    assert_eq!(received[0].target, "/api/v1/reede/tasks?limit=7");
    assert_bearer(&received);
    assert_no_token(&out);
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}");
    assert!(
        lines[0].starts_with(&format!("{}  Running  factcheck-agent  ", live.id)),
        "{}",
        lines[0]
    );
    assert!(
        lines[0].ends_with("reserved 100 metering credits (tokens)"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].starts_with(&format!("{}  Killed  ", cancelled.id)),
        "{}",
        lines[1]
    );
    assert!(
        lines[1].ends_with("reserved 40 metering credits (tokens)  cancel requested"),
        "{}",
        lines[1]
    );

    // Without --limit the server picks its default; an empty list prints nothing to stdout.
    let stub = Stub::start(vec![(200, "[]".to_owned())]);
    let out = run(&stub, &["tasks"]);
    let received = stub.finish();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(received[0].target, "/api/v1/reede/tasks");
    assert!(stdout(&out).is_empty());
}

#[test]
fn tasks_with_an_id_prints_the_task_as_json() {
    let t = task(TaskState::Running, 100, true);
    let served = serde_json::to_value(&t).unwrap();
    let stub = Stub::start(vec![(200, json(&t)), (404, "task not found".to_owned())]);
    let out = run(&stub, &["tasks", &t.id.to_string()]);
    let missing = run(&stub, &["tasks", &Uuid::new_v4().to_string()]);
    let received = stub.finish();

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(received[0].method, "GET");
    assert_eq!(received[0].target, format!("/api/v1/reede/tasks/{}", t.id));
    assert_bearer(&received);
    assert_no_token(&out);
    let printed: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(printed, served);
    assert_eq!(serde_json::from_value::<Task>(printed).unwrap(), t);
    assert!(stderr(&out).contains("metering credits (tokens)"));

    assert_eq!(missing.status.code(), Some(1));
    assert!(stderr(&missing).contains("not found for this tenant (404)"));
}

#[test]
fn lease_lists_every_lease_with_its_standing() {
    let task_id = Uuid::new_v4();
    let now = Utc::now();
    let lease = |secret_ref: &str, revoked: bool, expires_in_min: i64| CredentialLease {
        id: LeaseId(Uuid::new_v4()),
        task_id,
        secret_ref: secret_ref.to_owned(),
        issued_at: now - chrono::Duration::minutes(30),
        expires_at: now + chrono::Duration::minutes(expires_in_min),
        revoked,
    };
    let leases = vec![
        lease("mcp:gmail", false, -5),
        lease("mcp:drive", true, 10),
        lease("run", false, 10),
    ];
    let stub = Stub::start(vec![
        (200, json(&leases)),
        (404, "task not found".to_owned()),
        (200, "[]".to_owned()),
    ]);
    let out = run(&stub, &["lease", &task_id.to_string()]);
    let missing = run(&stub, &["lease", &Uuid::new_v4().to_string()]);
    let none = run(&stub, &["lease", &task_id.to_string()]);
    let received = stub.finish();

    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr(&out));
    assert_eq!(received[0].method, "GET");
    assert_eq!(
        received[0].target,
        format!("/api/v1/reede/tasks/{task_id}/leases")
    );
    assert_bearer(&received);
    assert_no_token(&out);
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    for (line, (l, standing)) in lines
        .iter()
        .zip(leases.iter().zip(["expired", "revoked", "live"]))
    {
        assert!(
            line.starts_with(&format!("{}  {}  issued ", l.id.0, l.secret_ref)),
            "{line}"
        );
        assert!(line.ends_with(&format!("  {standing}")), "{line}");
    }

    assert_eq!(missing.status.code(), Some(1));
    assert!(stderr(&missing).contains("not found for this tenant (404)"));
    assert_eq!(none.status.code(), Some(0));
    assert!(stdout(&none).is_empty());
    assert!(stderr(&none).contains("no leases for task"));
}

#[test]
fn policy_and_logs_are_honest_stubs() {
    let policy = reede(&["policy"], &[]);
    assert_eq!(policy.status.code(), Some(1));
    assert!(stderr(&policy).contains("NOT IMPLEMENTED: no per-run policy is stored"));
    let logs = reede(&["logs"], &[]);
    assert_eq!(logs.status.code(), Some(1));
    assert!(stderr(&logs).contains("NOT IMPLEMENTED: there is no log store"));
    let usage = reede(&[], &[]);
    for verb in [
        "reede tasks",
        "reede kill",
        "reede lease",
        "reede policy",
        "reede logs",
    ] {
        assert!(stdout(&usage).contains(verb), "{verb}");
    }
}
