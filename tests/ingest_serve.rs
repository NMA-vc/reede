//! `reede serve` end to end: real sockets, real files, the real `reede` and `verify` binaries.

use prost::Message;
use reede::ingest::otlp::*;
use reede::ingest::{self, Ingest, Server};
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("reede-ingest-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn kv_int(key: &str, n: i64) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(Value::IntValue(n)),
        }),
    }
}

fn span(trace: u8, id: u8, name: &str, tokens: Option<(i64, i64)>) -> Span {
    let mut attributes = vec![KeyValue {
        key: "gen_ai.operation.name".into(),
        value: Some(AnyValue {
            value: Some(Value::StringValue("chat".into())),
        }),
    }];
    if let Some((i, o)) = tokens {
        attributes.push(kv_int("gen_ai.usage.input_tokens", i));
        attributes.push(kv_int("gen_ai.usage.output_tokens", o));
    }
    Span {
        trace_id: vec![trace; 16],
        span_id: vec![id; 8],
        name: name.into(),
        start_time_unix_nano: 1_700_000_000_000_000_000,
        end_time_unix_nano: 1_700_000_001_000_000_000,
        attributes,
        ..Default::default()
    }
}

fn request(spans: Vec<Span>) -> ExportTraceServiceRequest {
    ExportTraceServiceRequest {
        resource_spans: vec![ResourceSpans {
            resource: Some(Resource { attributes: vec![] }),
            scope_spans: vec![ScopeSpans {
                scope: Some(Scope {
                    name: "t".into(),
                    version: "1".into(),
                }),
                spans,
            }],
        }],
    }
}

fn three_spans() -> ExportTraceServiceRequest {
    request(vec![
        span(1, 1, "root", None),
        span(1, 2, "llm", Some((10, 5))),
        span(2, 3, "other trace", None),
    ])
}

async fn start(dir: &Path) -> std::net::SocketAddr {
    let ingest = Ingest::open(dir, "local").await.unwrap();
    let server = Server::bind("127.0.0.1:0".parse().unwrap(), false, ingest)
        .await
        .unwrap();
    let addr = server.local_addr();
    tokio::spawn(server.run());
    addr
}

/// Send one raw request; (status, body).
async fn post(
    addr: std::net::SocketAddr,
    path: &str,
    ctype: Option<&str>,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(c) = ctype {
        head += &format!("Content-Type: {c}\r\n");
    }
    head += "\r\n";
    let _ = s.write_all(head.as_bytes()).await;
    let _ = s.write_all(body).await;
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let body = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| raw[i + 4..].to_vec())
        .unwrap_or_default();
    (status, body)
}

const PB: &str = "application/x-protobuf";

fn verify_cli(dir: &Path) -> std::process::Output {
    let pubkey = std::fs::read_to_string(dir.join("pubkey.hex")).unwrap();
    Command::new(env!("CARGO_BIN_EXE_verify"))
        .args([
            "--chain",
            dir.join("chain.json").to_str().unwrap(),
            "--pubkey",
            pubkey.trim(),
        ])
        .output()
        .unwrap()
}

fn check_cli(dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_reede"))
        .args(["ingest", "check", "--out", dir.to_str().unwrap()])
        .output()
        .unwrap()
}

fn chain(dir: &Path) -> Vec<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(dir.join("chain.json")).unwrap()).unwrap()
}

#[tokio::test]
async fn protobuf_export_seals_three_receipts_that_verify() {
    let dir = tmp("pb");
    let addr = start(&dir).await;
    let (status, body) = post(addr, "/v1/traces", Some(PB), &three_spans().encode_to_vec()).await;
    assert_eq!((status, body.len()), (200, 0));

    let chain = chain(&dir);
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0]["format"], "reede-v2");
    assert_eq!(chain[1]["tokens_used"], 15);
    assert_eq!(chain[0]["tokens_used"], 0);
    let subject = chain[2]["subject_id"].as_str().unwrap();
    assert_eq!(
        subject,
        format!("reported:{}/{}", "02".repeat(16), "03".repeat(8))
    );
    assert_eq!(chain[0]["tenant_id"], "local");

    let v = verify_cli(&dir);
    assert!(v.status.success(), "{}", String::from_utf8_lossy(&v.stderr));
    let c = check_cli(&dir);
    assert!(c.status.success(), "{}", String::from_utf8_lossy(&c.stderr));
    assert!(String::from_utf8_lossy(&c.stdout).contains("not that it is true"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("signing.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn json_path_seals_and_hex_ids_roundtrip() {
    let dir = tmp("json");
    let addr = start(&dir).await;
    let body = serde_json::json!({"resourceSpans":[{"scopeSpans":[{"spans":[{
        "traceId":"0102030405060708090a0b0c0d0e0f10","spanId":"1112131415161718",
        "name":"j","startTimeUnixNano":"5","endTimeUnixNano":6,
        "attributes":[{"key":"gen_ai.usage.input_tokens","value":{"intValue":"7"}},
                      {"key":"gen_ai.usage.output_tokens","value":{"intValue":3}}]}]}]}]});
    let (status, resp) = post(
        addr,
        "/v1/traces",
        Some("application/json; charset=utf-8"),
        body.to_string().as_bytes(),
    )
    .await;
    assert_eq!((status, resp), (200, b"{}".to_vec()));
    let chain = chain(&dir);
    assert_eq!(chain[0]["tokens_used"], 10);
    assert_eq!(
        chain[0]["subject_id"],
        "reported:0102030405060708090a0b0c0d0e0f10/1112131415161718"
    );
    assert!(verify_cli(&dir).status.success());
    assert!(check_cli(&dir).status.success());
}

#[tokio::test]
async fn bad_requests_get_413_415_400_and_seal_nothing() {
    let dir = tmp("bad");
    let addr = start(&dir).await;
    // 413: the declared length alone is enough; the body is never read.
    let mut s = TcpStream::connect(addr).await.unwrap();
    let big = 8 * 1024 * 1024 + 1;
    s.write_all(
        format!("POST /v1/traces HTTP/1.1\r\nContent-Type: {PB}\r\nContent-Length: {big}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).await.unwrap();
    assert!(raw.starts_with("HTTP/1.1 413"), "{raw}");

    assert_eq!(
        post(addr, "/v1/traces", Some("text/plain"), b"x").await.0,
        415
    );
    assert_eq!(post(addr, "/v1/traces", None, b"x").await.0, 415);
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), b"\xff\xff\xff garbage")
            .await
            .0,
        400
    );
    assert_eq!(
        post(addr, "/v1/traces", Some("application/json"), b"{not json")
            .await
            .0,
        400
    );
    // A span with a zero-length trace id is malformed, not sealed.
    let bad = request(vec![Span {
        span_id: vec![1; 8],
        ..Default::default()
    }]);
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), &bad.encode_to_vec())
            .await
            .0,
        400
    );
    assert_eq!(post(addr, "/v1/other", Some(PB), b"").await.0, 404);
    assert!(!dir.join("chain.json").exists());
    // Clean input still passes afterwards (the server survived all of the above).
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), &three_spans().encode_to_vec())
            .await
            .0,
        200
    );
}

async fn sealed_dir(name: &str) -> PathBuf {
    let dir = tmp(name);
    let addr = start(&dir).await;
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), &three_spans().encode_to_vec())
            .await
            .0,
        200
    );
    assert!(check_cli(&dir).status.success());
    dir
}

fn fails(out: std::process::Output, needle: &str) {
    assert!(!out.status.success(), "expected failure");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(needle), "stderr {err:?} lacks {needle:?}");
}

#[tokio::test]
async fn tampering_a_receipt_field_fails_verify_and_check() {
    let dir = sealed_dir("t-receipt").await;
    let mut c = chain(&dir);
    c[1]["tokens_used"] = 99999.into();
    std::fs::write(dir.join("chain.json"), serde_json::to_vec(&c).unwrap()).unwrap();
    assert!(!verify_cli(&dir).status.success());
    fails(check_cli(&dir), "FAIL");
}

#[tokio::test]
async fn tampering_a_span_file_fails_check() {
    let dir = sealed_dir("t-span").await;
    let p = dir.join("spans/2.json");
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("\"llm\"", "\"llm2\"");
    std::fs::write(&p, text).unwrap();
    // The chain itself still verifies; only the span recomputation catches it.
    assert!(verify_cli(&dir).status.success());
    fails(check_cli(&dir), "seq 2: span file does not match");
}

#[tokio::test]
async fn dropping_a_receipt_fails() {
    let dir = sealed_dir("t-drop").await;
    let mut c = chain(&dir);
    c.remove(1);
    std::fs::write(dir.join("chain.json"), serde_json::to_vec(&c).unwrap()).unwrap();
    assert!(!verify_cli(&dir).status.success());
    fails(check_cli(&dir), "FAIL");
    // Dropping the head receipt leaves a valid chain prefix; the orphan span file gives it away.
    let dir = sealed_dir("t-drop-last").await;
    let mut c = chain(&dir);
    c.pop();
    std::fs::write(dir.join("chain.json"), serde_json::to_vec(&c).unwrap()).unwrap();
    fails(check_cli(&dir), "has no receipt");
}

#[tokio::test]
async fn restart_continues_the_chain_and_refuses_a_broken_one() {
    let dir = sealed_dir("restart").await;
    let addr = start(&dir).await; // a second server on the same directory = a restart
    let more = request(vec![span(3, 9, "after restart", None)]);
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), &more.encode_to_vec())
            .await
            .0,
        200
    );
    let c = chain(&dir);
    assert_eq!(c.len(), 4);
    assert_eq!(c[3]["sequence_no"], 4);
    assert_eq!(c[3]["prev_hash"], c[2]["content_hash"]);
    assert!(verify_cli(&dir).status.success());
    assert!(check_cli(&dir).status.success());

    let mut broken = c.clone();
    broken[2]["credits_spent"] = 5.into();
    std::fs::write(dir.join("chain.json"), serde_json::to_vec(&broken).unwrap()).unwrap();
    let err = Ingest::open(&dir, "local")
        .await
        .err()
        .expect("must refuse");
    assert!(err.contains("refusing to append"), "{err}");
    // A different tenant on an existing chain is refused too.
    std::fs::write(dir.join("chain.json"), serde_json::to_vec(&c).unwrap()).unwrap();
    assert!(Ingest::open(&dir, "someone-else").await.is_err());
}

#[tokio::test]
async fn non_loopback_needs_the_flag() {
    let dir = tmp("remote");
    let ingest = Ingest::open(&dir, "local").await.unwrap();
    let err = Server::bind("0.0.0.0:0".parse().unwrap(), false, ingest)
        .await
        .err()
        .unwrap();
    assert!(err.contains("--allow-remote"));
    let ingest = Ingest::open(&dir, "local").await.unwrap();
    assert!(Server::bind("0.0.0.0:0".parse().unwrap(), true, ingest)
        .await
        .is_ok());

    // And through the real binary.
    let out = Command::new(env!("CARGO_BIN_EXE_reede"))
        .args([
            "serve",
            "--listen",
            "0.0.0.0:0",
            "--out",
            dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    fails(out, "--allow-remote");
}

#[test]
fn summary_is_sha256_of_sorted_compact_json() {
    let v: serde_json::Value =
        serde_json::from_str(r#"{"b":[1,{"z":"ä","a":null}],"a":"x"}"#).unwrap();
    assert_eq!(
        ingest::canonical_json(&v),
        "{\"a\":\"x\",\"b\":[1,{\"a\":null,\"z\":\"\u{e4}\"}]}"
    );
    assert_eq!(ingest::span_summary(&v).len(), 64);
}

/// Send raw bytes, return the status line's code (0 when the server just closed).
async fn raw(addr: std::net::SocketAddr, bytes: &[u8]) -> u16 {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let _ = s.write_all(bytes).await;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    String::from_utf8_lossy(&out)
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn chunked(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "POST /v1/traces HTTP/1.1\r\nContent-Type: {PB}\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .into_bytes();
    for part in body.chunks(7) {
        out.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

#[tokio::test]
async fn chunked_bodies_work_and_hostile_framing_is_refused() {
    let dir = tmp("framing");
    let addr = start(&dir).await;
    let head = format!("POST /v1/traces HTTP/1.1\r\nContent-Type: {PB}\r\n");

    // Clean chunked upload seals.
    assert_eq!(
        raw(addr, &chunked(&three_spans().encode_to_vec())).await,
        200
    );
    assert_eq!(chain(&dir).len(), 3);

    // Chunk sizes that would overflow the cap arithmetic: refused, no panic.
    for size in ["ffffffffffffffff", "7fffffffffffffff", "800001"] {
        let req = format!("{head}Transfer-Encoding: chunked\r\n\r\n{size}\r\n");
        assert_eq!(raw(addr, req.as_bytes()).await, 413, "{size}");
    }
    // A size that does not even fit usize.
    let req = format!("{head}Transfer-Encoding: chunked\r\n\r\nfffffffffffffffff\r\n");
    assert_eq!(raw(addr, req.as_bytes()).await, 400);
    // Chunk data not followed by CRLF.
    let req = format!("{head}Transfer-Encoding: chunked\r\n\r\n3\r\nabcXY0\r\n\r\n");
    assert_eq!(raw(addr, req.as_bytes()).await, 400);
    // An endless chunk-size line.
    let mut req = format!("{head}Transfer-Encoding: chunked\r\n\r\n").into_bytes();
    req.extend(std::iter::repeat_n(b'a', 4096));
    assert_eq!(raw(addr, &req).await, 400);
    // Content-Length together with Transfer-Encoding.
    let req = format!("{head}Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert_eq!(raw(addr, req.as_bytes()).await, 400);
    // Duplicate Content-Length, and whitespace before the header colon.
    let req = format!("{head}Content-Length: 0\r\nContent-Length: 0\r\n\r\n");
    assert_eq!(raw(addr, req.as_bytes()).await, 400);
    let req = format!("{head}Content-Length : 0\r\n\r\n");
    assert_eq!(raw(addr, req.as_bytes()).await, 400);
    // Oversized headers, and too many headers.
    let req = format!(
        "{head}X-Big: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(20_000)
    );
    assert_eq!(raw(addr, req.as_bytes()).await, 431);
    let many: String = (0..70).map(|i| format!("X-{i}: v\r\n")).collect();
    let req = format!("{head}{many}Content-Length: 0\r\n\r\n");
    assert_eq!(raw(addr, req.as_bytes()).await, 431);
    // Nothing hostile sealed anything, and a clean request still works afterwards.
    assert_eq!(chain(&dir).len(), 3);
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), &three_spans().encode_to_vec())
            .await
            .0,
        200
    );
    assert_eq!(chain(&dir).len(), 6);
}

#[tokio::test]
async fn restart_refuses_when_the_chain_is_missing_or_behind_the_spans() {
    let dir = sealed_dir("restart-missing").await;
    let saved = std::fs::read(dir.join("chain.json")).unwrap();
    std::fs::remove_file(dir.join("chain.json")).unwrap();
    let err = Ingest::open(&dir, "local")
        .await
        .err()
        .expect("must refuse");
    assert!(err.contains("chain.json is missing or behind"), "{err}");
    assert!(dir.join("spans/1.json").exists());
    // Behind: a chain cut to one receipt while three span files exist.
    let mut c: Vec<serde_json::Value> = serde_json::from_slice(&saved).unwrap();
    c.truncate(1);
    std::fs::write(dir.join("chain.json"), serde_json::to_vec(&c).unwrap()).unwrap();
    assert!(Ingest::open(&dir, "local").await.is_err());
    // Restored intact: opens again.
    std::fs::write(dir.join("chain.json"), saved).unwrap();
    assert!(Ingest::open(&dir, "local").await.is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn output_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let base = tmp("perms").join("fresh-out"); // created by the ingest itself
    let addr = start(&base).await;
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), &three_spans().encode_to_vec())
            .await
            .0,
        200
    );
    assert_eq!(mode(base.clone()), 0o700);
    assert_eq!(mode(base.join("spans")), 0o700);
    for f in ["chain.json", "spans/1.json", "pubkey.hex", "signing.key"] {
        assert_eq!(mode(base.join(f)), 0o600, "{f}");
    }
}

#[tokio::test]
async fn non_finite_doubles_seal_distinctly() {
    let dir = tmp("nonfinite");
    let addr = start(&dir).await;
    let body = |v: &str| {
        serde_json::json!({"resourceSpans":[{"scopeSpans":[{"spans":[{
            "traceId":"0102030405060708090a0b0c0d0e0f10","spanId":"1112131415161718","name":"d",
            "attributes":[{"key":"x","value":{"doubleValue": v}}]}]}]}]})
        .to_string()
    };
    // Three spans identical except for the non-finite value.
    for v in ["NaN", "Infinity", "-Infinity"] {
        let (status, _) = post(
            addr,
            "/v1/traces",
            Some("application/json"),
            body(v).as_bytes(),
        )
        .await;
        assert_eq!(status, 200, "{v}");
    }
    let c = chain(&dir);
    let sums: std::collections::HashSet<_> = c
        .iter()
        .map(|r| r["payload_summary"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        sums.len(),
        3,
        "NaN, Infinity and -Infinity must not share a summary"
    );
    let stored = std::fs::read_to_string(dir.join("spans/2.json")).unwrap();
    assert!(stored.contains("\"Infinity\""), "{stored}");
    // A protobuf NaN round-trips through the same encoding.
    let nan = request(vec![Span {
        trace_id: vec![1; 16],
        span_id: vec![1; 8],
        attributes: vec![KeyValue {
            key: "x".into(),
            value: Some(AnyValue {
                value: Some(Value::DoubleValue(f64::NAN)),
            }),
        }],
        ..Default::default()
    }]);
    assert_eq!(
        post(addr, "/v1/traces", Some(PB), &nan.encode_to_vec())
            .await
            .0,
        200
    );
    assert!(std::fs::read_to_string(dir.join("spans/4.json"))
        .unwrap()
        .contains("\"NaN\""));
    assert!(check_cli(&dir).status.success());
}

#[tokio::test]
async fn check_can_pin_the_public_key() {
    let dir = sealed_dir("pin").await;
    let good = std::fs::read_to_string(dir.join("pubkey.hex")).unwrap();
    let run = |key: &str| {
        Command::new(env!("CARGO_BIN_EXE_reede"))
            .args([
                "ingest",
                "check",
                "--out",
                dir.to_str().unwrap(),
                "--pubkey",
                key,
            ])
            .output()
            .unwrap()
    };
    assert!(run(good.trim()).status.success());
    // A different key (as after re-signing a directory and swapping pubkey.hex): the pin catches it.
    let other = reede::receipt::InMemoryReceiptSigner::generate_random();
    fails(run(&hex::encode(other.verifying_key().to_bytes())), "FAIL");
    fails(run("not-hex"), "--pubkey");
}
