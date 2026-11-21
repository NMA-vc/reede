//! S5 — two-tier receipt verification, end-to-end through the offline
//! `reede-verify` binary.
//!
//! Tier 1 (authenticity, fail-closed): content-hash integrity + Ed25519 signature.
//! Tier 2 (timestamp qualification, fail-open): a signed-but-not-timestamped receipt
//! verifies as "SIGNED, NOT TIMESTAMPED" and is never presented as fully qualified;
//! only an authentic + RFC-3161-validated chain is "FULLY QUALIFIED" (H8).
//!
//! Also exercises the O5 shared test vector: a third-party recomputation (inline,
//! not calling reede code) reproduces the committed content_hash, and the binary
//! verifies the committed signature.

use reede::isolation::PassthroughBackend;
use reede::policy::DerivedPolicy;
use reede::receipt::{
    emit_execution_receipt, ExecutionReceipt, InMemoryReceiptSigner, InMemoryReceiptStore,
};
use reede::task::{execute_isolated_task, InMemoryTaskStore, Task, TaskState};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Produce a genuine, signed reede-v1 receipt with no TSA token (the fail-open
/// pending state the platform emits today).
///
/// this used to go through `TaskRunner::run_task`. With that
/// wrapper deleted it drives the two surviving pieces it wrapped —
/// `task::execute_isolated_task` for the sandbox lifecycle and task state
/// machine, then `receipt::emit_execution_receipt`, which is the single place a
/// reede-v1 receipt is hashed, signed and chained. Both paths hash the same
/// seven fields in the same order (`recompute_content_hash_reede_v1`), so the
/// receipt the verifier sees is byte-for-byte what it saw before.
async fn produce_genuine_receipt(signer: Arc<InMemoryReceiptSigner>) -> (Uuid, ExecutionReceipt) {
    let task_store = InMemoryTaskStore::new();
    let isolation = PassthroughBackend;
    let receipt_store = InMemoryReceiptStore::new();

    let mut task = Task::new(Uuid::new_v4(), "tenant-two-tier", "spec-1", 50.0);
    let policy = DerivedPolicy {
        agent_id: "agent-two-tier".to_string(),
        budget_ceiling_eur: 50.0,
        hitl_above_credits: 10,
        egress_allowlist: vec![],
        resource_grants: vec![],
    };

    let out = execute_isolated_task(&mut task, &policy, &isolation, &task_store, || Ok("out"))
        .await
        .expect("isolated task must succeed");
    assert_eq!(out, "out");
    assert_eq!(task.state, TaskState::Succeeded);

    let receipt = emit_execution_receipt(
        signer.as_ref(),
        &receipt_store,
        task.id,
        &task.tenant_id,
        format!("Task {} completed successfully", task.id),
        10,
        1000,
        50,
        task.subject_id.clone(),
    )
    .await
    .expect("receipt must be emitted");
    (task.id, receipt)
}

fn write_chain(receipt: &ExecutionReceipt, name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("reede_two_tier_{name}_{}.json", Uuid::new_v4()));
    std::fs::write(&path, serde_json::to_string_pretty(&vec![receipt]).unwrap()).unwrap();
    path
}

// ---------------------------------------------------------------------------
// O5 — shared third-party test vector
// ---------------------------------------------------------------------------

/// A verifier reimplemented from the wire-format doc (here: an inline recompute
/// that does NOT call `reede::receipt`) reproduces the committed content_hash, and
/// the `reede-verify` binary verifies the committed signature. This is the O5 gate:
/// a party who has not read the Rust agrees with us on a shared vector.
#[test]
fn shared_vector_third_party_recompute_and_binary_verify() {
    let fixture_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/reede-v1-vector.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fixture_path).unwrap()).unwrap();

    let expected = doc["expected_content_hash"].as_str().unwrap();
    let pubkey_hex = doc["pubkey_hex"].as_str().unwrap();
    let receipt = &doc["receipt"];

    // Independent recomputation of the reede-v1 injective encoding, straight from
    // the wire-format doc. Intentionally does not touch any reede function.
    let credits = receipt["credits_spent"].as_i64().unwrap().to_string();
    let tokens = receipt["tokens_used"].as_u64().unwrap().to_string();
    let reservation = receipt["reservation_credits"].as_i64().unwrap().to_string();
    let prev = receipt["prev_hash"].as_str().unwrap_or("");
    let fields = [
        receipt["tenant_id"].as_str().unwrap(),
        receipt["task_id"].as_str().unwrap(),
        receipt["payload_summary"].as_str().unwrap(),
        credits.as_str(),
        tokens.as_str(),
        reservation.as_str(),
        prev,
    ];
    let mut canonical = Vec::new();
    for f in fields {
        canonical.extend_from_slice(format!("{:x}:", f.len()).as_bytes());
        canonical.extend_from_slice(f.as_bytes());
    }
    let recomputed = hex::encode(Sha256::digest(&canonical));

    assert_eq!(
        recomputed, expected,
        "third-party recompute must reproduce the committed content_hash"
    );
    assert_eq!(
        recomputed,
        receipt["content_hash"].as_str().unwrap(),
        "committed receipt content_hash must match the vector"
    );

    // The binary agrees end-to-end: hash recomputes, signature verifies, and the
    // pending vector is reported SIGNED, NOT TIMESTAMPED.
    let receipt_typed: ExecutionReceipt = serde_json::from_value(receipt.clone()).unwrap();
    let chain_path = write_chain(&receipt_typed, "vector");
    let out = Command::new(env!("CARGO_BIN_EXE_verify"))
        .args([
            "--chain",
            chain_path.to_str().unwrap(),
            "--pubkey",
            pubkey_hex,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _ = std::fs::remove_file(&chain_path);

    assert!(
        out.status.success(),
        "vector must verify. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("HASH:       VERIFIED (1/1 links, reede-v1)"),
        "{stdout}"
    );
    assert!(stdout.contains("SIGNATURES: VERIFIED"), "{stdout}");
    assert!(
        stdout.contains("VERDICT:    SIGNED, NOT TIMESTAMPED"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("FULLY QUALIFIED"),
        "a pending vector must not read as fully qualified: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// H8 Tier 2 — pending is visibly distinct from fully qualified
// ---------------------------------------------------------------------------

/// A genuine receipt with the TSA never reached verifies (Tier 1 passes) and the
/// binary states plainly it is not timestamped, and NEVER "FULLY QUALIFIED".
#[tokio::test]
async fn binary_pending_receipt_reports_signed_not_timestamped() {
    let signer = Arc::new(InMemoryReceiptSigner::generate_random());
    let pubkey_hex = hex::encode(signer.verifying_key().to_bytes());
    let (_id, receipt) = produce_genuine_receipt(signer.clone()).await;
    assert!(
        receipt.tsa_token.is_none(),
        "the emission path yields a pending (no-TSA) receipt"
    );

    let chain_path = write_chain(&receipt, "pending");
    let out = Command::new(env!("CARGO_BIN_EXE_verify"))
        .args([
            "--chain",
            chain_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _ = std::fs::remove_file(&chain_path);

    assert!(
        out.status.success(),
        "a genuine pending receipt must still verify (fail-open). stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("TIMESTAMP:  ABSENT"), "{stdout}");
    assert!(
        stdout.contains("VERDICT:    SIGNED, NOT TIMESTAMPED"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("FULLY QUALIFIED"),
        "pending must never read as fully qualified: {stdout}"
    );
}

/// A tampered body is rejected by Tier 1 even though the timestamp tier is fail-open
/// — authenticity failure is never masked by the pending path.
#[tokio::test]
async fn binary_tampered_pending_receipt_is_rejected() {
    let signer = Arc::new(InMemoryReceiptSigner::generate_random());
    let pubkey_hex = hex::encode(signer.verifying_key().to_bytes());
    let (_id, receipt) = produce_genuine_receipt(signer.clone()).await;

    let chain_path = write_chain(&receipt, "tamper");
    // Mutate a hashed field in the serialized JSON.
    let mut v: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(&chain_path).unwrap()).unwrap();
    v[0]["credits_spent"] = serde_json::json!(0);
    std::fs::write(&chain_path, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_verify"))
        .args([
            "--chain",
            chain_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&chain_path);
    assert!(
        !out.status.success(),
        "tampered receipt must be rejected by Tier 1"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("content_hash mismatch"));
}

// ---------------------------------------------------------------------------
// H8 Tier 2 — a real RFC 3161 timestamp reads as FULLY QUALIFIED
// ---------------------------------------------------------------------------

/// Build a real, locally-issued RFC 3161 timestamp token over `content_hash`, plus
/// the CA that signs it. Returns `(token_base64, cafile_path)` or `None` if the
/// local openssl toolchain cannot produce one (test then skips — never hangs).
fn make_rfc3161_token(content_hash: &str, dir: &Path) -> Option<(String, PathBuf)> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    fn ok(dir: &Path, args: &[&str]) -> bool {
        Command::new("openssl")
            .current_dir(dir)
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    let dir_s = dir.to_str()?;
    let cnf = dir.join("tsa.cnf");
    // `default_policy` is an arbitrary test TSA policy OID. Keep it to 3 arcs
    // (e.g. `1.2.3`): a 4+-component dotted OID reads as an IPv4 literal and
    // trips the infra IP-literal guardrail (false positive).
    std::fs::write(
        &cnf,
        format!(
            "[ tsa ]\n\
             default_tsa = tsa_config1\n\
             [ tsa_config1 ]\n\
             serial = {dir_s}/tsa_serial\n\
             crypto_device = builtin\n\
             signer_cert = {dir_s}/tsa.crt\n\
             certs = {dir_s}/ca.crt\n\
             signer_key = {dir_s}/tsa.key\n\
             signer_digest = sha256\n\
             default_policy = 1.2.3\n\
             digests = sha256\n\
             accuracy = secs:1\n\
             clock_precision_digits = 0\n\
             ordering = yes\n\
             tsa_name = yes\n\
             ess_cert_id_chain = no\n\
             ess_cert_id_alg = sha256\n\
             [ v3_tsa ]\n\
             basicConstraints = critical,CA:false\n\
             keyUsage = critical,digitalSignature\n\
             extendedKeyUsage = critical,timeStamping\n"
        ),
    )
    .ok()?;
    std::fs::write(dir.join("tsa_serial"), "01\n").ok()?;

    if !ok(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "1",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=reede-test-ca",
        ],
    ) {
        return None;
    }
    if !ok(
        dir,
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "tsa.key",
            "-out",
            "tsa.csr",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=reede-test-tsa",
        ],
    ) {
        return None;
    }
    if !ok(
        dir,
        &[
            "x509",
            "-req",
            "-in",
            "tsa.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-out",
            "tsa.crt",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            "tsa.cnf",
            "-extensions",
            "v3_tsa",
        ],
    ) {
        return None;
    }
    if !ok(
        dir,
        &[
            "ts",
            "-query",
            "-digest",
            content_hash,
            "-sha256",
            "-cert",
            "-out",
            "req.tsq",
        ],
    ) {
        return None;
    }
    if !ok(
        dir,
        &[
            "ts",
            "-reply",
            "-config",
            "tsa.cnf",
            "-queryfile",
            "req.tsq",
            "-token_out",
            "-out",
            "token.tk",
        ],
    ) {
        return None;
    }

    let token_bytes = std::fs::read(dir.join("token.tk")).ok()?;
    if token_bytes.is_empty() {
        return None;
    }
    Some((STANDARD.encode(&token_bytes), dir.join("ca.crt")))
}

/// A genuine receipt carrying a validated RFC 3161 token reads as FULLY QUALIFIED,
/// which is visibly different from the pending case above (H8 DONE-WHEN).
#[tokio::test]
async fn binary_timestamped_receipt_reports_fully_qualified() {
    let signer = Arc::new(InMemoryReceiptSigner::generate_random());
    let pubkey_hex = hex::encode(signer.verifying_key().to_bytes());
    let (_id, mut receipt) = produce_genuine_receipt(signer.clone()).await;

    let workdir = std::env::temp_dir().join(format!("reede_tsa_gen_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&workdir).unwrap();

    let made = make_rfc3161_token(&receipt.content_hash, &workdir);
    let (token_b64, cafile) = match made {
        Some(v) => v,
        None => {
            eprintln!("SKIP: local openssl could not issue an RFC 3161 token; timestamped-path assertion skipped");
            let _ = std::fs::remove_dir_all(&workdir);
            return;
        }
    };

    receipt.tsa_token = Some(token_b64); // does not affect content_hash (not a hashed field)
    let chain_path = write_chain(&receipt, "timestamped");
    let out = Command::new(env!("CARGO_BIN_EXE_verify"))
        .args([
            "--chain",
            chain_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
            "--cafile",
            cafile.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_file(&chain_path);
    let _ = std::fs::remove_dir_all(&workdir);

    assert!(
        out.status.success(),
        "a timestamped receipt must verify. stderr: {stderr}\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("TIMESTAMP:  RFC 3161 SIGNATURE OK"),
        "expected validated timestamp. stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("VERDICT:    FULLY QUALIFIED"),
        "expected fully qualified verdict. stdout: {stdout}"
    );
    // The two states are visibly different: this run says FULLY QUALIFIED, the
    // pending run says SIGNED, NOT TIMESTAMPED.
    assert!(!stdout.contains("SIGNED, NOT TIMESTAMPED"), "{stdout}");
}
