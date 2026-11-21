//! Both installed receipt commands must run the same offline verification.
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};

struct ChainFile(PathBuf);

impl ChainFile {
    fn new(chain: &Value) -> Self {
        let path = std::env::temp_dir().join(format!(
            "reede-verifier-parity-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, serde_json::to_vec(chain).unwrap()).unwrap();
        Self(path)
    }
}

impl Drop for ChainFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn run_both(args: &[&str]) -> Output {
    let standalone = Command::new(env!("CARGO_BIN_EXE_verify"))
        .args(args)
        .output()
        .unwrap();
    let alias = Command::new(env!("CARGO_BIN_EXE_reede"))
        .args(["receipt", "verify"])
        .args(args)
        .output()
        .unwrap();
    assert_eq!(standalone.status.code(), alias.status.code());
    assert_eq!(standalone.stdout, alias.stdout);
    assert_eq!(standalone.stderr, alias.stderr);
    standalone
}

#[test]
fn receipt_commands_share_signed_partial_and_rejected_verdicts() {
    let doc: Value =
        serde_json::from_str(include_str!("fixtures/reede-v1-writer-receipt.json")).unwrap();
    let key = doc["pubkey_hex"].as_str().unwrap();
    let receipt = doc["receipt"].clone();
    let file = ChainFile::new(&json!([receipt]));
    let path = file.0.to_str().unwrap();
    let signed = run_both(&["--chain", path, "--pubkey", key]);
    assert!(signed.status.success());
    let report = String::from_utf8(signed.stdout).unwrap();
    assert!(report.contains("SIGNATURES: VERIFIED (ed25519, 1 links)"));
    assert!(report.contains("HASH:       VERIFIED (1/1 links, reede-v1)"));
    assert!(report.contains("VERDICT:    SIGNED, NOT TIMESTAMPED"));

    let partial = run_both(&["--chain", path]);
    assert!(partial.status.success());
    let report = String::from_utf8(partial.stdout).unwrap();
    assert!(report.contains("SIGNATURES: NOT CHECKED (no --pubkey)"));
    assert!(report.contains("VERDICT:    NOT FULLY VERIFIED"));

    for field in ["credits_spent", "content_hash", "signature"] {
        let mut tampered = receipt.clone();
        tampered[field] = match field {
            "credits_spent" => json!(receipt[field].as_u64().unwrap() + 1),
            "content_hash" => json!("00".repeat(32)),
            "signature" => json!("00".repeat(64)),
            _ => unreachable!(),
        };
        let file = ChainFile::new(&json!([tampered]));
        let output = run_both(&["--chain", file.0.to_str().unwrap(), "--pubkey", key]);
        assert!(!output.status.success(), "accepted tampered {field}");
        assert!(String::from_utf8(output.stderr).unwrap().contains("FAIL:"));
    }
    let vector: Value =
        serde_json::from_str(include_str!("fixtures/reede-v1-vector.json")).unwrap();
    let other_key = vector["pubkey_hex"].as_str().unwrap();
    assert_ne!(key, other_key);
    assert!(!run_both(&["--chain", path, "--pubkey", other_key])
        .status
        .success());
    assert!(!run_both(&["--chain", path, "--pubkey", "invalid-hex"])
        .status
        .success());

    let mut unknown_format = receipt;
    unknown_format["format"] = json!("future-format");
    let file = ChainFile::new(&json!([unknown_format]));
    let output = run_both(&["--chain", file.0.to_str().unwrap(), "--pubkey", key]);
    assert!(output.status.success());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("HASH:       NOT RECOMPUTED"));
    assert!(report.contains("VERDICT:    NOT FULLY VERIFIED"));
}

#[test]
fn receipt_commands_share_empty_invalid_and_usage_results() {
    let empty = ChainFile::new(&json!([]));
    let output = run_both(&["--chain", empty.0.to_str().unwrap()]);
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("Nothing to verify"));
    let malformed = ChainFile::new(&json!({"not": "a receipt chain"}));
    assert!(!run_both(&["--chain", malformed.0.to_str().unwrap()])
        .status
        .success());
    let absent =
        std::env::temp_dir().join(format!("reede-missing-chain-{}.json", uuid::Uuid::new_v4()));
    assert!(!run_both(&["--chain", absent.to_str().unwrap()])
        .status
        .success());
    assert!(!run_both(&[]).status.success());
}

#[test]
fn strict_json_verification_requires_authentic_nonempty_known_chain() {
    let doc: Value = serde_json::from_str(include_str!("fixtures/reede-v1-vector.json")).unwrap();
    let key = doc["pubkey_hex"].as_str().unwrap();
    let file = ChainFile::new(&json!([doc["receipt"]]));
    let path = file.0.to_str().unwrap();
    let output = run_both(&[
        "--chain",
        path,
        "--pubkey",
        key,
        "--json",
        "--require-genesis",
        "--expected-count",
        "1",
        "--expected-head",
        doc["receipt"]["content_hash"].as_str().unwrap(),
    ]);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["authentic"], true);
    assert_eq!(report["completeness"], "verified_against_trusted_boundary");
    assert!(report["legally_qualified"].is_null());
    assert!(!run_both(&["--chain", path, "--json"]).status.success());
    assert!(!run_both(&[
        "--chain",
        path,
        "--pubkey",
        key,
        "--json",
        "--expected-count",
        "2"
    ])
    .status
    .success());
    let empty = ChainFile::new(&json!([]));
    assert!(!run_both(&[
        "--chain",
        empty.0.to_str().unwrap(),
        "--pubkey",
        key,
        "--strict"
    ])
    .status
    .success());
    let mut unknown = doc["receipt"].clone();
    unknown["format"] = json!("unknown");
    let file = ChainFile::new(&json!([unknown]));
    assert!(!run_both(&[
        "--chain",
        file.0.to_str().unwrap(),
        "--pubkey",
        key,
        "--json"
    ])
    .status
    .success());
}
