//! Receipt tamper detection, end-to-end through the offline `reede-verify`
//! binary: a receipt produced by the real emission path verifies, and the same
//! receipt with one hashed field altered does not.
//!
//! this used to drive `TaskRunner::run_task`. With that wrapper
//! deleted the test drives the two surviving pieces it wrapped —
//! `task::execute_isolated_task` (sandbox lifecycle + task state machine) and
//! `receipt::emit_execution_receipt` (the single place a receipt is hashed,
//! signed and chained). It writes reede-v2: the eleven fields recomputed
//! independently below.

use reede::isolation::PassthroughBackend;
use reede::policy::DerivedPolicy;
use reede::receipt::{
    emit_execution_receipt, encode_fields_injective, InMemoryReceiptSigner, InMemoryReceiptStore,
};
use reede::task::{execute_isolated_task, InMemoryTaskStore, Task, TaskState};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_emitted_receipt_tamper_detection() {
    // End-to-end test: produce a receipt, verify it using the pre-built verify binary, tamper credits_spent, verify it fails.
    let task_store = InMemoryTaskStore::new();
    let isolation = PassthroughBackend;
    let signer = Arc::new(InMemoryReceiptSigner::generate_random());
    let receipt_store = InMemoryReceiptStore::new();

    let mut task = Task::new(Uuid::new_v4(), "tenant-tamper", "spec-1", 50.0);
    let policy = DerivedPolicy {
        agent_id: "agent-tamper".to_string(),
        budget_ceiling_eur: 50.0,
        hitl_above_credits: 10,
        egress_allowlist: vec![],
        resource_grants: vec![],
    };

    // The work really runs inside the sandbox lifecycle, so the receipt below
    // describes an executed task rather than a hand-built struct.
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
        10,   // credits_spent
        1000, // tokens_used
        50,   // reservation_credits
        task.subject_id.clone(),
    )
    .await
    .expect("receipt must be emitted");
    assert_eq!(receipt.sequence_no, 1, "first receipt for this tenant");

    // Verify hash was computed correctly from the fields
    let task_id_str = task.id.to_string();
    let timestamp_str = receipt
        .timestamp
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    // signer_key_id: the first 16 hex chars of SHA-256 over the Ed25519 public key.
    let key_id = hex::encode(Sha256::digest(signer.verifying_key().to_bytes()))[..16].to_string();
    assert_eq!(receipt.signer_key_id.as_deref(), Some(key_id.as_str()));
    let original_fields = vec![
        "tenant-tamper",
        task_id_str.as_str(),
        receipt.payload_summary.as_str(),
        "10",   // credits_spent
        "1000", // tokens_used
        "50",   // reservation_credits
        "",     // prev_hash (genesis)
        "1",    // sequence_no
        timestamp_str.as_str(),
        task.subject_id.as_deref().unwrap_or(""),
        key_id.as_str(),
    ];
    let original_bytes = encode_fields_injective(&original_fields);
    let expected_hash = hex::encode(Sha256::digest(&original_bytes));
    assert_eq!(receipt.content_hash, expected_hash);
    assert_eq!(receipt.format.as_deref(), Some("reede-v2"));

    // Serialize to JSON chain for reede-verify
    let pubkey_hex = hex::encode(signer.verifying_key().to_bytes());
    let chain_json = serde_json::to_string_pretty(&vec![&receipt]).unwrap();

    let tmp_dir = std::env::temp_dir();
    let valid_path = tmp_dir.join(format!("reede_tamper_valid_{}.json", task.id));
    std::fs::write(&valid_path, &chain_json).unwrap();

    // Use CARGO_BIN_EXE_verify directly (no cargo run subprocess, no lock contention)
    let verify_bin = env!("CARGO_BIN_EXE_verify");

    // Direction 1: unaltered receipt passes reede-verify
    let valid_out = std::process::Command::new(verify_bin)
        .args([
            "--chain",
            valid_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ])
        .output()
        .expect("Failed to execute verify binary");

    assert!(
        valid_out.status.success(),
        "reede-verify MUST exit 0 for unaltered receipt. stderr: {}",
        String::from_utf8_lossy(&valid_out.stderr)
    );
    let valid_stdout = String::from_utf8_lossy(&valid_out.stdout);
    assert!(valid_stdout.contains("HASH:       VERIFIED (1/1 links, reede-v2)"));

    // Direction 2: tamper credits_spent from 10 to 0 in the JSON
    let mut tampered: Vec<serde_json::Value> = serde_json::from_str(&chain_json).unwrap();
    tampered[0]["credits_spent"] = serde_json::json!(0);
    let tampered_json = serde_json::to_string_pretty(&tampered).unwrap();

    let tampered_path = tmp_dir.join(format!("reede_tamper_bad_{}.json", task.id));
    std::fs::write(&tampered_path, &tampered_json).unwrap();

    let tampered_out = std::process::Command::new(verify_bin)
        .args([
            "--chain",
            tampered_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ])
        .output()
        .expect("Failed to execute verify binary");

    assert!(
        !tampered_out.status.success(),
        "reede-verify MUST exit non-zero for tampered credits_spent. stdout: {}",
        String::from_utf8_lossy(&tampered_out.stdout)
    );
    let tampered_stderr = String::from_utf8_lossy(&tampered_out.stderr);
    assert!(
        tampered_stderr.contains("content_hash mismatch"),
        "Error must mention content_hash mismatch. stderr: {tampered_stderr}"
    );

    // Direction 3: re-date the receipt by a year. reede-v2 hashes the timestamp, so the
    // binary must reject it (audit finding 6; under v1 it could only print a caveat).
    let mut redated: Vec<serde_json::Value> = serde_json::from_str(&chain_json).unwrap();
    let earlier = receipt.timestamp - chrono::Duration::days(365);
    redated[0]["timestamp"] = serde_json::to_value(earlier).unwrap();
    let redated_path = tmp_dir.join(format!("reede_tamper_redated_{}.json", task.id));
    std::fs::write(
        &redated_path,
        serde_json::to_string_pretty(&redated).unwrap(),
    )
    .unwrap();
    let redated_out = std::process::Command::new(verify_bin)
        .args([
            "--chain",
            redated_path.to_str().unwrap(),
            "--pubkey",
            &pubkey_hex,
        ])
        .output()
        .expect("Failed to execute verify binary");
    let redated_stderr = String::from_utf8_lossy(&redated_out.stderr);
    assert!(
        !redated_out.status.success(),
        "a re-dated v2 receipt must not verify"
    );
    assert!(
        redated_stderr.contains("content_hash mismatch"),
        "{redated_stderr}"
    );

    // Cleanup
    let _ = std::fs::remove_file(&valid_path);
    let _ = std::fs::remove_file(&tampered_path);
    let _ = std::fs::remove_file(&redated_path);
}
