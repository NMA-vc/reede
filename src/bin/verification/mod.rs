use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reede::receipt::{
    recompute_content_hash, verify_chain, verify_chain_from_genesis, ExecutionReceipt,
    REEDE_V1_FORMAT,
};
use std::env;
use std::fs;

mod anchor_cli;
#[allow(unused_imports)] // the `verify` binary has no anchor verb
pub use anchor_cli::run as run_anchor;

const VERIFY_HELP: &str = "\
Offline receipt chain verification
Usage:
  verify --chain <receipts.json> [--pubkey <hex>] [--cafile <ca.pem>] [--segment]
         [--strict | --json] [--expected-head <hash>] [--expected-tenant <id>]
         [--expected-count <n>] [--require-genesis]

Options:
  --chain <file>           Receipt chain JSON file
  --pubkey <hex>           Ed25519 public key (required for strict verification)
  --cafile <file>          CA certificate for timestamp token inspection
  --segment                Accept a chain that does not start at seq 1 (reported as a segment)
  --strict                 Require authenticated strict verification
  --json                   Strict verification with JSON report output
  --expected-head <hash>   Require this chain head (implies --strict)
  --expected-tenant <id>   Require this tenant (implies --strict)
  --expected-count <n>     Require this receipt count (implies --strict)
  --require-genesis        Require a genesis receipt (implies --strict)
  -h, --help               Show this help
  -V, --version            Show version";

pub fn print_help(program: &str) {
    println!(
        "{}",
        VERIFY_HELP.replacen("  verify --chain", &format!("  {program} --chain"), 1)
    );
}

pub fn run(args: &[String]) -> i32 {
    if args.len() == 2 {
        match args[1].as_str() {
            "--help" | "-h" => {
                print_help("verify");
                return 0;
            }
            "--version" | "-V" => {
                println!("verify {}", env!("CARGO_PKG_VERSION"));
                return 0;
            }
            _ => {}
        }
    }
    if args.len() < 3 {
        eprintln!("Usage: verify --chain <receipts.json> [--pubkey <hex>] [--cafile <ca.pem>] [--segment] [--strict | --json] [--expected-head <hash>] [--expected-tenant <id>] [--expected-count <n>] [--require-genesis]");
        return 1;
    }

    let mut chain_path = None;
    let mut pubkey_hex = None;
    let mut cafile_path = None;
    let mut strict = false;
    let mut json = false;
    let mut expected_head = None;
    let mut expected_tenant = None;
    let mut expected_count = None;
    let mut require_genesis = false;
    let mut allow_segment = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--chain" if i + 1 < args.len() => {
                chain_path = Some(&args[i + 1]);
                i += 1;
            }
            "--pubkey" if i + 1 < args.len() => {
                pubkey_hex = Some(&args[i + 1]);
                i += 1;
            }
            "--segment" => allow_segment = true,
            "--cafile" if i + 1 < args.len() => {
                cafile_path = Some(&args[i + 1]);
                i += 1;
            }
            "--strict" => strict = true,
            "--json" => {
                json = true;
                strict = true;
            }
            "--require-genesis" => {
                require_genesis = true;
                strict = true;
            }
            "--expected-head" if i + 1 < args.len() => {
                expected_head = Some(args[i + 1].as_str());
                strict = true;
                i += 1;
            }
            "--expected-tenant" if i + 1 < args.len() => {
                expected_tenant = Some(args[i + 1].as_str());
                strict = true;
                i += 1;
            }
            "--expected-count" if i + 1 < args.len() => {
                match args[i + 1].parse::<usize>() {
                    Ok(count) => expected_count = Some(count),
                    Err(_) => {
                        eprintln!("invalid expected count");
                        return 1;
                    }
                }
                strict = true;
                i += 1;
            }
            _ => {
                eprintln!("unknown or incomplete verifier option");
                return 1;
            }
        }
        i += 1;
    }

    let path = match chain_path {
        Some(p) => p,
        None => {
            eprintln!("Error: Missing --chain argument");
            return 1;
        }
    };

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading file '{path}': {e}");
            return 1;
        }
    };

    let chain: Vec<ExecutionReceipt> = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error parsing JSON receipt chain: {e}");
            return 1;
        }
    };

    if strict {
        let result = (|| -> Result<_, String> {
            if cafile_path.is_some() {
                return Err("strict JSON verification does not validate timestamp tokens; use the inspection report separately".into());
            }
            let raw_key = pubkey_hex.ok_or("strict verification requires --pubkey")?;
            let bytes = hex::decode(raw_key).map_err(|_| "invalid public key hex")?;
            let key = VerifyingKey::try_from(bytes.as_slice()).map_err(|_| "invalid public key")?;
            reede::verification::verify_export(
                &chain,
                &key,
                &reede::verification::VerificationPolicy {
                    expected_tenant,
                    expected_head,
                    expected_count,
                    require_genesis,
                },
            )
            .map_err(|error| error.to_string())
        })();
        return match result {
            Ok(report) => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&report).expect("serializable report")
                    );
                } else {
                    println!(
                        "VERIFIED: {} signed receipts; completeness: {}; timestamp: {}",
                        report.receipt_count, report.completeness, report.timestamp
                    );
                }
                0
            }
            Err(error) => {
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"schema":"reede-verification-v1", "authentic":false, "error":error})
                    );
                } else {
                    eprintln!("FAIL: {error}");
                }
                1
            }
        };
    }

    if chain.is_empty() {
        println!("Receipt chain is empty. Nothing to verify.");
        return 0;
    }

    match verify_chain_report(
        &chain,
        pubkey_hex.map(|s| s.as_str()),
        cafile_path.map(|s| s.as_str()),
        allow_segment,
    ) {
        Ok(report) => {
            print!("{report}");
            0
        }
        Err(failure) => {
            eprintln!("{failure}");
            1
        }
    }
}

/// The whole offline verification of one exported chain, as the lines the binary
/// prints. `Err` carries the `FAIL:`/`Error:` line for a chain that is rejected
/// (Tier 1, fail-closed: tenant, sequence contiguity, linkage, signature,
/// content-hash recompute, or a TSA token that does not validate against a supplied
/// CA). The CHAIN line names the head's `sequence_no` and `prev_hash`: a head that
/// links to an earlier receipt is reported as a SEGMENT, never as a full chain, so
/// receipts cut from the start are visible. Unless `allow_segment`, a chain whose
/// head is not seq 1 is rejected outright. Pure over its inputs apart from
/// shelling out to `openssl ts -verify` for TSA tokens; no network.
fn verify_chain_report(
    chain: &[ExecutionReceipt],
    pubkey_hex: Option<&str>,
    cafile_path: Option<&str>,
    allow_segment: bool,
) -> Result<String, String> {
    // 1. Verify tenant, sequence contiguity, uniqueness and hash linkage. Without
    // --segment the file must also start at seq 1, so a cut at the start fails.
    let structural = if allow_segment {
        verify_chain(chain, None)
    } else {
        verify_chain_from_genesis(chain, None)
    };
    if let Err(e) = structural {
        return Err(format!("FAIL: Receipt chain verification failed: {e}"));
    }

    // 2. Verify Ed25519 signatures if pubkey provided
    if let Some(pk_hex) = pubkey_hex {
        let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Error parsing pubkey hex: {e}"))?;
        let verifying_key = VerifyingKey::try_from(pk_bytes.as_slice())
            .map_err(|e| format!("Invalid Ed25519 public key: {e}"))?;

        for r in chain {
            let sig_bytes = hex::decode(&r.signature)
                .map_err(|_| format!("FAIL: Invalid signature hex for seq {}", r.sequence_no))?;
            let sig_array: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| format!("FAIL: Signature not 64 bytes for seq {}", r.sequence_no))?;
            let sig = Signature::from_bytes(&sig_array);
            if verifying_key
                .verify(r.content_hash.as_bytes(), &sig)
                .is_err()
            {
                return Err(format!(
                    "FAIL: Signature verification failed for seq {}",
                    r.sequence_no
                ));
            }
        }
    }

    // 3. Recompute content_hash for receipts with known format markers
    let mut hash_verified_count = 0;
    let mut hash_not_recomputed_count = 0;
    // reede-v1 links whose sequence_no, timestamp and subject_id are outside the hash.
    let mut v1_count = 0;
    let mut formats: Vec<&str> = Vec::new();

    for r in chain {
        match recompute_content_hash(r) {
            Some(recomputed) => {
                let format = r.format.as_deref().unwrap_or_default();
                if recomputed != r.content_hash {
                    return Err(format!(
                        "FAIL: content_hash mismatch for seq {} (format {}): stored {} != recomputed {}",
                        r.sequence_no, format, r.content_hash, recomputed
                    ));
                }
                hash_verified_count += 1;
                if format == REEDE_V1_FORMAT {
                    v1_count += 1;
                }
                if !formats.contains(&format) {
                    formats.push(format);
                }
            }
            None => {
                hash_not_recomputed_count += 1;
                tracing::info!(
                    "Seq {}: content_hash not recomputed (format {:?})",
                    r.sequence_no,
                    r.format
                );
            }
        }
    }

    // 4. Evaluate TSA timestamp tokens
    let mut verified_tsa_count = 0;
    let mut tsa_present_count = 0;

    for r in chain {
        if let Some(ref tok_b64) = r.tsa_token {
            tsa_present_count += 1;
            match verify_tsa_token_standalone(tok_b64, &r.content_hash, cafile_path) {
                Ok(true) => {
                    verified_tsa_count += 1;
                }
                Ok(false) => {
                    if cafile_path.is_some() {
                        return Err(format!(
                            "FAIL: TSA token verification failed for seq {} against provided CAfile",
                            r.sequence_no
                        ));
                    }
                }
                Err(e) => {
                    if cafile_path.is_some() {
                        return Err(format!(
                            "FAIL: TSA token verification error for seq {}: {e}",
                            r.sequence_no
                        ));
                    }
                }
            }
        }
    }

    let total = chain.len();
    let mut out = String::new();

    let head = &chain[0];
    let tail_seq = chain[total - 1].sequence_no;
    // A head with a non-null prev_hash continues an earlier receipt this file does not hold.
    let segment = head.prev_hash.as_deref().map(|prev| {
        format!(
            "SEGMENT: starts at seq {} after {prev}; earlier receipts are not in this file",
            head.sequence_no
        )
    });
    match &head.prev_hash {
        None => out.push_str(&format!(
            "CHAIN:      VERIFIED ({total} links, seq {}..{tail_seq}, head prev_hash null)\n",
            head.sequence_no
        )),
        Some(prev) => out.push_str(&format!(
            "CHAIN:      VERIFIED SEGMENT ({total} links, seq {}..{tail_seq}, head prev_hash {prev})\n",
            head.sequence_no
        )),
    }
    if pubkey_hex.is_some() {
        out.push_str(&format!(
            "SIGNATURES: VERIFIED (ed25519, {} links)\n",
            total
        ));
    } else {
        out.push_str("SIGNATURES: NOT CHECKED (no --pubkey)\n");
    }

    if hash_verified_count == total && total > 0 {
        out.push_str(&format!(
            "HASH:       VERIFIED ({}/{} links, {})\n",
            hash_verified_count,
            total,
            formats.join(" + ")
        ));
    } else if hash_verified_count > 0 {
        out.push_str(&format!(
            "HASH:       VERIFIED PARTIAL ({}/{} links, {} NOT RECOMPUTED)\n",
            hash_verified_count, total, hash_not_recomputed_count
        ));
    } else {
        out.push_str(&format!(
            "HASH:       NOT RECOMPUTED ({}/{} links, no known format)\n",
            hash_not_recomputed_count, total
        ));
    }

    let all_timestamped = verified_tsa_count == total && total > 0;
    if all_timestamped {
        out.push_str(&format!(
            "TIMESTAMP:  RFC 3161 SIGNATURE OK ({}/{} links)\n",
            verified_tsa_count, total
        ));
    } else if verified_tsa_count > 0 {
        out.push_str(&format!(
            "TIMESTAMP:  RFC 3161 SIGNATURE OK PARTIAL ({}/{} links)\n",
            verified_tsa_count, total
        ));
    } else if tsa_present_count == total && total > 0 {
        out.push_str(&format!(
            "TIMESTAMP:  TOKEN PRESENT ({}/{} links, NOT VALIDATED)\n",
            tsa_present_count, total
        ));
    } else if tsa_present_count > 0 {
        out.push_str(&format!(
            "TIMESTAMP:  TOKEN PRESENT PARTIAL ({}/{} links, NOT VALIDATED)\n",
            tsa_present_count, total
        ));
    } else {
        out.push_str(&format!("TIMESTAMP:  ABSENT (0/{} links)\n", total));
    }

    // Combined two-tier verdict (H8). Tier 1 = authenticity (chain + hash + signature,
    // all fail-closed above), Tier 2 = timestamp qualification (fail-open). A receipt
    // that is authentic but not timestamped is reported "SIGNED, NOT TIMESTAMPED" and
    // never as fully qualified evidence; only an authentic + RFC-3161-validated chain
    // is "FULLY QUALIFIED". The two are deliberately, visibly different lines.
    // Qualifiers no tier can lift: a segment is not the whole history, and a reede-v1
    // link's sequence_no, timestamp and subject_id are not signed, so an edit to them
    // cannot be detected. Both are appended to whichever verdict is printed.
    let mut caveats: Vec<String> = Vec::new();
    if let Some(segment) = segment {
        caveats.push(segment);
    }
    if v1_count > 0 {
        caveats.push(format!(
            "reede-v1 on {v1_count} link(s): sequence_no, timestamp and subject_id are not covered by hash or signature"
        ));
    }
    let caveats = caveats.iter().map(|c| format!("; {c}")).collect::<String>();
    let authenticity_established =
        pubkey_hex.is_some() && hash_verified_count == total && total > 0;
    if !authenticity_established {
        let mut gaps: Vec<String> = Vec::new();
        if pubkey_hex.is_none() {
            gaps.push("signatures not checked (no --pubkey)".to_string());
        }
        if hash_verified_count != total {
            gaps.push(format!(
                "content-hash not recomputable on {} link(s)",
                total - hash_verified_count
            ));
        }
        out.push_str(&format!(
            "VERDICT:    NOT FULLY VERIFIED ({}{caveats})\n",
            gaps.join("; ")
        ));
    } else if all_timestamped {
        out.push_str(&format!(
            "VERDICT:    FULLY QUALIFIED (authentic + RFC 3161 timestamped{caveats})\n"
        ));
    } else {
        out.push_str(&format!(
            "VERDICT:    SIGNED, NOT TIMESTAMPED (authentic; not fully qualified evidence{caveats})\n"
        ));
    }

    Ok(out)
}

fn verify_tsa_token_standalone(
    token_b64: &str,
    content_hash: &str,
    cafile: Option<&str>,
) -> Result<bool, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let token_bytes = match STANDARD.decode(token_b64) {
        Ok(b) => b,
        Err(e) => return Err(format!("Base64 decode failed: {e}")),
    };

    if token_bytes.is_empty() {
        return Err("TSA token bytes empty".to_string());
    }

    let temp_dir = env::temp_dir();
    let token_file = temp_dir.join(format!("reede_tsa_{}.p7", uuid::Uuid::new_v4()));
    if let Err(e) = fs::write(&token_file, &token_bytes) {
        return Err(format!("Failed to write temp TSA token file: {e}"));
    }

    let mut args = vec![
        "ts".to_string(),
        "-verify".to_string(),
        "-digest".to_string(),
        content_hash.to_string(),
        "-in".to_string(),
        token_file.to_str().unwrap().to_string(),
        "-token_in".to_string(),
    ];

    if let Some(ca) = cafile {
        args.push("-CAfile".to_string());
        args.push(ca.to_string());
    }

    let output = std::process::Command::new("openssl").args(&args).output();

    let _ = fs::remove_file(&token_file);

    match output {
        Ok(out) => {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("Verification: OK") {
                    return Ok(true);
                }
            }
            // Strict: return false on openssl verification failure without dummy fallbacks
            Ok(false)
        }
        Err(e) => Err(format!("Failed to run openssl ts -verify: {e}")),
    }
}

#[cfg(test)]
mod tests {
    //! The verifier verifies what production writes. `reede-v1-writer-receipt.json`
    //! is one receipt exactly as `the host application::receipt::finalize_receipt` emits
    //! it for a finalized run (pinned there by a cross-implementation test that re-runs
    //! the writer and compares hash + signature); `reede-v1-vector.json` is the O5
    //! shared vector. Both go through the same report the binary prints.
    use super::*;

    const PRODUCTION_FIXTURE: &str =
        include_str!("../../../tests/fixtures/reede-v1-writer-receipt.json");
    const SHARED_VECTOR: &str = include_str!("../../../tests/fixtures/reede-v1-vector.json");

    fn fixture(doc: &str) -> (ExecutionReceipt, String, String) {
        let doc: serde_json::Value = serde_json::from_str(doc).unwrap();
        let receipt: ExecutionReceipt = serde_json::from_value(doc["receipt"].clone()).unwrap();
        (
            receipt,
            doc["pubkey_hex"].as_str().unwrap().to_string(),
            doc["expected_content_hash"].as_str().unwrap().to_string(),
        )
    }

    #[test]
    fn production_receipt_fixture_verifies() {
        let (receipt, pubkey, expected_hash) = fixture(PRODUCTION_FIXTURE);
        assert_eq!(receipt.format.as_deref(), Some(REEDE_V1_FORMAT));
        assert_eq!(receipt.content_hash, expected_hash);
        assert_eq!(
            reede::receipt::recompute_content_hash_reede_v1(&receipt),
            expected_hash
        );
        // Production shape: the signed payload_summary is the canonical terminal
        // summary v2, including producer identity, terminal status, and final value hash.
        let summary: serde_json::Value =
            serde_json::from_str(&receipt.payload_summary).expect("v2 terminal summary JSON");
        assert_eq!(summary["version"], 2);
        assert_eq!(summary["agent_id"], "example-agent");
        assert_eq!(summary["terminal_status"], "complete");
        let final_value_sha256 = summary["final_value_sha256"]
            .as_str()
            .expect("v2 summary final_value_sha256");
        assert_eq!(final_value_sha256.len(), 64);
        assert!(final_value_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));

        let report = verify_chain_report(&[receipt], Some(&pubkey), None, false)
            .expect("production receipt verifies");
        assert!(
            report.contains("CHAIN:      VERIFIED (1 links, seq 1..1, head prev_hash null)"),
            "{report}"
        );
        assert!(
            report.contains("SIGNATURES: VERIFIED (ed25519, 1 links)"),
            "{report}"
        );
        assert!(
            report.contains("HASH:       VERIFIED (1/1 links, reede-v1)"),
            "{report}"
        );
        assert!(
            report.contains("TIMESTAMP:  ABSENT (0/1 links)"),
            "{report}"
        );
        assert!(
            report.contains("VERDICT:    SIGNED, NOT TIMESTAMPED"),
            "{report}"
        );
        assert!(!report.contains("FULLY QUALIFIED"), "{report}");
    }

    #[test]
    fn production_receipt_fixture_rejects_tamper_and_wrong_key() {
        let (receipt, pubkey, _) = fixture(PRODUCTION_FIXTURE);

        let mut tampered = receipt.clone();
        tampered.tokens_used += 1;
        let err = verify_chain_report(&[tampered], Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("content_hash mismatch"), "{err}");

        let mut flipped = receipt.clone();
        flipped.payload_summary = flipped.payload_summary.replacen("complete", "error", 1);
        let err = verify_chain_report(&[flipped], Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("content_hash mismatch"), "{err}");

        let mut bad_sig = receipt.clone();
        let mut bytes = hex::decode(&bad_sig.signature).unwrap();
        bytes[0] ^= 0xff;
        bad_sig.signature = hex::encode(bytes);
        let err = verify_chain_report(&[bad_sig], Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("Signature verification failed"), "{err}");

        let other_key = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[1u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let err = verify_chain_report(&[receipt], Some(&other_key), None, false).unwrap_err();
        assert!(err.contains("Signature verification failed"), "{err}");
    }

    /// The verifier reads only reede-v1: a pre-cutover legacy-format `task_receipts` row
    /// is reported as not recomputable and the
    /// verdict never claims more than the signature check established.
    #[test]
    fn legacy_format_is_reported_unverifiable_not_passed() {
        let (mut receipt, pubkey, _) = fixture(PRODUCTION_FIXTURE);
        receipt.format = Some("legacy-v0".to_string());
        let report = verify_chain_report(&[receipt.clone()], Some(&pubkey), None, false).unwrap();
        assert!(
            report.contains("HASH:       NOT RECOMPUTED (1/1 links, no known format)"),
            "{report}"
        );
        assert!(
            report.contains(
                "VERDICT:    NOT FULLY VERIFIED (content-hash not recomputable on 1 link(s))"
            ),
            "{report}"
        );

        receipt.format = None;
        let report = verify_chain_report(&[receipt], None, None, false).unwrap();
        assert!(
            report.contains("SIGNATURES: NOT CHECKED (no --pubkey)"),
            "{report}"
        );
        assert!(report.contains("VERDICT:    NOT FULLY VERIFIED (signatures not checked (no --pubkey); content-hash not recomputable on 1 link(s))"), "{report}");
    }

    #[test]
    fn shared_vector_verifies_through_the_same_report() {
        let (receipt, pubkey, expected_hash) = fixture(SHARED_VECTOR);
        assert_eq!(receipt.content_hash, expected_hash);
        let report = verify_chain_report(&[receipt], Some(&pubkey), None, false).unwrap();
        assert!(
            report.contains("HASH:       VERIFIED (1/1 links, reede-v1)"),
            "{report}"
        );
        assert!(
            report.contains("VERDICT:    SIGNED, NOT TIMESTAMPED"),
            "{report}"
        );
    }

    /// A two-link chain spliced out of order fails the linkage tier before anything else.
    #[test]
    fn broken_linkage_is_rejected() {
        let (receipt, pubkey, _) = fixture(PRODUCTION_FIXTURE);
        let mut second = receipt.clone();
        second.sequence_no = 2;
        second.prev_hash = Some("not-the-first-hash".to_string());
        let err = verify_chain_report(&[receipt, second], Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("Receipt chain verification failed"), "{err}");
    }

    // ---- Finding 6 (CODE_AUDIT_2026-10-26): truncation and re-dating ----

    const V2_VECTOR: &str = include_str!("../../../tests/fixtures/reede-v2-vector.json");

    fn seeded_signer() -> reede::receipt::InMemoryReceiptSigner {
        reede::receipt::InMemoryReceiptSigner::new(ed25519_dalek::SigningKey::from_bytes(
            &[7u8; 32],
        ))
    }

    /// Five receipts written by the production emitter (reede-v2), oldest first.
    async fn emitted_chain(
        signer: &reede::receipt::InMemoryReceiptSigner,
    ) -> Vec<ExecutionReceipt> {
        use reede::receipt::{emit_execution_receipt, InMemoryReceiptStore, ReceiptStore};
        let store = InMemoryReceiptStore::new();
        for i in 0..5 {
            emit_execution_receipt(
                signer,
                &store,
                uuid::Uuid::new_v4(),
                "tenant-f6",
                format!("run-{i}"),
                10 + i,
                100,
                0,
                Some(format!("subject-{i}")),
            )
            .await
            .unwrap();
        }
        let chain = store.chain("tenant-f6").await.unwrap();
        assert!(chain
            .iter()
            .all(|r| r.format.as_deref() == Some(reede::receipt::REEDE_V2_FORMAT)));
        chain
    }

    /// Five hand-built receipts in `format`, linked and signed the way a writer would.
    fn built_chain(
        signer: &reede::receipt::InMemoryReceiptSigner,
        format: &str,
    ) -> Vec<ExecutionReceipt> {
        use reede::receipt::{signer_key_id, ReceiptSigner, REEDE_V2_FORMAT};
        let v2 = format == REEDE_V2_FORMAT;
        let mut chain: Vec<ExecutionReceipt> = Vec::new();
        for seq in 1..=5u64 {
            let mut r = ExecutionReceipt {
                task_id: uuid::Uuid::new_v4(),
                tenant_id: "tenant-f6-built".to_string(),
                sequence_no: seq,
                credits_spent: 10,
                tokens_used: 100,
                reservation_credits: 0,
                content_hash: String::new(),
                prev_hash: chain.last().map(|p| p.content_hash.clone()),
                signature: String::new(),
                tsa_token: None,
                timestamp: chrono::DateTime::from_timestamp(1_700_000_000 + seq as i64, 0).unwrap(),
                payload_summary: format!("built-{seq}"),
                format: Some(format.to_string()),
                subject_id: v2.then(|| format!("subject-{seq}")),
                signer_key_id: if v2 { signer_key_id(signer) } else { None },
            };
            r.content_hash = recompute_content_hash(&r).unwrap();
            r.signature = hex::encode(signer.sign(r.content_hash.as_bytes()).unwrap());
            chain.push(r);
        }
        chain
    }

    #[test]
    fn genuine_v2_chain_verifies_as_a_full_chain() {
        let signer = seeded_signer();
        let pubkey = hex::encode(signer.verifying_key().to_bytes());
        let chain = built_chain(&signer, reede::receipt::REEDE_V2_FORMAT);
        let report = verify_chain_report(&chain, Some(&pubkey), None, false).unwrap();
        assert!(
            report.contains("CHAIN:      VERIFIED (5 links, seq 1..5, head prev_hash null)"),
            "{report}"
        );
        assert!(
            report.contains("HASH:       VERIFIED (5/5 links, reede-v2)"),
            "{report}"
        );
        assert!(
            report.contains(
                "VERDICT:    SIGNED, NOT TIMESTAMPED (authentic; not fully qualified evidence)\n"
            ),
            "a full v2 chain carries no caveat: {report}"
        );
    }

    /// The audit's reproduction, on what production writes today: export [r1..r5], delete
    /// r1 and r2. Before the fix this printed `CHAIN: VERIFIED (3 links)`.
    #[tokio::test]
    async fn chain_with_first_two_receipts_removed_fails() {
        let signer = seeded_signer();
        let pubkey = hex::encode(signer.verifying_key().to_bytes());
        let chain = emitted_chain(&signer).await;
        verify_chain_report(&chain, Some(&pubkey), None, false).expect("the full export verifies");
        let truncated = chain[2..].to_vec();

        let err = verify_chain_report(&truncated, Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("chain starts at seq 3, not 1"), "{err}");

        // Asked for explicitly, the segment verifies but is named a segment, with the
        // receipt it continues from, and never reads as a full chain.
        let report = verify_chain_report(&truncated, Some(&pubkey), None, true).unwrap();
        let cut_at = &chain[1].content_hash;
        assert!(
            report.contains(&format!(
                "CHAIN:      VERIFIED SEGMENT (3 links, seq 3..5, head prev_hash {cut_at})"
            )),
            "{report}"
        );
        let verdict = report.lines().find(|l| l.starts_with("VERDICT:")).unwrap();
        assert!(
            verdict.contains(&format!(
                "SEGMENT: starts at seq 3 after {cut_at}; earlier receipts are not in this file"
            )),
            "{verdict}"
        );

        // v1 (still verifiable, no longer written) does not sign sequence_no, so a forger can
        // renumber a cut v1 chain to start at 1. It still cannot null the head's prev_hash
        // (hashed), so the report names it a segment instead of a full chain.
        let v1 = built_chain(&signer, REEDE_V1_FORMAT);
        let mut renumbered = v1[2..].to_vec();
        for (i, r) in renumbered.iter_mut().enumerate() {
            r.sequence_no = i as u64 + 1;
        }
        let report = verify_chain_report(&renumbered, Some(&pubkey), None, false).unwrap();
        assert!(
            report.contains("CHAIN:      VERIFIED SEGMENT (3 links, seq 1..3"),
            "{report}"
        );
        assert!(
            report.contains("not covered by hash or signature"),
            "{report}"
        );

        // Under v2 the same renumbering breaks the hash.
        let v2 = built_chain(&signer, reede::receipt::REEDE_V2_FORMAT);
        let mut renumbered = v2[2..].to_vec();
        for (i, r) in renumbered.iter_mut().enumerate() {
            r.sequence_no = i as u64 + 1;
        }
        let err = verify_chain_report(&renumbered, Some(&pubkey), None, false).unwrap_err();
        assert!(
            err.contains("content_hash mismatch for seq 1 (format reede-v2)"),
            "{err}"
        );
    }

    #[test]
    fn v2_chain_with_one_timestamp_edited_fails() {
        let signer = seeded_signer();
        let pubkey = hex::encode(signer.verifying_key().to_bytes());
        let mut chain = built_chain(&signer, reede::receipt::REEDE_V2_FORMAT);
        chain[2].timestamp -= chrono::Duration::days(365);
        let err = verify_chain_report(&chain, Some(&pubkey), None, false).unwrap_err();
        assert!(
            err.contains("content_hash mismatch for seq 3 (format reede-v2)"),
            "{err}"
        );

        // subject_id is bound too.
        let mut chain = built_chain(&signer, reede::receipt::REEDE_V2_FORMAT);
        chain[0].subject_id = Some("someone-else".to_string());
        let err = verify_chain_report(&chain, Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("content_hash mismatch for seq 1"), "{err}");
    }

    /// reede-v1 cannot detect the same edit (the field is not hashed), so the report must
    /// say so in the verdict rather than present the chain as if it had been checked.
    #[tokio::test]
    async fn v1_chain_with_timestamp_edited_is_reported_not_silently_passed() {
        let signer = seeded_signer();
        let pubkey = hex::encode(signer.verifying_key().to_bytes());
        let mut chain = built_chain(&signer, REEDE_V1_FORMAT);
        chain[2].timestamp -= chrono::Duration::days(365);
        let report = verify_chain_report(&chain, Some(&pubkey), None, false).unwrap();
        assert!(
            report.contains("HASH:       VERIFIED (5/5 links, reede-v1)"),
            "{report}"
        );
        let verdict = report.lines().find(|l| l.starts_with("VERDICT:")).unwrap();
        assert!(
            verdict.contains(
                "reede-v1 on 5 link(s): sequence_no, timestamp and subject_id are not covered by hash or signature"
            ),
            "the caveat is in the VERDICT line: {verdict}"
        );
    }

    /// Sequence contiguity, one tenant and no repeated link, each in both directions, on
    /// the reede-v2 chains production writes.
    #[tokio::test]
    async fn gap_foreign_tenant_and_duplicate_are_rejected() {
        let signer = seeded_signer();
        let pubkey = hex::encode(signer.verifying_key().to_bytes());
        let chain = emitted_chain(&signer).await;
        assert!(verify_chain_report(&chain, Some(&pubkey), None, false).is_ok());

        let mut gap = chain.clone();
        gap.remove(2);
        let err = verify_chain_report(&gap, Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("seq 4 follows seq 2"), "{err}");

        // A v1 receipt's tenant_id is hashed, so the swap is also caught by the hash; the
        // tenant check fires first and names it.
        let mut foreign = chain.clone();
        foreign[3].tenant_id = "tenant-other".to_string();
        let err = verify_chain_report(&foreign, Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("tenant \"tenant-other\""), "{err}");

        let mut dup = chain.clone();
        dup.push(chain[4].clone());
        let err = verify_chain_report(&dup, Some(&pubkey), None, true).unwrap_err();
        assert!(err.contains("appears twice"), "{err}");
    }

    #[test]
    fn v2_shared_vector_verifies_as_a_segment_only() {
        let (receipt, pubkey, expected_hash) = fixture(V2_VECTOR);
        assert_eq!(receipt.content_hash, expected_hash);
        let report =
            verify_chain_report(std::slice::from_ref(&receipt), Some(&pubkey), None, true).unwrap();
        assert!(
            report.contains("HASH:       VERIFIED (1/1 links, reede-v2)"),
            "{report}"
        );
        assert!(
            report.contains("CHAIN:      VERIFIED SEGMENT (1 links, seq 2..2"),
            "{report}"
        );
        let err = verify_chain_report(&[receipt], Some(&pubkey), None, false).unwrap_err();
        assert!(err.contains("chain starts at seq 2, not 1"), "{err}");
    }
}
