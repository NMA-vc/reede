//! Verify a receipt chain offline, and watch tampered copies fail.
//!
//! Run: `cargo run -p reede --example verify`
//!   or `cargo run -p reede --example verify -- --chain <dir>/chain.json --pubkey <hex>`
//!
//! With no arguments it builds the same chain the `receipt` example emits (same
//! code, in-process, with a fresh ephemeral key). With `--chain`/`--pubkey` it
//! reads a chain the `receipt` example wrote instead.
//!
//! What is checked, using only the library functions an auditor would use:
//! - `verify_chain_from_genesis`: one tenant, `sequence_no` contiguous from 1,
//!   and every receipt's `prev_hash` is the previous receipt's hash;
//! - `verify_receipt_two_tier`: tier 1 (fail-closed) recomputes the content hash
//!   by the receipt's own format rule (`reede-v2` for what is emitted today)
//!   and checks the Ed25519 signature; tier 2 (fail-open) classifies the
//!   timestamp.
//!
//! Then six tampered copies are checked, and each must be rejected. The
//! process exits non-zero if the genuine chain fails or any tamper passes.

mod common;

use ed25519_dalek::VerifyingKey;
use reede::receipt::{
    recompute_content_hash, verify_chain_from_genesis, verify_receipt_two_tier, ExecutionReceipt,
};
use std::process::exit;

fn verify_all(chain: &[ExecutionReceipt], key: &VerifyingKey) -> Result<(), String> {
    verify_chain_from_genesis(chain, None).map_err(|e| e.to_string())?;
    for r in chain {
        verify_receipt_two_tier(r, key).map_err(|e| format!("seq {}: {e}", r.sequence_no))?;
    }
    Ok(())
}

fn parse_key(hex_str: &str) -> VerifyingKey {
    let bytes = hex::decode(hex_str.trim()).unwrap_or_else(|e| {
        eprintln!("Error: public key is not hex: {e}");
        exit(1);
    });
    VerifyingKey::try_from(bytes.as_slice()).unwrap_or_else(|e| {
        eprintln!("Error: not an Ed25519 public key: {e}");
        exit(1);
    })
}

async fn load() -> (Vec<ExecutionReceipt>, VerifyingKey, String) {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    match (flag("--chain"), flag("--pubkey")) {
        (Some(path), Some(pubkey)) => {
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
                eprintln!("Error reading {path}: {e}");
                exit(1);
            });
            let chain = serde_json::from_str(&text).unwrap_or_else(|e| {
                eprintln!("Error parsing {path} as a receipt chain: {e}");
                exit(1);
            });
            (chain, parse_key(&pubkey), path)
        }
        (None, None) => {
            let signer = common::ephemeral_signer();
            let chain = common::emit_demo_chain(&signer).await;
            (
                chain,
                signer.verifying_key(),
                "in-process demo chain".to_string(),
            )
        }
        _ => {
            eprintln!("Usage: verify [--chain <chain.json> --pubkey <hex>]");
            exit(2);
        }
    }
}

#[tokio::main]
async fn main() {
    let (chain, key, source) = load().await;
    if chain.is_empty() {
        eprintln!("Error: {source} holds no receipts");
        exit(1);
    }
    println!("Verifying {} ({} receipts)", source, chain.len());

    // The genuine chain must verify.
    if let Err(e) = verify_chain_from_genesis(&chain, None) {
        eprintln!("FAIL: genuine chain linkage: {e}");
        exit(1);
    }
    println!("  CHAIN      linked ({} receipts)", chain.len());
    for r in &chain {
        match verify_receipt_two_tier(r, &key) {
            Ok(verdict) => println!(
                "  seq {}      authentic={}  timestamp={}  fully_qualified={}",
                r.sequence_no,
                verdict.is_authentic(),
                verdict.timestamp.label(),
                verdict.is_fully_qualified(),
            ),
            Err(e) => {
                eprintln!("FAIL: genuine receipt seq {}: {e}", r.sequence_no);
                exit(1);
            }
        }
    }

    // Every tampered copy must be rejected.
    let last = chain.len() - 1;
    let mut cases: Vec<(&str, Vec<ExecutionReceipt>, VerifyingKey)> = Vec::new();

    let mut c = chain.clone();
    c[last].credits_spent += 1;
    cases.push(("credits_spent edited", c, key));

    let mut c = chain.clone();
    c[0].payload_summary
        .push_str(" (and nothing else happened)");
    cases.push(("payload_summary edited", c, key));

    // A forger who edits a field AND recomputes the hash still has no key.
    let mut c = chain.clone();
    c[last].credits_spent = 0;
    c[last].content_hash = recompute_content_hash(&c[last]).unwrap_or_default();
    cases.push(("field edited and hash recomputed", c, key));

    let other = common::ephemeral_signer().verifying_key();
    cases.push(("checked against the wrong public key", chain.clone(), other));

    if chain.len() >= 3 {
        let mut c = chain.clone();
        c.remove(1);
        cases.push(("a receipt dropped from the middle", c, key));
        cases.push(("the first two receipts dropped", chain[2..].to_vec(), key));
    }

    let mut unexpected = 0;
    println!("\nTampered copies:");
    for (label, tampered, k) in &cases {
        match verify_all(tampered, k) {
            Err(e) => println!("  REJECTED  {label}: {e}"),
            Ok(()) => {
                println!("  ACCEPTED  {label}   <-- UNEXPECTED");
                unexpected += 1;
            }
        }
    }

    if unexpected > 0 {
        eprintln!("\nFAIL: {unexpected} tampered copy/copies verified");
        exit(1);
    }
    println!(
        "\nOK: the genuine chain verifies; all {} tampered copies are rejected.",
        cases.len()
    );
}
