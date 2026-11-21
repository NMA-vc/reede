//! Emit a signed, hash-chained receipt chain and export it for an auditor.
//!
//! Run: `cargo run -p reede --example receipt [-- <output-dir>]`
//!
//! Three governed runs each reserve credits from a budget ledger, settle what
//! they actually spent, and leave one `reede-v2` receipt. Each receipt's
//! `content_hash` covers its own fields plus the previous receipt's hash, and
//! is signed with an Ed25519 key generated for this process only (the private
//! key is never written anywhere).
//!
//! The chain is written as `chain.json`, with the public key in `pubkey.hex`,
//! to `<output-dir>` (default: `<system temp dir>/reede-example`). Check it
//! with the offline verifier:
//!
//! ```text
//! cargo run -p reede --bin verify -- --chain <dir>/chain.json --pubkey "$(cat <dir>/pubkey.hex)"
//! ```
//!
//! No network. Receipts carry no RFC 3161 timestamp token (`tsa_token` is
//! null), so the verifier reports them as signed, not timestamped.

mod common;

use std::path::PathBuf;
use std::process::exit;

#[tokio::main]
async fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("reede-example"));

    let signer = common::ephemeral_signer();
    let pubkey = common::pubkey_hex(&signer);
    let chain = common::emit_demo_chain(&signer).await;

    println!(
        "Tenant {} receipt chain ({} receipts):",
        common::TENANT,
        chain.len()
    );
    for r in &chain {
        println!(
            "  seq {}  spent {:>3} of {:>3} reserved credits, {:>5} tokens  hash {}..  prev {}",
            r.sequence_no,
            r.credits_spent,
            r.reservation_credits,
            r.tokens_used,
            &r.content_hash[..16],
            r.prev_hash
                .as_deref()
                .map(|h| format!("{}..", &h[..16]))
                .unwrap_or_else(|| "(chain start)".to_string()),
        );
        println!("         {}", r.payload_summary);
    }

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("Error creating {}: {e}", out_dir.display());
        exit(1);
    }
    let chain_path = out_dir.join("chain.json");
    let pubkey_path = out_dir.join("pubkey.hex");
    let json = serde_json::to_string_pretty(&chain).expect("receipts serialize");
    if let Err(e) = std::fs::write(&chain_path, json) {
        eprintln!("Error writing {}: {e}", chain_path.display());
        exit(1);
    }
    if let Err(e) = std::fs::write(&pubkey_path, &pubkey) {
        eprintln!("Error writing {}: {e}", pubkey_path.display());
        exit(1);
    }

    println!("\nWrote {}", chain_path.display());
    println!("Wrote {}", pubkey_path.display());
    println!("\nVerify offline:");
    println!(
        "  cargo run -p reede --bin verify -- --chain {} --pubkey {}",
        chain_path.display(),
        pubkey
    );
}
