//! Shared by the `receipt` and `verify` examples, so `verify` checks exactly
//! the chain that `receipt` emits. Not an example of its own: cargo only
//! discovers `examples/<name>.rs` and `examples/<name>/main.rs`.
//!
//! Everything here is in-process: an ephemeral Ed25519 key, an in-memory
//! budget ledger and an in-memory receipt store. No network, no database.

use reede::ledger::{InMemoryLedger, Ledger};
use reede::receipt::{
    emit_execution_receipt, ExecutionReceipt, InMemoryReceiptSigner, InMemoryReceiptStore,
};
use uuid::Uuid;

/// The tenant whose receipt chain the examples build. Every receipt in a
/// chain is scoped to one tenant; `sequence_no` and `prev_hash` count per tenant.
pub const TENANT: &str = "tenant-example";

/// One governed run: what it did, how much it reserved, how much it spent.
pub struct DemoRun {
    pub summary: &'static str,
    pub reserve_credits: i64,
    pub spent_credits: i64,
    pub tokens_used: u32,
}

pub const RUNS: [DemoRun; 3] = [
    DemoRun {
        summary: "market-researcher: summarised 3 EU market reports",
        reserve_credits: 40,
        spent_credits: 25,
        tokens_used: 1800,
    },
    DemoRun {
        summary: "market-researcher: drafted a battlecard for acme",
        reserve_credits: 40,
        spent_credits: 31,
        tokens_used: 2400,
    },
    DemoRun {
        summary: "market-researcher: answered a follow-up question",
        reserve_credits: 20,
        spent_credits: 6,
        tokens_used: 420,
    },
];

/// A fresh signer with a random key that lives only in this process.
pub fn ephemeral_signer() -> InMemoryReceiptSigner {
    InMemoryReceiptSigner::generate_random()
}

/// The hex-encoded Ed25519 public key an auditor needs to verify the chain.
#[allow(dead_code)] // used by `receipt`, not by `verify`
pub fn pubkey_hex(signer: &InMemoryReceiptSigner) -> String {
    hex::encode(signer.verifying_key().to_bytes())
}

/// Run each demo run against the budget ledger (reserve, then settle the
/// actual spend) and emit one chained, signed `reede-v1` receipt per run.
pub async fn emit_demo_chain(signer: &InMemoryReceiptSigner) -> Vec<ExecutionReceipt> {
    let ledger = InMemoryLedger::new();
    ledger.set_balance(TENANT, 200);
    let store = InMemoryReceiptStore::new();

    let mut chain = Vec::with_capacity(RUNS.len());
    for run in &RUNS {
        let task_id = Uuid::new_v4();
        let reservation = ledger
            .reserve(task_id, TENANT, run.reserve_credits)
            .await
            .expect("the demo budget covers every demo run");
        ledger
            .deduct(reservation, run.spent_credits)
            .await
            .expect("a fresh reservation settles once");

        let receipt = emit_execution_receipt(
            signer,
            &store,
            task_id,
            TENANT,
            run.summary,
            run.spent_credits,
            run.tokens_used,
            run.reserve_credits,
            None,
        )
        .await
        .expect("an in-memory signer and store do not fail");
        chain.push(receipt);
    }
    chain
}
