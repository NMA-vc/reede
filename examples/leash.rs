//! The leash: temporary, explicit, revocable authority, checked in-process.
//!
//! Run: `cargo run -p reede --example leash`
//!
//! Walks the five checks a governed run is held to, each in both directions
//! (the allowed case passes, the disallowed case is refused):
//!
//! 1. egress   - `AllowlistEgress` decides which hosts a run may reach;
//! 2. grants   - `grant_permits` decides which tools a run may invoke;
//! 3. budget   - `InMemoryLedger` reserves credits before work and settles after;
//! 4. tokens   - `TokenBudget` holds a hard per-task token ceiling;
//! 5. leases   - `InMemoryLeaseManager` hands out credentials that expire or
//!    can be revoked mid-run.
//!
//! These are the library decisions only. Enforcing egress at the network
//! layer needs the gVisor sandbox and the egress proxy, which this example
//! does not start (see README "Status"). No network, no files.

use reede::egress::{AllowlistEgress, EgressPolicy};
use reede::error::ReedeError;
use reede::lease::{InMemoryLeaseManager, LeaseManager};
use reede::ledger::{InMemoryLedger, Ledger};
use reede::policy::{derive_policy, grant_permits};
use reede::spec::parse_manifest_v1;
use reede::token_budget::TokenBudget;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const MANIFEST: &str = r#"
[meta]
schema_version = "1"
author = "example-founder"

[agent]
id = "market-researcher"
name = "Market Researcher"
description = "Summarizes EU market reports on request"
version = "1.0.0"

[agent.model]
provider = "cortecs"
name = "example-model"

[agent.prompt]
system = "You are a market research assistant."

[agent.limits]
monthly_budget_eur = 200.0

[[agent.mcp]]
name = "market-data-api"
transport = "http"
url = "https://api.marketdata.example.eu/v1"

[[agent.grant]]
resource = "market-data-api/*"
actions = ["invoke"]
"#;

/// Counts checks whose outcome was not the expected one.
struct Tally(u32);

impl Tally {
    fn expect(&mut self, label: &str, allowed: bool, expected: bool) {
        let verdict = if allowed { "ALLOW" } else { "DENY " };
        if allowed == expected {
            println!("  {verdict}  {label}");
        } else {
            println!("  {verdict}  {label}   <-- UNEXPECTED");
            self.0 += 1;
        }
    }
}

#[tokio::main]
async fn main() {
    let mut tally = Tally(0);
    let spec = parse_manifest_v1(MANIFEST).expect("the example manifest is valid");
    let policy = derive_policy(&spec);

    println!("1. Egress allowlist {:?}", policy.egress_allowlist);
    let egress = AllowlistEgress::from_policy(&policy);
    tally.expect(
        "https://api.marketdata.example.eu/v1/reports",
        egress.is_allowed("https://api.marketdata.example.eu/v1/reports"),
        true,
    );
    tally.expect(
        "https://attacker.example.com/upload",
        egress.is_allowed("https://attacker.example.com/upload"),
        false,
    );
    tally.expect(
        "93.184.216.34 (direct IP, bypasses DNS)",
        egress.is_allowed("93.184.216.34"),
        false,
    );
    tally.expect(
        "169.254.169.254 (cloud metadata)",
        egress.is_allowed("169.254.169.254"),
        false,
    );
    let empty = AllowlistEgress::new(vec![]);
    tally.expect(
        "anything, under an EMPTY allowlist (fail closed)",
        empty.is_allowed("api.marketdata.example.eu"),
        false,
    );

    println!("\n2. Resource grants {:?}", policy.resource_grants);
    let grants = &policy.resource_grants;
    tally.expect(
        "invoke market-data-api/search",
        grant_permits(grants, "market-data-api/search", "invoke"),
        true,
    );
    tally.expect(
        "invoke mailer/send",
        grant_permits(grants, "mailer/send", "invoke"),
        false,
    );
    tally.expect(
        "anything, under an EMPTY grant list (fail closed)",
        grant_permits(&[], "market-data-api/search", "invoke"),
        false,
    );

    println!("\n3. Budget ledger (credits)");
    let ledger = InMemoryLedger::new();
    let tenant = "tenant-example";
    ledger.set_balance(tenant, 100);
    let task = Uuid::new_v4();
    let reservation = ledger.reserve(task, tenant, 60).await;
    tally.expect(
        "reserve 60 of a 100-credit balance",
        reservation.is_ok(),
        true,
    );
    let over = ledger.reserve(task, tenant, 60).await;
    tally.expect("reserve another 60 (only 40 left)", over.is_ok(), false);
    if let Err(e) = &over {
        println!("         refused: {e}");
    }
    if let Ok(id) = reservation {
        ledger.deduct(id, 45).await.expect("settle once");
        let balance = ledger.balance(tenant).await.expect("in-memory balance");
        println!("         settled 45 of the 60 reserved; 15 refunded, balance now {balance}");
        tally.expect("balance after settlement is 55", balance == 55, true);
    }
    println!(
        "         policy also derives a human-approval threshold of {} credits; \
         enforcing it is the host runtime's job, not this example's",
        policy.hitl_above_credits
    );

    println!("\n4. Token ceiling");
    let tokens = Arc::new(TokenBudget::new(1_000));
    let first = tokens.begin(800);
    tally.expect("reserve 800 of a 1000-token ceiling", first.is_ok(), true);
    tally.expect(
        "reserve another 500 while the first is open",
        tokens.begin(500).is_ok(),
        false,
    );
    if let Ok(reservation) = first {
        reservation
            .commit(650)
            .expect("actual usage under the reserved bound");
    }
    println!(
        "         settled 650 tokens; {} remain",
        tokens.remaining_tokens()
    );

    println!("\n5. Credential leases");
    let leases = InMemoryLeaseManager::new();
    let lease = leases
        .issue(task, "market-data-api-key", Duration::from_secs(3600))
        .await
        .expect("issue a one-hour lease");
    tally.expect(
        "use a fresh one-hour lease",
        leases.check(lease.id).await.is_ok(),
        true,
    );
    leases.revoke(lease.id).await.expect("revoke");
    let after_revoke = leases.check(lease.id).await;
    tally.expect(
        "use the same lease after revocation",
        after_revoke.is_ok(),
        false,
    );
    if !matches!(after_revoke, Err(ReedeError::LeaseRevoked { .. })) {
        println!("         expected LeaseRevoked, got {after_revoke:?}");
        tally.0 += 1;
    }
    let short = leases
        .issue(task, "one-shot-token", Duration::from_millis(0))
        .await
        .expect("issue a zero-TTL lease");
    tally.expect(
        "use a lease whose TTL has passed",
        leases.check(short.id).await.is_ok(),
        false,
    );

    if tally.0 > 0 {
        eprintln!("\nFAIL: {} check(s) had an unexpected outcome", tally.0);
        exit(1);
    }
    println!("\nOK: every check allowed what it should and refused what it should.");
}
