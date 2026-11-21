//! Parse and validate an agent manifest, then derive the policy it runs under.
//!
//! Run: `cargo run -p reede --example manifest`
//!
//! A manifest is the agent's own declaration of what it is and what it needs.
//! `parse_manifest_v1` rejects anything it does not understand (unknown keys
//! are an error, not ignored), refuses an empty model provider (which provider is
//! allowed is host policy, not Reede's), and refuses a budget ceiling of zero or less.
//! `derive_policy` turns the accepted manifest into a `DerivedPolicy`: the
//! budget ceiling, the human-approval threshold, the egress allowlist and the
//! resource grants. No network, no files.

use reede::policy::derive_policy;
use reede::spec::parse_manifest_v1;
use std::process::exit;

const MANIFEST: &str = r#"
[meta]
schema_version = "1"
author = "example-founder"

[agent]
id = "market-researcher"
name = "Market Researcher"
description = "Summarizes EU market reports on request"
version = "1.0.0"
egress = ["reports.example.eu"]

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

[[agent.triggers]]
type = "manual"
"#;

fn main() {
    let mut failures = 0;

    // 1. A well-formed manifest is accepted.
    let spec = match parse_manifest_v1(MANIFEST) {
        Ok(spec) => spec,
        Err(e) => {
            eprintln!("FAIL: the example manifest was rejected: {e}");
            exit(1);
        }
    };
    println!(
        "ACCEPTED  agent '{}' v{} by {} (model {}/{}, budget {:.2} EUR/month)",
        spec.agent.id,
        spec.agent.version,
        spec.meta.author,
        spec.agent.model.provider,
        spec.agent.model.name,
        spec.agent.limits.monthly_budget_eur,
    );

    // 2. The policy it runs under, derived from the manifest alone.
    let policy = derive_policy(&spec);
    println!("\nDerived policy:");
    println!(
        "{}",
        serde_json::to_string_pretty(&policy).expect("DerivedPolicy serializes")
    );
    // The allowlist is the union of the MCP server hosts and the manifest's
    // own `egress` list; nothing else.
    let expected_hosts = vec![
        "api.marketdata.example.eu".to_string(),
        "reports.example.eu".to_string(),
    ];
    if policy.egress_allowlist != expected_hosts {
        eprintln!(
            "FAIL: unexpected egress allowlist {:?}",
            policy.egress_allowlist
        );
        failures += 1;
    }

    // 3. The gate fires on bad input, too. Each of these must be rejected.
    println!("\nRejected manifests:");
    let bad: [(&str, String); 3] = [
        (
            "empty model provider",
            MANIFEST.replace(r#"provider = "cortecs""#, r#"provider = """#),
        ),
        (
            "zero budget ceiling",
            MANIFEST.replace("monthly_budget_eur = 200.0", "monthly_budget_eur = 0.0"),
        ),
        (
            "unknown key",
            MANIFEST.replace("[agent.limits]", "[agent.limits]\nunlimited = true"),
        ),
    ];
    for (label, toml) in &bad {
        match parse_manifest_v1(toml) {
            Err(e) => println!("REJECTED  {label}: {e}"),
            Ok(_) => {
                eprintln!("FAIL: manifest with {label} was accepted");
                failures += 1;
            }
        }
    }

    if failures > 0 {
        exit(1);
    }
}
