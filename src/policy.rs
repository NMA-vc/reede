use crate::spec::AgentSpec;
use serde::{Deserialize, Serialize};

pub const DEFAULT_BUDGET_CEILING_EUR: f64 = 50.0;
pub const HITL_FRACTION: f64 = 0.2;
pub const HITL_FLOOR_CREDITS: i64 = 10;

/// A single resource a run is permitted to touch. `resource` is a qualified
/// `server/tool` identifier (or the `server/*` / `*` wildcard forms) -- the
/// same shape the host runtime's skill-level tool_permissions already
/// use. `actions` gates finer-than-invocation semantics (read vs write) for
/// connectors that support it; today's only enforced action is "invoke"
/// (call the tool at all). Per-resource-instance scoping (e.g. a specific
/// calendar id, not just the calendar tool) is not modeled here -- it is
/// documented future work, not solved by this type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceGrant {
    pub resource: String,
    pub actions: Vec<String>,
}

impl ResourceGrant {
    pub fn new(resource: impl Into<String>, actions: Vec<String>) -> Self {
        Self {
            resource: resource.into(),
            actions,
        }
    }
}

/// Fail-closed match: a resource+action is permitted only if some grant
/// covers it. Matching mirrors the host runtime's existing
/// `is_tool_permitted` semantics deliberately, so this is a generalization
/// of that shape (per-run grant list instead of a per-skill static file),
/// not an incompatible parallel scheme:
/// - exact `resource` match
/// - `"*"` matches any resource
/// - a grant resource ending in `/*` matches any resource sharing that
///   prefix (e.g. `"google_workspace/*"` matches `"google_workspace/list_calendar_events"`)
///   Action matching is exact-or-`"*"` within the matched grant's `actions`.
///   An empty grant list denies everything -- there is no implicit-allow path.
pub fn grant_permits(grants: &[ResourceGrant], resource: &str, action: &str) -> bool {
    // The pre-rename apply-lesson-delta id is the same resource as the neutral one, in either
    // direction, so stored grants and new requests keep matching.
    let canon = |r: &str| {
        if r == crate::govern::LEGACY_TOOL_APPLY_LESSON_DELTA {
            crate::govern::TOOL_APPLY_LESSON_DELTA.to_string()
        } else {
            r.to_string()
        }
    };
    let resource = canon(resource);
    let resource = resource.as_str();
    grants.iter().any(|g| {
        let granted = canon(&g.resource);
        let resource_matches = granted == "*"
            || granted == resource
            || (granted.ends_with("/*") && resource.starts_with(&granted[..granted.len() - 1]));
        resource_matches && g.actions.iter().any(|a| a == "*" || a == action)
    })
}

#[cfg(test)]
mod alias_tests {
    use super::*;
    use crate::govern::{LEGACY_TOOL_APPLY_LESSON_DELTA as OLD, TOOL_APPLY_LESSON_DELTA as NEW};

    fn grant(r: &str) -> Vec<ResourceGrant> {
        vec![ResourceGrant::new(r, vec!["invoke".to_string()])]
    }

    #[test]
    fn legacy_and_neutral_apply_ids_match_in_both_directions() {
        for (granted, asked) in [(OLD, NEW), (NEW, OLD), (OLD, OLD), (NEW, NEW)] {
            assert!(
                grant_permits(&grant(granted), asked, "invoke"),
                "{granted} -> {asked}"
            );
        }
        assert!(!grant_permits(&grant("feedback/other"), NEW, "invoke"));
        assert!(!grant_permits(&grant(OLD), "feedback/other", "invoke"));
        assert!(!grant_permits(&[], OLD, "invoke"));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DerivedPolicy {
    pub agent_id: String,
    pub budget_ceiling_eur: f64,
    pub hitl_above_credits: i64,
    pub egress_allowlist: Vec<String>,
    #[serde(default)]
    pub resource_grants: Vec<ResourceGrant>,
}

pub fn derive_policy(spec: &AgentSpec) -> DerivedPolicy {
    let budget_ceiling_eur = spec.agent.limits.monthly_budget_eur;
    let hitl_calc = (budget_ceiling_eur * HITL_FRACTION).ceil() as i64;
    let hitl_above_credits = std::cmp::max(HITL_FLOOR_CREDITS, hitl_calc);

    let mut allowlist_set = std::collections::BTreeSet::new();
    for mcp in &spec.agent.mcp_servers {
        if let Some(url) = &mcp.url {
            if let Ok(parsed) = url::Url::parse(url) {
                if let Some(host) = parsed.host_str() {
                    allowlist_set.insert(host.to_string());
                } else {
                    allowlist_set.insert(url.clone());
                }
            } else {
                // Host extract fallback if not full URL scheme
                let cleaned = url
                    .trim_start_matches("http://")
                    .trim_start_matches("https://")
                    .split('/')
                    .next()
                    .unwrap_or(url);
                allowlist_set.insert(cleaned.to_string());
            }
        }
    }

    // The manifest's own egress list joins the MCP url hosts in one set: a host named in both
    // appears once, and the result stays sorted and deduplicated. Empty entries are dropped,
    // an empty string would otherwise be a policy entry that matches nothing or everything.
    for host in &spec.agent.egress {
        let host = host.trim();
        if !host.is_empty() {
            allowlist_set.insert(host.to_string());
        }
    }

    let resource_grants = spec
        .agent
        .grants
        .iter()
        .map(|g| ResourceGrant::new(g.resource.clone(), g.actions.clone()))
        .collect();

    DerivedPolicy {
        agent_id: spec.agent.id.clone(),
        budget_ceiling_eur,
        hitl_above_credits,
        egress_allowlist: allowlist_set.into_iter().collect(),
        resource_grants,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::parse_manifest_v1;

    #[test]
    fn test_derive_policy_matching() {
        let toml_str = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "market-researcher"
name = "Market Researcher"
description = "EU market research agent"
version = "1.0.0"

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "You are a research assistant."

[agent.limits]
monthly_budget_eur = 200.0

[[agent.mcp]]
name = "market-data"
transport = "http"
url = "https://api.example.eu/v1"
"#;
        let spec = parse_manifest_v1(toml_str).unwrap();
        let policy = derive_policy(&spec);

        assert_eq!(policy.agent_id, "market-researcher");
        assert_eq!(policy.budget_ceiling_eur, 200.0);
        assert_eq!(policy.hitl_above_credits, 40); // 200 * 0.2 = 40
        assert_eq!(policy.egress_allowlist, vec!["api.example.eu"]);
        assert!(policy.resource_grants.is_empty());
    }

    #[test]
    fn test_derive_policy_populates_resource_grants() {
        let toml_str = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "grant-agent"
name = "Grant Agent"
description = "Agent with explicit resource grants"
version = "1.0.0"

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "You are a research assistant."

[agent.limits]
monthly_budget_eur = 50.0

[[agent.grant]]
resource = "google_workspace/list_calendar_events"
actions = ["invoke"]
"#;
        let spec = parse_manifest_v1(toml_str).unwrap();
        let policy = derive_policy(&spec);

        assert_eq!(policy.resource_grants.len(), 1);
        assert_eq!(
            policy.resource_grants[0].resource,
            "google_workspace/list_calendar_events"
        );
        assert_eq!(policy.resource_grants[0].actions, vec!["invoke"]);
    }

    #[test]
    fn test_derive_policy_unions_egress_with_mcp_hosts() {
        let toml_str = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "egress-agent"
name = "Egress Agent"
description = "Agent with a declared egress list"
version = "1.0.0"
egress = ["b.example.eu", "api.example.eu", "a.example.eu", " ", "a.example.eu"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "You are a research assistant."

[agent.limits]
monthly_budget_eur = 50.0

[[agent.mcp]]
name = "market-data"
transport = "http"
url = "https://api.example.eu/v1"
secrets = ["MARKET_TOKEN"]
"#;
        let spec = parse_manifest_v1(toml_str).unwrap();
        assert_eq!(spec.agent.mcp_servers[0].secrets, vec!["MARKET_TOKEN"]);
        let policy = derive_policy(&spec);
        // Union, sorted, deduplicated, blank dropped; the MCP host is not repeated.
        assert_eq!(
            policy.egress_allowlist,
            vec!["a.example.eu", "api.example.eu", "b.example.eu"]
        );
    }

    #[test]
    fn test_derive_policy_without_egress_is_unchanged() {
        // Both directions of the union: no `egress` key means the allowlist is exactly the MCP
        // hosts, as before this field existed.
        let toml_str = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "no-egress"
name = "No Egress"
description = "No declared egress"
version = "1.0.0"

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "x"

[agent.limits]
monthly_budget_eur = 50.0
"#;
        let spec = parse_manifest_v1(toml_str).unwrap();
        assert!(spec.agent.egress.is_empty());
        assert!(derive_policy(&spec).egress_allowlist.is_empty());
        // And the serialized form does not gain an `egress` key.
        assert!(!serde_json::to_string(&spec)
            .unwrap()
            .contains("\"egress\":"));
    }

    // Both-directions: grant_permits must fire on a resource/action outside
    // the grant set AND stay silent (permit) on one inside it. Rule 3.
    #[test]
    fn test_grant_permits_both_directions_exact_match() {
        let grants = vec![ResourceGrant::new(
            "google_workspace/list_calendar_events",
            vec!["invoke".to_string()],
        )];
        assert!(grant_permits(
            &grants,
            "google_workspace/list_calendar_events",
            "invoke"
        ));
        assert!(!grant_permits(
            &grants,
            "google_workspace/list_recent_emails",
            "invoke"
        ));
    }

    #[test]
    fn test_grant_permits_both_directions_action_mismatch() {
        let grants = vec![ResourceGrant::new(
            "slack/post_message",
            vec!["invoke".to_string()],
        )];
        assert!(grant_permits(&grants, "slack/post_message", "invoke"));
        assert!(!grant_permits(&grants, "slack/post_message", "delete"));
    }

    #[test]
    fn test_grant_permits_both_directions_prefix_wildcard() {
        let grants = vec![ResourceGrant::new(
            "google_workspace/*",
            vec!["invoke".to_string()],
        )];
        assert!(grant_permits(
            &grants,
            "google_workspace/list_calendar_events",
            "invoke"
        ));
        assert!(!grant_permits(&grants, "slack/post_message", "invoke"));
    }

    #[test]
    fn test_grant_permits_both_directions_global_wildcard() {
        let grants = vec![ResourceGrant::new("*", vec!["*".to_string()])];
        assert!(grant_permits(&grants, "anything/at_all", "any_action"));
        // Global wildcard still requires a non-empty grant list to exist --
        // proven by the next test, which uses an empty list.
    }

    #[test]
    fn test_grant_permits_empty_grant_list_denies_everything() {
        // Rule 2: fail closed. An empty grant list is deny-all, never
        // implicit-allow, matching the existing egress_allowlist precedent.
        let grants: Vec<ResourceGrant> = vec![];
        assert!(!grant_permits(
            &grants,
            "google_workspace/list_calendar_events",
            "invoke"
        ));
        assert!(!grant_permits(&grants, "*", "invoke"));
    }
}
