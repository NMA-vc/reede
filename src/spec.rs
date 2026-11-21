use crate::error::ReedeError;
use crate::receipt::{
    encode_fields_injective, AuthorizationReceipt, ExecutionReceipt, ReceiptSigner, ReceiptStore,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MetaSection {
    pub schema_version: String,
    pub author: String,
    #[serde(default)]
    pub vertical: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModelSection {
    pub provider: String,
    pub name: String,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
}

fn default_temperature() -> f32 {
    0.3
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PromptSection {
    pub system: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub monthly_budget_eur: f64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout: String,
    #[serde(default = "default_max_concurrent_runs")]
    pub max_concurrent_runs: u32,
}

fn default_idle_timeout() -> String {
    "10m".to_string()
}

fn default_max_concurrent_runs() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AccessSection {
    pub visibility: String,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantSection {
    pub resource: String,
    #[serde(default = "default_grant_actions")]
    pub actions: Vec<String>,
}

fn default_grant_actions() -> Vec<String> {
    vec!["invoke".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpSection {
    pub name: String,
    pub transport: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
    /// Names (never values) of the secrets this server is given. The control-plane
    /// contract says the spec digest covers secret names
    /// (docs/reede/REEDE_CONTROL_PLANE_CONTRACT.md). Absent or empty is not serialized, so
    /// specs that never set it keep their existing serialized form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TriggerSection {
    #[serde(rename = "type")]
    pub trigger_type: String,
    #[serde(default)]
    pub cron: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentInner {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    #[serde(default = "default_base")]
    pub base: String,
    pub model: ModelSection,
    pub prompt: PromptSection,
    pub limits: LimitsSection,
    #[serde(default)]
    pub access: Option<AccessSection>,
    #[serde(default, rename = "mcp")]
    pub mcp_servers: Vec<McpSection>,
    #[serde(default)]
    pub skills: Vec<String>,
    /// per-capability rubrics (dimensions a skill can be judged on).
    /// Absent or empty means the capability has no declared rubric yet.
    #[serde(default)]
    pub rubrics: Vec<AgentRubric>,
    #[serde(default)]
    pub triggers: Vec<TriggerSection>,
    /// explicit per-run resource grants, the manifest surface
    /// `derive_policy` reads into `DerivedPolicy.resource_grants`. Absent
    /// or empty means the run's policy carries no grants -- fail-closed,
    /// not implicit-allow (rule 2).
    #[serde(default, rename = "grant")]
    pub grants: Vec<GrantSection>,
    /// Hostnames the run may reach, in addition to the hosts of the MCP server urls.
    /// `derive_policy` unions them into `DerivedPolicy.egress_allowlist`; absent or empty
    /// adds nothing (fail-closed). Not serialized when empty, so specs that never set it
    /// keep their existing serialized form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<String>,
}

fn default_base() -> String {
    "reede/agent-base".to_string()
}

/// One dimension an agent capability can be judged on. The rating
/// widget renders these labels and the reducers map signals onto them, so this
/// block is the single source of truth for a capability's dimensions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RubricDimension {
    /// Short stable id, e.g. "hook", "accuracy", "tone", "structure", "cta".
    pub id: String,
    /// Human label, e.g. "The Hook".
    pub label: String,
    /// What "good" means for this dimension.
    pub description: String,
    /// Relative weight (>= 0). Higher = more influential in aggregate scoring.
    pub weight: f64,
}

/// A declared rubric for one agent capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentRubric {
    /// Which capability the rubric judges. Must match one of `agent.skills`.
    pub capability: String,
    /// Rubric version. Judgements record which rubric version they
    /// were made under, so a later rubric edit never re-labels old judgements.
    pub version: String,
    #[serde(default)]
    pub dimensions: Vec<RubricDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentSpec {
    pub meta: MetaSection,
    pub agent: AgentInner,
}

pub fn parse_manifest_v1(toml_str: &str) -> Result<AgentSpec, ReedeError> {
    let spec: AgentSpec =
        toml::from_str(toml_str).map_err(|e| ReedeError::SpecValidationFailed {
            reason: format!("TOML parse error: {e}"),
        })?;

    // Provider policy belongs to the host; Reede only needs a name to be present.
    if spec.agent.model.provider.trim().is_empty() {
        return Err(ReedeError::SpecValidationFailed {
            reason: "Invalid model provider: must not be empty".to_string(),
        });
    }

    if spec.agent.limits.monthly_budget_eur <= 0.0 {
        return Err(ReedeError::SpecValidationFailed {
            reason: format!(
                "Invalid budget ceiling {:.2}: must be strictly greater than 0.0 EUR",
                spec.agent.limits.monthly_budget_eur
            ),
        });
    }

    validate_rubrics(&spec)?;

    Ok(spec)
}

/// validate every declared rubric block.
///   * a rubric's capability must be one of `agent.skills`
///   * a rubric must declare at least one dimension
///   * dimension ids must be unique within a rubric
///   * dimension weights must be finite and >= 0
fn validate_rubrics(spec: &AgentSpec) -> Result<(), ReedeError> {
    validate_rubric_set(&spec.agent.skills, &spec.agent.rubrics)
}

/// The rubric rules of [`parse_manifest_v1`] over a skill list and a rubric list, for a
/// caller that builds its rubrics without going through TOML (for example the agent.toml
/// projection). Same rules, same error text.
pub fn validate_rubric_set(skills: &[String], rubrics: &[AgentRubric]) -> Result<(), ReedeError> {
    for rubric in rubrics {
        if !skills.contains(&rubric.capability) {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "Rubric capability '{}' is not one of the agent's skills {:?}",
                    rubric.capability, skills
                ),
            });
        }
        if rubric.version.trim().is_empty() {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "Rubric for capability '{}' must declare a non-empty version",
                    rubric.capability
                ),
            });
        }
        if rubric.dimensions.is_empty() {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "Rubric for capability '{}' must declare at least one dimension",
                    rubric.capability
                ),
            });
        }
        let mut seen = std::collections::HashSet::new();
        for d in &rubric.dimensions {
            if !seen.insert(d.id.as_str()) {
                return Err(ReedeError::SpecValidationFailed {
                    reason: format!(
                        "Rubric '{}' declares duplicate dimension id '{}'",
                        rubric.capability, d.id
                    ),
                });
            }
            if !d.weight.is_finite() || d.weight < 0.0 {
                return Err(ReedeError::SpecValidationFailed {
                    reason: format!(
                        "Rubric '{}' dimension '{}' weight {} must be finite and >= 0",
                        rubric.capability, d.id, d.weight
                    ),
                });
            }
        }
    }
    Ok(())
}

pub fn import_spec(toml_str: &str) -> Result<AgentSpec, ReedeError> {
    parse_manifest_v1(toml_str)
}

pub fn clone_spec(spec: &AgentSpec, new_id: &str) -> AgentSpec {
    let mut cloned = spec.clone();
    cloned.agent.id = new_id.to_string();
    cloned.agent.name = format!("{} (Clone)", spec.agent.name);
    cloned
}

#[async_trait]
pub trait SpecStore: Send + Sync {
    async fn push_version(&self, spec: AgentSpec) -> Result<u32, ReedeError>;
    async fn get_version(&self, agent_id: &str, version: u32) -> Result<AgentSpec, ReedeError>;
    async fn diff_versions(&self, agent_id: &str, v1: u32, v2: u32) -> Result<String, ReedeError>;
    async fn rollback_to(&self, agent_id: &str, version: u32) -> Result<AgentSpec, ReedeError>;
    async fn reload_prompt(
        &self,
        agent_id: &str,
        new_system_prompt: &str,
        signer: &dyn ReceiptSigner,
        store: &dyn ReceiptStore,
        tenant_id: &str,
    ) -> Result<AuthorizationReceipt, ReedeError>;
}

pub struct InMemorySpecStore {
    versions: Mutex<HashMap<String, Vec<AgentSpec>>>,
}

impl InMemorySpecStore {
    pub fn new() -> Self {
        Self {
            versions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySpecStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SpecStore for InMemorySpecStore {
    async fn push_version(&self, spec: AgentSpec) -> Result<u32, ReedeError> {
        let mut versions = self.versions.lock().unwrap();
        let list = versions.entry(spec.agent.id.clone()).or_default();
        list.push(spec);
        Ok(list.len() as u32)
    }

    async fn get_version(&self, agent_id: &str, version: u32) -> Result<AgentSpec, ReedeError> {
        let versions = self.versions.lock().unwrap();
        let list = versions
            .get(agent_id)
            .ok_or_else(|| ReedeError::SpecValidationFailed {
                reason: format!("Agent ID '{agent_id}' not found in SpecStore"),
            })?;

        if version == 0 || version as usize > list.len() {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!("Version {version} not found for agent '{agent_id}'"),
            });
        }

        Ok(list[(version - 1) as usize].clone())
    }

    async fn diff_versions(&self, agent_id: &str, v1: u32, v2: u32) -> Result<String, ReedeError> {
        let spec1 = self.get_version(agent_id, v1).await?;
        let spec2 = self.get_version(agent_id, v2).await?;

        let prompt1 = &spec1.agent.prompt.system;
        let prompt2 = &spec2.agent.prompt.system;

        Ok(format!(
            "--- v{v1} system prompt ---\n{prompt1}\n+++ v{v2} system prompt +++\n{prompt2}"
        ))
    }

    async fn rollback_to(&self, agent_id: &str, version: u32) -> Result<AgentSpec, ReedeError> {
        let target = self.get_version(agent_id, version).await?;
        self.push_version(target.clone()).await?;
        Ok(target)
    }

    async fn reload_prompt(
        &self,
        agent_id: &str,
        new_system_prompt: &str,
        signer: &dyn ReceiptSigner,
        store: &dyn ReceiptStore,
        tenant_id: &str,
    ) -> Result<AuthorizationReceipt, ReedeError> {
        let mut current = {
            let versions = self.versions.lock().unwrap();
            let list = versions
                .get(agent_id)
                .ok_or_else(|| ReedeError::SpecValidationFailed {
                    reason: format!("Agent ID '{agent_id}' not found in SpecStore"),
                })?;
            list.last()
                .cloned()
                .ok_or_else(|| ReedeError::SpecValidationFailed {
                    reason: format!("No version found for agent '{agent_id}'"),
                })?
        };

        current.agent.prompt.system = new_system_prompt.to_string();
        let _new_v = self.push_version(current.clone()).await?;

        // Emit AuthorizationReceipt documenting prompt hot reload
        let task_id = Uuid::new_v4();
        let latest_hash = store.latest_hash(tenant_id).await?;
        let payload_summary = format!("Prompt hot reload for agent {agent_id}");

        let prev_hash_str = latest_hash.as_deref().unwrap_or("");
        let task_id_str = task_id.to_string();
        let fields = vec![
            tenant_id,
            task_id_str.as_str(),
            payload_summary.as_str(),
            "0", // credits_spent
            "0", // tokens_used
            "0", // reservation_credits
            prev_hash_str,
        ];

        let canonical_bytes = encode_fields_injective(&fields);
        let content_hash = hex::encode(Sha256::digest(&canonical_bytes));
        let sig_bytes = signer.sign(content_hash.as_bytes())?;

        let execution = ExecutionReceipt {
            task_id,
            tenant_id: tenant_id.to_string(),
            sequence_no: 2000,
            credits_spent: 0,
            tokens_used: 0,
            reservation_credits: 0,
            content_hash,
            prev_hash: latest_hash,
            signature: hex::encode(sig_bytes),
            tsa_token: None,
            timestamp: Utc::now(),
            payload_summary,
            format: None,
            subject_id: None,
            signer_key_id: None,
        };

        store.append(execution.clone()).await?;

        Ok(AuthorizationReceipt {
            execution,
            lease_id: None,
            policy_ref: format!("policy-{agent_id}"),
            decision_context: format!("Hot-reloaded system prompt to: {new_system_prompt}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{InMemoryReceiptSigner, InMemoryReceiptStore};

    #[test]
    fn test_valid_manifest_v1_parsing() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "market-researcher"
name = "Market Researcher"
description = "EU market research agent"
version = "1.0.0"
base = "reede/agent-base"

[agent.model]
provider = "cortecs"
name = "cortecs-default"
temperature = 0.3

[agent.prompt]
system = "You are a market research assistant."

[agent.limits]
monthly_budget_eur = 200.0

[[agent.mcp]]
name = "market-data"
transport = "http"
url = "https://api.example.eu/v1"
"#;
        let spec = parse_manifest_v1(toml_data).expect("Should parse valid TOML");
        assert_eq!(spec.agent.id, "market-researcher");
        assert_eq!(spec.agent.model.provider, "cortecs");
        assert_eq!(spec.agent.limits.monthly_budget_eur, 200.0);
    }

    #[test]
    fn test_manifest_v1_parses_resource_grants() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "grant-agent"
name = "Grant Agent"
description = "Agent with explicit resource grants"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "You are a research assistant."

[agent.limits]
monthly_budget_eur = 50.0

[[agent.grant]]
resource = "google_workspace/list_calendar_events"

[[agent.grant]]
resource = "slack/*"
actions = ["invoke", "read"]
"#;
        let spec = parse_manifest_v1(toml_data).expect("Should parse valid TOML with grants");
        assert_eq!(spec.agent.grants.len(), 2);
        assert_eq!(
            spec.agent.grants[0].resource,
            "google_workspace/list_calendar_events"
        );
        // actions omitted -> defaults to ["invoke"]
        assert_eq!(spec.agent.grants[0].actions, vec!["invoke"]);
        assert_eq!(spec.agent.grants[1].resource, "slack/*");
        assert_eq!(spec.agent.grants[1].actions, vec!["invoke", "read"]);
    }

    #[test]
    fn test_manifest_v1_without_grants_defaults_to_empty() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "no-grant-agent"
name = "No Grant Agent"
description = "Agent without a grants section"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "prompt"

[agent.limits]
monthly_budget_eur = 50.0
"#;
        let spec = parse_manifest_v1(toml_data).expect("Should parse valid TOML without grants");
        assert!(spec.agent.grants.is_empty());
    }

    #[test]
    fn test_clone_spec() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "orig-agent"
name = "Original Agent"
description = "Original spec"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "prompt"

[agent.limits]
monthly_budget_eur = 100.0
"#;
        let spec = parse_manifest_v1(toml_data).unwrap();
        let cloned = clone_spec(&spec, "cloned-agent");
        assert_eq!(cloned.agent.id, "cloned-agent");
        assert_eq!(cloned.agent.name, "Original Agent (Clone)");
    }

    #[tokio::test]
    async fn test_spec_store_versioning_and_hot_reload() {
        let store = InMemorySpecStore::new();
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "vers-agent"
name = "Versioned Agent"
description = "Versioned spec"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "Version 1 prompt"

[agent.limits]
monthly_budget_eur = 100.0
"#;
        let spec = parse_manifest_v1(toml_data).unwrap();
        let v1 = store.push_version(spec).await.unwrap();
        assert_eq!(v1, 1);

        let signer = InMemoryReceiptSigner::generate_random();
        let receipt_store = InMemoryReceiptStore::new();

        let auth_receipt = store
            .reload_prompt(
                "vers-agent",
                "Version 2 prompt",
                &signer,
                &receipt_store,
                "tenant-x",
            )
            .await
            .unwrap();

        assert_eq!(auth_receipt.execution.tenant_id, "tenant-x");
        assert!(auth_receipt.decision_context.contains("Version 2 prompt"));

        let diff = store.diff_versions("vers-agent", 1, 2).await.unwrap();
        assert!(diff.contains("Version 1 prompt"));
        assert!(diff.contains("Version 2 prompt"));
    }

    #[test]
    fn test_manifest_v1_two_capabilities_with_real_rubrics() {
        // Acceptance: two different capabilities have real rubrics.
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "content-agent"
name = "Content Agent"
description = "Agent with per-capability rubrics"
version = "1.0.0"
skills = ["copy", "code"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "You are a content writer."

[agent.limits]
monthly_budget_eur = 200.0

[[agent.rubrics]]
capability = "copy"
version = "2026-08-07-r1"

[[agent.rubrics.dimensions]]
id = "hook"
label = "The Hook"
description = "Opening that pulls the reader in"
weight = 1.0

[[agent.rubrics.dimensions]]
id = "accuracy"
label = "Accuracy"
description = "Correct and verifiable claims"
weight = 1.5

[[agent.rubrics.dimensions]]
id = "tone"
label = "Tone"
description = "Matches the brand voice"
weight = 0.5

[[agent.rubrics]]
capability = "code"
version = "2026-08-07-r1"

[[agent.rubrics.dimensions]]
id = "correctness"
label = "Correctness"
description = "Runs and behaves correctly"
weight = 1.0

[[agent.rubrics.dimensions]]
id = "test_coverage"
label = "Test Coverage"
description = "Edge cases are covered"
weight = 0.8
"#;
        let spec = parse_manifest_v1(toml_data).expect("should parse valid rubrics");
        assert_eq!(spec.agent.rubrics.len(), 2);

        let copy = spec
            .agent
            .rubrics
            .iter()
            .find(|r| r.capability == "copy")
            .expect("copy rubric present");
        assert_eq!(copy.version, "2026-08-07-r1");
        assert_eq!(copy.dimensions.len(), 3);
        assert_eq!(copy.dimensions[0].id, "hook");
        assert_eq!(copy.dimensions[1].weight, 1.5);

        let code = spec
            .agent
            .rubrics
            .iter()
            .find(|r| r.capability == "code")
            .expect("code rubric present");
        assert_eq!(code.dimensions.len(), 2);
        assert!(code.dimensions.iter().any(|d| d.id == "test_coverage"));
    }

    #[test]
    fn test_manifest_v1_rejects_rubric_duplicate_dimension_id() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "dup-agent"
name = "Dup Agent"
description = "Agent with duplicate rubric dimensions"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "prompt"

[agent.limits]
monthly_budget_eur = 50.0

[[agent.rubrics]]
capability = "copy"
version = "v1"

[[agent.rubrics.dimensions]]
id = "hook"
label = "Hook"
description = "d"
weight = 1.0

[[agent.rubrics.dimensions]]
id = "hook"
label = "Hook again"
description = "duplicate"
weight = 1.0
"#;
        let err = parse_manifest_v1(toml_data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate dimension id 'hook'"), "got: {msg}");
    }

    #[test]
    fn test_manifest_v1_rejects_rubric_negative_weight() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "weight-agent"
name = "Weight Agent"
description = "Agent with negative rubric weight"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "prompt"

[agent.limits]
monthly_budget_eur = 50.0

[[agent.rubrics]]
capability = "copy"
version = "v1"

[[agent.rubrics.dimensions]]
id = "hook"
label = "Hook"
description = "d"
weight = -1.0
"#;
        let err = parse_manifest_v1(toml_data).unwrap_err();
        assert!(err.to_string().contains("weight -1"));
    }

    #[test]
    fn test_manifest_v1_rejects_rubric_for_unknown_capability() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "mismatch-agent"
name = "Mismatch Agent"
description = "Rubric references a skill that does not exist"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "prompt"

[agent.limits]
monthly_budget_eur = 50.0

[[agent.rubrics]]
capability = "code"
version = "v1"

[[agent.rubrics.dimensions]]
id = "correctness"
label = "Correctness"
description = "d"
weight = 1.0
"#;
        let err = parse_manifest_v1(toml_data).unwrap_err();
        assert!(err.to_string().contains("not one of the agent's skills"));
    }

    #[test]
    fn test_manifest_v1_rejects_empty_rubric_dimensions() {
        let toml_data = r#"
[meta]
schema_version = "1"
author = "founder"

[agent]
id = "empty-rubric-agent"
name = "Empty Rubric Agent"
description = "Rubric with no dimensions"
version = "1.0.0"
skills = ["copy"]

[agent.model]
provider = "cortecs"
name = "cortecs-default"

[agent.prompt]
system = "prompt"

[agent.limits]
monthly_budget_eur = 50.0

[[agent.rubrics]]
capability = "copy"
version = "v1"
"#;
        let err = parse_manifest_v1(toml_data).unwrap_err();
        assert!(err.to_string().contains("at least one dimension"));
    }

    const VALID_MANIFEST_FOR_PROVIDER: &str = r#"
[meta]
schema_version = "1"
author = "t"

[agent]
id = "a"
name = "A"
description = "d"
version = "1.0.0"
base = "reede/agent-base"

[agent.model]
provider = "cortecs"
name = "cortecs-default"
temperature = 0.3

[agent.prompt]
system = "s"

[agent.limits]
monthly_budget_eur = 10.0
"#;

    #[test]
    fn any_non_empty_provider_is_accepted_and_empty_is_refused() {
        let base = VALID_MANIFEST_FOR_PROVIDER;
        for p in ["cortecs", "example-llm", "other"] {
            let t = base.replace("provider = \"cortecs\"", &format!("provider = \"{p}\""));
            assert_eq!(parse_manifest_v1(&t).unwrap().agent.model.provider, p);
        }
        let t = base.replace("provider = \"cortecs\"", "provider = \"\"");
        assert!(parse_manifest_v1(&t).is_err());
    }

    #[test]
    fn omitted_base_defaults_to_the_neutral_image() {
        let t = VALID_MANIFEST_FOR_PROVIDER.replace("base = \"reede/agent-base\"\n", "");
        assert_eq!(
            parse_manifest_v1(&t).unwrap().agent.base,
            "reede/agent-base"
        );
    }
}
