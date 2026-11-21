//! Canonical MCP capability fingerprints and fail-closed approval gating.
//!
//! This is deliberately Reede-native: it describes a capability's public
//! surface without importing a host application MCP type. The managed control plane owns
//! persistence and authentication; this module owns the deterministic contract
//! and the in-memory reference implementation used to prove its semantics.

use crate::error::ReedeError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// The complete callable surface that requires a tenant approval.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityDescriptor {
    pub name: String,
    pub description: String,
    pub transport: String,
    /// Stable endpoint identity, not a resolved IP or a secret-bearing URL.
    pub endpoint: String,
    pub input_schema: Value,
    pub output_schema: Value,
}

impl CapabilityDescriptor {
    /// A SHA-256 fingerprint over the name, description, transport, endpoint,
    /// and canonicalized complete input/output schemas.
    pub fn fingerprint(&self) -> Result<String, ReedeError> {
        for (field, value) in [
            ("name", self.name.as_str()),
            ("transport", self.transport.as_str()),
            ("endpoint", self.endpoint.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(ReedeError::SpecValidationFailed {
                    reason: format!("capability {field} must not be empty"),
                });
            }
        }

        let canonical = serde_json::json!({
            "name": self.name,
            "description": self.description,
            "transport": self.transport,
            "endpoint": self.endpoint,
            "input_schema": canonicalize_json_schema(&self.input_schema),
            "output_schema": canonicalize_json_schema(&self.output_schema),
        });
        let encoded =
            serde_json::to_vec(&canonical).map_err(|error| ReedeError::SpecValidationFailed {
                reason: format!("cannot canonicalize capability '{}': {error}", self.name),
            })?;
        Ok(format!("sha256:{:x}", Sha256::digest(encoded)))
    }
}

/// Canonicalize JSON Schema without destroying ordering where JSON Schema makes
/// it meaningful (`prefixItems`, tuple validation, examples). Object keys are
/// always sorted; selected set-like schema arrays are sorted by canonical JSON.
pub fn canonicalize_json_schema(value: &Value) -> Value {
    canonicalize_value(value, None)
}

fn canonicalize_value(value: &Value, parent_key: Option<&str>) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = BTreeMap::new();
            for (key, child) in object {
                sorted.insert(key.clone(), canonicalize_value(child, Some(key)));
            }
            let mut result = Map::new();
            for (key, child) in sorted {
                result.insert(key, child);
            }
            Value::Object(result)
        }
        Value::Array(items) => {
            let mut canonical: Vec<Value> = items
                .iter()
                .map(|item| canonicalize_value(item, None))
                .collect();
            if is_set_like_schema_array(parent_key) {
                canonical.sort_by_key(canonical_json);
            }
            Value::Array(canonical)
        }
        _ => value.clone(),
    }
}

fn is_set_like_schema_array(key: Option<&str>) -> bool {
    matches!(
        key,
        Some("required" | "enum" | "type" | "allOf" | "anyOf" | "oneOf")
    )
}

fn canonical_json(value: &Value) -> String {
    // `value` has already been recursively canonicalized. Serialization cannot
    // fail for a serde_json::Value; an empty string is still deterministic if a
    // future serde_json implementation ever did report one.
    serde_json::to_string(value).unwrap_or_default()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityApprovalState {
    Approved,
    ApprovalRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityApproval {
    pub fingerprint: String,
    pub state: CapabilityApprovalState,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityChange {
    pub name: String,
    pub kind: CapabilityChangeKind,
    pub previous_fingerprint: Option<String>,
    pub current_fingerprint: Option<String>,
}

/// Result of comparing a proposed deploy/import to the tenant's approved
/// surface. Any non-empty `changes` list requires explicit approval before
/// affected capability calls can proceed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityReconciliation {
    pub changes: Vec<CapabilityChange>,
}

impl CapabilityReconciliation {
    pub fn is_unchanged(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Reference, concurrency-safe approval registry. Production persistence must
/// provide the same atomic compare/reconcile/approve behavior per tenant.
pub struct CapabilityApprovalRegistry {
    entries: Mutex<HashMap<(String, String), CapabilityApproval>>,
}

impl Default for CapabilityApprovalRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CapabilityApprovalRegistry {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Reconcile one complete capability set atomically. New or changed entries
    /// become `ApprovalRequired`; removed entries are deleted so stale calls
    /// fail closed and a later re-addition needs a fresh approval.
    pub fn reconcile(
        &self,
        tenant_id: &str,
        capabilities: &[CapabilityDescriptor],
    ) -> Result<CapabilityReconciliation, ReedeError> {
        let incoming = fingerprint_by_name(capabilities)?;
        let mut entries = self.entries.lock().unwrap();
        let existing: BTreeMap<String, CapabilityApproval> = entries
            .iter()
            .filter(|((tenant, _), _)| tenant == tenant_id)
            .map(|((_, name), approval)| (name.clone(), approval.clone()))
            .collect();

        let mut changes = Vec::new();
        for (name, prior) in &existing {
            if !incoming.contains_key(name) {
                entries.remove(&(tenant_id.to_string(), name.clone()));
                changes.push(CapabilityChange {
                    name: name.clone(),
                    kind: CapabilityChangeKind::Removed,
                    previous_fingerprint: Some(prior.fingerprint.clone()),
                    current_fingerprint: None,
                });
            }
        }

        for (name, fingerprint) in incoming {
            let key = (tenant_id.to_string(), name.clone());
            match entries.get(&key) {
                None => {
                    entries.insert(
                        key,
                        CapabilityApproval {
                            fingerprint: fingerprint.clone(),
                            state: CapabilityApprovalState::ApprovalRequired,
                            approved_by: None,
                            approved_at: None,
                        },
                    );
                    changes.push(CapabilityChange {
                        name,
                        kind: CapabilityChangeKind::Added,
                        previous_fingerprint: None,
                        current_fingerprint: Some(fingerprint),
                    });
                }
                Some(prior) if prior.fingerprint != fingerprint => {
                    let previous_fingerprint = prior.fingerprint.clone();
                    entries.insert(
                        key,
                        CapabilityApproval {
                            fingerprint: fingerprint.clone(),
                            state: CapabilityApprovalState::ApprovalRequired,
                            approved_by: None,
                            approved_at: None,
                        },
                    );
                    changes.push(CapabilityChange {
                        name,
                        kind: CapabilityChangeKind::Changed,
                        previous_fingerprint: Some(previous_fingerprint),
                        current_fingerprint: Some(fingerprint),
                    });
                }
                Some(_) => {}
            }
        }

        changes.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(CapabilityReconciliation { changes })
    }

    /// Approve exactly the fingerprint shown in a reconciliation diff. A stale
    /// approval cannot authorize a replacement that raced in after review.
    pub fn approve(
        &self,
        tenant_id: &str,
        capability: &str,
        expected_fingerprint: &str,
        approver: &str,
    ) -> Result<(), ReedeError> {
        if approver.trim().is_empty() {
            return Err(ReedeError::SpecValidationFailed {
                reason: "capability approver must not be empty".to_string(),
            });
        }
        let mut entries = self.entries.lock().unwrap();
        let entry = entries
            .get_mut(&(tenant_id.to_string(), capability.to_string()))
            .ok_or_else(|| ReedeError::CapabilityApprovalRequired {
                capability: capability.to_string(),
            })?;
        if entry.fingerprint != expected_fingerprint {
            return Err(ReedeError::CapabilityFingerprintMismatch {
                capability: capability.to_string(),
            });
        }
        entry.state = CapabilityApprovalState::Approved;
        entry.approved_by = Some(approver.to_string());
        entry.approved_at = Some(Utc::now());
        Ok(())
    }

    /// The call-time gate. Recompute the offered surface so a same-name tool
    /// replacement cannot use a prior approval.
    pub fn assert_call_allowed(
        &self,
        tenant_id: &str,
        capability: &CapabilityDescriptor,
    ) -> Result<(), ReedeError> {
        let fingerprint = capability.fingerprint()?;
        let entries = self.entries.lock().unwrap();
        let entry = entries
            .get(&(tenant_id.to_string(), capability.name.clone()))
            .ok_or_else(|| ReedeError::CapabilityApprovalRequired {
                capability: capability.name.clone(),
            })?;
        if entry.fingerprint != fingerprint {
            return Err(ReedeError::CapabilityFingerprintMismatch {
                capability: capability.name.clone(),
            });
        }
        if entry.state != CapabilityApprovalState::Approved {
            return Err(ReedeError::CapabilityApprovalRequired {
                capability: capability.name.clone(),
            });
        }
        Ok(())
    }

    pub fn approval(&self, tenant_id: &str, capability: &str) -> Option<CapabilityApproval> {
        self.entries
            .lock()
            .unwrap()
            .get(&(tenant_id.to_string(), capability.to_string()))
            .cloned()
    }
}

fn fingerprint_by_name(
    capabilities: &[CapabilityDescriptor],
) -> Result<BTreeMap<String, String>, ReedeError> {
    let mut result = BTreeMap::new();
    for capability in capabilities {
        let fingerprint = capability.fingerprint()?;
        if result
            .insert(capability.name.clone(), fingerprint)
            .is_some()
        {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!("duplicate capability name '{}'", capability.name),
            });
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn search_tool() -> CapabilityDescriptor {
        CapabilityDescriptor {
            name: "search".to_string(),
            description: "Search approved sources".to_string(),
            transport: "http".to_string(),
            endpoint: "https://search.example.test/mcp".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["query", "locale"],
                "properties": {
                    "locale": {"type": "string"},
                    "query": {"type": "string"}
                }
            }),
            output_schema: serde_json::json!({"type": "object", "properties": {"hits": {"type": "array"}}}),
        }
    }

    fn approve(registry: &CapabilityApprovalRegistry, tenant: &str, tool: &CapabilityDescriptor) {
        registry
            .reconcile(tenant, std::slice::from_ref(tool))
            .unwrap();
        registry
            .approve(
                tenant,
                &tool.name,
                &tool.fingerprint().unwrap(),
                "reviewer-1",
            )
            .unwrap();
    }

    #[test]
    fn description_only_drift_requires_reapproval() {
        let registry = CapabilityApprovalRegistry::new();
        let mut tool = search_tool();
        approve(&registry, "tenant-a", &tool);
        tool.description = "Search only approved EU sources".to_string();

        let reconciliation = registry.reconcile("tenant-a", &[tool.clone()]).unwrap();
        assert_eq!(
            reconciliation.changes[0].kind,
            CapabilityChangeKind::Changed
        );
        assert!(matches!(
            registry.assert_call_allowed("tenant-a", &tool),
            Err(ReedeError::CapabilityApprovalRequired { .. })
        ));
    }

    #[test]
    fn reordered_equivalent_json_schema_does_not_drift() {
        let a = search_tool();
        let mut b = search_tool();
        b.input_schema = serde_json::json!({
            "properties": {
                "query": {"type": "string"},
                "locale": {"type": "string"}
            },
            "required": ["locale", "query"],
            "type": "object"
        });
        assert_eq!(a.fingerprint().unwrap(), b.fingerprint().unwrap());
    }

    #[test]
    fn widening_and_narrowing_schema_both_drift() {
        let original = search_tool();
        let mut widened = original.clone();
        widened.input_schema["properties"]["limit"] = serde_json::json!({"type": "integer"});
        let mut narrowed = original.clone();
        narrowed.input_schema["required"] = serde_json::json!(["query"]);

        assert_ne!(
            original.fingerprint().unwrap(),
            widened.fingerprint().unwrap()
        );
        assert_ne!(
            original.fingerprint().unwrap(),
            narrowed.fingerprint().unwrap()
        );
    }

    #[test]
    fn endpoint_change_and_same_name_replacement_fail_closed() {
        let registry = CapabilityApprovalRegistry::new();
        let original = search_tool();
        approve(&registry, "tenant-a", &original);

        let mut replacement = original.clone();
        replacement.endpoint = "https://attacker.example.test/mcp".to_string();
        let reconciliation = registry
            .reconcile("tenant-a", &[replacement.clone()])
            .unwrap();
        assert_eq!(
            reconciliation.changes[0].kind,
            CapabilityChangeKind::Changed
        );
        assert!(matches!(
            registry.assert_call_allowed("tenant-a", &replacement),
            Err(ReedeError::CapabilityApprovalRequired { .. })
        ));
        assert!(matches!(
            registry.assert_call_allowed("tenant-a", &original),
            Err(ReedeError::CapabilityFingerprintMismatch { .. })
        ));
    }

    #[test]
    fn unchanged_redeploy_continues_without_reapproval() {
        let registry = CapabilityApprovalRegistry::new();
        let tool = search_tool();
        approve(&registry, "tenant-a", &tool);
        assert!(registry
            .reconcile("tenant-a", std::slice::from_ref(&tool))
            .unwrap()
            .is_unchanged());
        registry.assert_call_allowed("tenant-a", &tool).unwrap();
    }

    #[test]
    fn removed_capability_is_not_left_callable() {
        let registry = CapabilityApprovalRegistry::new();
        let tool = search_tool();
        approve(&registry, "tenant-a", &tool);
        let changes = registry.reconcile("tenant-a", &[]).unwrap();
        assert_eq!(changes.changes[0].kind, CapabilityChangeKind::Removed);
        assert!(matches!(
            registry.assert_call_allowed("tenant-a", &tool),
            Err(ReedeError::CapabilityApprovalRequired { .. })
        ));
    }

    #[test]
    fn concurrent_approval_and_call_never_admits_an_old_fingerprint() {
        let registry = Arc::new(CapabilityApprovalRegistry::new());
        let original = search_tool();
        approve(&registry, "tenant-a", &original);
        let mut replacement = original.clone();
        replacement.description = "Replacement surface".to_string();
        registry
            .reconcile("tenant-a", &[replacement.clone()])
            .unwrap();
        let fingerprint = replacement.fingerprint().unwrap();
        let barrier = Arc::new(Barrier::new(2));

        let approver_registry = registry.clone();
        let approver_barrier = barrier.clone();
        let approver = std::thread::spawn(move || {
            approver_barrier.wait();
            approver_registry.approve("tenant-a", "search", &fingerprint, "reviewer-2")
        });

        barrier.wait();
        let call_result = registry.assert_call_allowed("tenant-a", &replacement);
        approver.join().unwrap().unwrap();

        // The racing call may observe the gate before or after approval, but it
        // can never succeed under the old fingerprint.
        if call_result.is_err() {
            registry
                .assert_call_allowed("tenant-a", &replacement)
                .unwrap();
        }
        assert!(matches!(
            registry.assert_call_allowed("tenant-a", &original),
            Err(ReedeError::CapabilityFingerprintMismatch { .. })
        ));
    }
}
