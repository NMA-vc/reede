//! Telemetry_probe + sufficiency_gate, report-only.
//!
//! **Generic by construction.** The design brief names a pilot vertical and a
//! telemetry dependency it says is blocked. As established in `inquiry.rs`'s
//! module doc comment, neither exists in this crate. This module is built
//! against a `TelemetrySource` trait instead of a concrete integration, so it
//! plugs into whichever vertical and telemetry stack actually gets decided
//! later instead of a fictional one invented here.
//!
//! **Report-only means exactly that.** `SufficiencyGate::decide` never
//! triggers an ask -- it returns a `ProbeReport` recording what it *would*
//! have decided, so the two-week ask-rate read the ticket calls for can
//! happen before any user ever sees a prompt.
//!
//! **What this module cannot do by itself:** the actual two-week
//! observation window against live pilot traffic. That needs a real
//! vertical wired to a real `TelemetrySource` and two calendar weeks of
//! production data -- an operational step, not a coding one. Shipping this
//! module is what makes that step possible once a vertical exists to run it
//! against; it does not simulate having already run it.

use crate::error::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One telemetry observation available to answer an inquiry without asking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetryObservation {
    pub key: String,
    pub value: serde_json::Value,
    pub observed_at: DateTime<Utc>,
}

/// Where telemetry_probe reads from. A real implementation wraps whichever
/// vertical's event pipeline ends up existing; `InMemoryTelemetrySource`
/// below is the reference/test implementation.
#[async_trait]
pub trait TelemetrySource: Send + Sync {
    async fn observations_for(
        &self,
        subject_id: &str,
    ) -> Result<Vec<TelemetryObservation>, ReedeError>;
}

/// Per-inquiry sufficiency policy: which telemetry keys, if all present,
/// mean the inquiry can be answered from telemetry alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SufficiencyPolicy {
    pub required_keys: Vec<String>,
    /// Per-inquiry cost ceiling in EUR, per the ticket's "also in scope"
    /// note: probe/draft/convergence/synthesis burn tokens and convergence
    /// and synthesis need a frontier model, so without a ceiling this is a
    /// line item worth killing once inquiries run across ten verticals.
    /// Carried here, enforced by whichever node spends against it --
    /// sufficiency checking itself is mechanical and spends nothing.
    pub cost_ceiling_eur: f64,
    /// BCP-47 locale for whichever node eventually phrases a question or
    /// synthesises an answer. Named explicitly rather than defaulted to
    /// "en": a probe run against a German-speaking vertical that silently
    /// assumed English would have already decided the wrong thing before
    /// synthesis ever saw a token.
    pub locale: String,
}

/// A report-only decision. Never triggers an ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SufficiencyDecision {
    /// Telemetry alone answers the inquiry; a real deployment would not ask.
    Sufficient,
    /// Telemetry does not answer it; a real deployment would ask. This gate
    /// itself never does -- see the module doc comment.
    WouldAsk,
}

/// One logged report-only decision, for the two-week ask-rate read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeReport {
    pub subject_id: String,
    pub decision: SufficiencyDecision,
    pub matched_keys: Vec<String>,
    pub decided_at: DateTime<Utc>,
}

pub struct SufficiencyGate<'a> {
    source: &'a dyn TelemetrySource,
    policy: SufficiencyPolicy,
}

impl<'a> SufficiencyGate<'a> {
    pub fn new(source: &'a dyn TelemetrySource, policy: SufficiencyPolicy) -> Self {
        Self { source, policy }
    }

    /// Decides and returns a report. Report-only: never asks anyone,
    /// regardless of the decision.
    pub async fn decide(
        &self,
        subject_id: &str,
        now: DateTime<Utc>,
    ) -> Result<ProbeReport, ReedeError> {
        let observations = self.source.observations_for(subject_id).await?;
        let present: std::collections::HashSet<&str> =
            observations.iter().map(|o| o.key.as_str()).collect();
        let matched: Vec<String> = self
            .policy
            .required_keys
            .iter()
            .filter(|k| present.contains(k.as_str()))
            .cloned()
            .collect();

        // A policy that requires nothing answers nothing -- treated as
        // "would ask", never as a free pass. An empty `required_keys` is a
        // misconfigured or not-yet-decided policy, not evidence telemetry
        // is sufficient.
        let decision = if !self.policy.required_keys.is_empty()
            && matched.len() == self.policy.required_keys.len()
        {
            SufficiencyDecision::Sufficient
        } else {
            SufficiencyDecision::WouldAsk
        };

        Ok(ProbeReport {
            subject_id: subject_id.to_string(),
            decision,
            matched_keys: matched,
            decided_at: now,
        })
    }
}

/// Reference/test implementation of `TelemetrySource`.
#[derive(Debug, Default)]
pub struct InMemoryTelemetrySource {
    by_subject: std::collections::HashMap<String, Vec<TelemetryObservation>>,
}

impl InMemoryTelemetrySource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_observation(
        mut self,
        subject_id: impl Into<String>,
        observation: TelemetryObservation,
    ) -> Self {
        self.by_subject
            .entry(subject_id.into())
            .or_default()
            .push(observation);
        self
    }
}

#[async_trait]
impl TelemetrySource for InMemoryTelemetrySource {
    async fn observations_for(
        &self,
        subject_id: &str,
    ) -> Result<Vec<TelemetryObservation>, ReedeError> {
        Ok(self.by_subject.get(subject_id).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(key: &str) -> TelemetryObservation {
        TelemetryObservation {
            key: key.to_string(),
            value: serde_json::json!(true),
            observed_at: Utc::now(),
        }
    }

    fn policy(required_keys: &[&str]) -> SufficiencyPolicy {
        SufficiencyPolicy {
            required_keys: required_keys.iter().map(|s| s.to_string()).collect(),
            cost_ceiling_eur: 0.05,
            locale: "de-DE".to_string(),
        }
    }

    #[tokio::test]
    async fn test_sufficient_when_all_required_keys_present() {
        let source = InMemoryTelemetrySource::new()
            .with_observation("sub_1", obs("completed_onboarding"))
            .with_observation("sub_1", obs("route_distance_km"));
        let gate = SufficiencyGate::new(
            &source,
            policy(&["completed_onboarding", "route_distance_km"]),
        );

        let report = gate.decide("sub_1", Utc::now()).await.unwrap();
        assert_eq!(report.decision, SufficiencyDecision::Sufficient);
        assert_eq!(report.matched_keys.len(), 2);
    }

    #[tokio::test]
    async fn test_would_ask_when_a_required_key_is_missing() {
        let source =
            InMemoryTelemetrySource::new().with_observation("sub_1", obs("completed_onboarding"));
        let gate = SufficiencyGate::new(
            &source,
            policy(&["completed_onboarding", "route_distance_km"]),
        );

        let report = gate.decide("sub_1", Utc::now()).await.unwrap();
        assert_eq!(report.decision, SufficiencyDecision::WouldAsk);
        assert_eq!(
            report.matched_keys,
            vec!["completed_onboarding".to_string()]
        );
    }

    #[tokio::test]
    async fn test_would_ask_never_asks_when_policy_requires_nothing() {
        // An empty required_keys policy is a misconfiguration, not evidence
        // of sufficiency -- must not silently pass as "Sufficient".
        let source = InMemoryTelemetrySource::new();
        let gate = SufficiencyGate::new(&source, policy(&[]));

        let report = gate.decide("sub_1", Utc::now()).await.unwrap();
        assert_eq!(report.decision, SufficiencyDecision::WouldAsk);
    }

    #[tokio::test]
    async fn test_unknown_subject_has_no_observations_and_would_ask() {
        let source = InMemoryTelemetrySource::new();
        let gate = SufficiencyGate::new(&source, policy(&["completed_onboarding"]));

        let report = gate.decide("sub_never_seen", Utc::now()).await.unwrap();
        assert_eq!(report.decision, SufficiencyDecision::WouldAsk);
        assert!(report.matched_keys.is_empty());
    }

    #[tokio::test]
    async fn test_locale_and_cost_ceiling_are_carried_through_the_policy_untouched() {
        let p = policy(&["k"]);
        assert_eq!(p.locale, "de-DE");
        assert_eq!(p.cost_ceiling_eur, 0.05);
    }
}
