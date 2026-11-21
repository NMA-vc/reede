//! What a stable role key is (decision D2).
//!
//! A memory is scoped to a role, so the role needs an identity that is *the same
//! thing on two different runs*. Nothing in the tree provided one: takeln's
//! `DAGNode` carries a `Uuid` minted per DAG build, which is fresh every run, and
//! `step_type` is a free `String` with nothing constraining its values.
//!
//! D2's answer: the role key is the agent's declared **capability** plus the DAG
//! node's **`step_type`**, validated against a per-agent allowlist **at DAG build
//! time**.
//!
//! ## Why an allowlist, and why at build time
//!
//! It converts the failure mode, which is the whole point. An unregistered or
//! mistyped role is otherwise a memory scope that looks perfectly fine and quietly
//! retrieves nothing -- corrections accumulate in `summarizer` while every read
//! goes to `summariser`, and nothing anywhere goes red. Validated at build time it
//! is one loud error, once. Given that the reflection loop is built entirely on
//! attribution, a silently wrong scope is the most expensive bug available here.
//!
//! ## Canonical form
//!
//! `"<capability>/<step_type>"`. `Signal::role` stays an `Option<String>` holding
//! exactly this, so nothing downstream has to learn a new type to store or index a
//! role -- but every string that gets there came through [`RoleKey`], which is what
//! keeps the vocabulary from drifting.
//!
//! The separator is why the segment charset is restricted rather than free: a `/`
//! inside a capability would make `"a/b/c"` parse two ways, and a key that parses
//! ambiguously is a key that can collide with another role's scope.

use crate::error::ReedeError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// The separator between the two segments of a canonical role key.
pub const ROLE_KEY_SEPARATOR: char = '/';

/// A stable role identity: the agent's declared capability plus a DAG step type.
///
/// Stable across runs by construction: both halves are declared, neither is minted
/// per execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RoleKey {
    capability: String,
    step_type: String,
}

impl RoleKey {
    /// Build a key, rejecting anything that cannot round-trip through the canonical
    /// form.
    ///
    /// Validation is on construction rather than on use so an invalid key cannot
    /// exist to be passed around. Both segments are normalised to lowercase: a role
    /// is a scope identity, and `Summarizer` and `summarizer` being two scopes is
    /// the silent-divergence bug this type exists to prevent.
    pub fn new(
        capability: impl Into<String>,
        step_type: impl Into<String>,
    ) -> Result<Self, ReedeError> {
        let capability = normalise_segment("capability", capability.into())?;
        let step_type = normalise_segment("step_type", step_type.into())?;
        Ok(Self {
            capability,
            step_type,
        })
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn step_type(&self) -> &str {
        &self.step_type
    }

    /// The canonical string, which is what `Signal::role` carries.
    pub fn as_key(&self) -> String {
        format!(
            "{}{}{}",
            self.capability, ROLE_KEY_SEPARATOR, self.step_type
        )
    }

    /// Recover a key from its canonical form.
    ///
    /// Needed to read a role back off a stored signal and know which scope it
    /// names. Round-trips with [`RoleKey::as_key`] for every value this type can
    /// hold, which is the property the segment charset buys.
    pub fn parse(key: &str) -> Result<Self, ReedeError> {
        let mut parts = key.splitn(2, ROLE_KEY_SEPARATOR);
        let capability = parts.next().unwrap_or_default();
        let Some(step_type) = parts.next() else {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "role key {key:?} is not '<capability>{ROLE_KEY_SEPARATOR}<step_type>'"
                ),
            });
        };
        Self::new(capability, step_type)
    }
}

impl fmt::Display for RoleKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_key())
    }
}

/// Check one segment and lowercase it.
///
/// Deliberately narrow: lowercase letters, digits, `-` and `_`. Not a style rule --
/// `/` would make the canonical form ambiguous, whitespace and case make two
/// spellings of one role, and both produce a scope that silently diverges from the
/// one being read.
fn normalise_segment(field: &str, value: String) -> Result<String, ReedeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ReedeError::SpecValidationFailed {
            reason: format!("role key {field} is empty"),
        });
    }
    let lowered = trimmed.to_ascii_lowercase();
    if let Some(bad) = lowered
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
    {
        return Err(ReedeError::SpecValidationFailed {
            reason: format!(
                "role key {field} {trimmed:?} contains {bad:?}; \
                 only a-z, 0-9, '-' and '_' are allowed"
            ),
        });
    }
    Ok(lowered)
}

/// The step vocabulary a **producer** may stamp, for feedback that comes from
/// outside a DAG (decision D6).
///
/// [`RoleRegistry`] answers "which step types may run under *this agent*", which is
/// the right question when a DAG node produced the output and a manifest declared
/// the allowlist. It is the wrong question — and unanswerable — for a producer with
/// no graph behind it. Some hosts decide approvals through a stateless gatekeeper and
/// never resumes a graph, so there is no node to name, and every correction it
/// emitted was therefore stored unattributed and could never promote. That is not a
/// quirk of one host: it is true of any surface where a human touches an artifact
/// outside a DAG run.
///
/// The observation that makes this cheap: **the capability is already there**. Every
/// signal carries one, it is required, and the cohort aggregation already keys on
/// it. What was missing is only the other half — *which part* of the work the human
/// touched. For a producer, that half is a property of the producer itself, not of
/// the run: diff capture always means "a human edited the draft this run produced",
/// whatever the capability happens to be.
///
/// So a producer declares its steps once, and the capability arrives on the signal:
///
/// ```
/// # use reede::ProducerRoles;
/// let diff_capture = ProducerRoles::new("diff-capture", ["draft"]).unwrap();
/// assert_eq!(
///     diff_capture.role_for("meeting", "draft").unwrap().as_key(),
///     "meeting/draft"
/// );
/// ```
///
/// ## How this differs from D2, deliberately
///
/// D2 says a role key is a *declared* capability plus a DAG node's step type,
/// allowlisted at build time. Here the capability is not declared — it is product
/// data flowing through the signal. That is a real divergence and is written up in
/// D6 rather than smuggled in.
///
/// The property D2 exists to protect survives, because it protects against the wrong
/// half drifting. A mistyped scope is a scope that silently retrieves nothing, and
/// typos happen where a developer types a literal: the step. That half is declared
/// in one place and validated here. The capability half is data the system already
/// trusts to key cohorts, so stamping a role adds no new trust in it.
///
/// What this is *not* is an invented role. D5 forbids inventing one to make a signal
/// promotable, and rightly. "A human edited the draft this run produced" is a
/// checkable statement about what happened, recorded by the surface that captured
/// it — which is why a signal stamped this way is `Explicit` and not `Inferred`.
/// The claim is about the *stage*, never about which section of the text changed;
/// that finer attribution is `correction::correction_signals`' job and needs a
/// sectioned diff this does not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerRoles {
    source: String,
    steps: BTreeSet<String>,
}

impl ProducerRoles {
    /// Declare a producer and the steps it may stamp.
    ///
    /// Rejects an empty step set for the same reason [`RoleRegistry`] does: empty
    /// means nothing is allowed, never everything. A producer that declares no steps
    /// has nothing to stamp, and reading that as "any step" would hand every typo
    /// its own scope.
    pub fn new<I, S>(source: impl Into<String>, steps: I) -> Result<Self, ReedeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let source = normalise_segment("source", source.into())?;
        let mut declared = BTreeSet::new();
        for step in steps {
            declared.insert(normalise_segment("step_type", step.into())?);
        }
        if declared.is_empty() {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!("producer {source:?} declares no steps, so it can stamp no role"),
            });
        }
        Ok(Self {
            source,
            steps: declared,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// The declared steps, in a stable order.
    pub fn steps(&self) -> impl Iterator<Item = &str> {
        self.steps.iter().map(String::as_str)
    }

    /// The role key for a capability at one of this producer's declared steps.
    ///
    /// Returns the key rather than a bool, for the reason [`RoleRegistry::resolve`]
    /// does: the only way to obtain a validated key is through the allowlist, so a
    /// caller cannot check one thing and then stamp another.
    pub fn role_for(&self, capability: &str, step: &str) -> Result<RoleKey, ReedeError> {
        let key = RoleKey::new(capability, step)?;
        if !self.steps.contains(key.step_type()) {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "step {:?} is not declared by producer {:?} (declared: {})",
                    key.step_type(),
                    self.source,
                    self.steps
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        Ok(key)
    }
}

/// The per-agent allowlist of roles that may exist.
///
/// One capability plus the step types declared under it. Empty means **nothing is
/// allowed**, never everything (reede/CLAUDE.md rule 2): an agent that declared no
/// roles has no role-scoped memory, and reading an empty registry as
/// "unconstrained" would hand every typo its own scope -- exactly the failure this
/// is here to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleRegistry {
    capability: String,
    step_types: BTreeSet<String>,
}

impl RoleRegistry {
    /// Declare a capability and the step types that may run under it.
    ///
    /// Every entry goes through [`RoleKey::new`], so a registry cannot be built
    /// around a role key that could never be constructed at emit time.
    pub fn new<I, S>(capability: impl Into<String>, step_types: I) -> Result<Self, ReedeError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let capability = normalise_segment("capability", capability.into())?;
        let mut declared = BTreeSet::new();
        for step_type in step_types {
            declared.insert(normalise_segment("step_type", step_type.into())?);
        }
        Ok(Self {
            capability,
            step_types: declared,
        })
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// The declared step types, in a stable order.
    pub fn step_types(&self) -> impl Iterator<Item = &str> {
        self.step_types.iter().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.step_types.is_empty()
    }

    /// Resolve a step type to its role key, or fail.
    ///
    /// This is the build-time gate D2 asks for. It returns the key rather than a
    /// bare `bool` so the only way to obtain a validated role key is to pass
    /// through the allowlist -- a caller cannot check and then construct something
    /// else.
    pub fn resolve(&self, step_type: &str) -> Result<RoleKey, ReedeError> {
        let key = RoleKey::new(self.capability.clone(), step_type)?;
        if !self.step_types.contains(key.step_type()) {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "step type {:?} is not a declared role of capability {:?} \
                     (declared: {})",
                    key.step_type(),
                    self.capability,
                    if self.step_types.is_empty() {
                        "none".to_string()
                    } else {
                        self.step_types
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ),
            });
        }
        Ok(key)
    }

    /// Validate a whole DAG's step types at once, reporting **every** offender.
    ///
    /// One error per build rather than one per rebuild: fixing a five-typo DAG
    /// should not take five failed builds to discover.
    pub fn validate_all<'a, I>(&self, step_types: I) -> Result<Vec<RoleKey>, ReedeError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut keys = Vec::new();
        let mut problems = Vec::new();
        for step_type in step_types {
            match self.resolve(step_type) {
                Ok(key) => keys.push(key),
                Err(error) => problems.push(error.to_string()),
            }
        }
        if !problems.is_empty() {
            return Err(ReedeError::SpecValidationFailed {
                reason: problems.join("; "),
            });
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    // ── ProducerRoles (D6) ────────────────────────────────────────────────────

    use super::ProducerRoles;

    fn diff_capture() -> ProducerRoles {
        ProducerRoles::new("diff-capture", ["draft"]).unwrap()
    }

    /// The point of the type: the capability comes from the signal, the step from
    /// the producer, and together they make a key no DAG had to supply.
    #[test]
    fn a_producer_stamps_a_role_for_any_capability() {
        let p = diff_capture();
        for capability in ["meeting", "opportunity", "council-summary"] {
            assert_eq!(
                p.role_for(capability, "draft").unwrap().as_key(),
                format!("{capability}/draft")
            );
        }
    }

    /// The allowlist half that D2 exists to protect: a step nobody declared is
    /// refused, so a typo cannot open a scope that silently retrieves nothing.
    #[test]
    fn an_undeclared_step_is_refused_and_says_what_is_declared() {
        let err = diff_capture().role_for("meeting", "drafft").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("drafft"), "{text}");
        assert!(text.contains("diff-capture"), "{text}");
        assert!(text.contains("draft"), "names what IS declared: {text}");
    }

    /// Empty means nothing is allowed, never everything — same rule as
    /// `RoleRegistry`, and the reason is the same.
    #[test]
    fn a_producer_declaring_no_steps_is_refused() {
        assert!(ProducerRoles::new("diff-capture", Vec::<String>::new()).is_err());
    }

    /// Both halves normalise, so `Meeting` and `meeting` cannot become two scopes.
    #[test]
    fn both_halves_are_normalised_so_one_role_has_one_spelling() {
        let p = ProducerRoles::new("Diff-Capture", ["Draft"]).unwrap();
        assert_eq!(p.source(), "diff-capture");
        assert_eq!(
            p.role_for("Meeting", "DRAFT").unwrap().as_key(),
            "meeting/draft"
        );
        assert_eq!(
            p.role_for("  meeting  ", "draft").unwrap().as_key(),
            "meeting/draft"
        );
    }

    /// A capability that cannot be a segment is refused rather than silently
    /// mangled — it arrives as product data, so this is the boundary that checks it.
    #[test]
    fn a_capability_that_cannot_be_a_segment_is_refused() {
        for bad in ["", "  ", "meeting/notes", "meeting notes", "meeting.notes"] {
            assert!(
                diff_capture().role_for(bad, "draft").is_err(),
                "should refuse capability {bad:?}"
            );
        }
    }

    /// The key a producer stamps has to round-trip, or a reader cannot tell which
    /// scope it names.
    #[test]
    fn a_stamped_key_round_trips_through_parse() {
        let key = diff_capture().role_for("meeting", "draft").unwrap();
        assert_eq!(RoleKey::parse(&key.as_key()).unwrap(), key);
    }

    use super::*;

    fn registry() -> RoleRegistry {
        RoleRegistry::new(
            "council-summary",
            ["product", "account-history", "consensus"],
        )
        .unwrap()
    }

    // D2's acceptance criterion, directly: the same logical role produces the same
    // key across two runs of the same DAG.
    #[test]
    fn the_same_role_is_the_same_key_on_a_second_run() {
        let first = registry().resolve("product").unwrap();
        let second = registry().resolve("product").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.as_key(), "council-summary/product");
    }

    // D2's other half: a role absent from the allowlist fails, loudly.
    #[test]
    fn an_undeclared_role_is_rejected() {
        let error = registry().resolve("billing").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("billing"), "{message}");
        assert!(
            message.contains("product"),
            "the error must name what IS declared, or it is not actionable: {message}"
        );
    }

    #[test]
    fn a_typo_is_rejected_rather_than_minting_a_second_scope() {
        // The exact bug the allowlist exists for: this would otherwise be a fresh
        // memory scope that accumulates corrections nobody ever retrieves.
        assert!(registry().resolve("prodcut").is_err());
    }

    #[test]
    fn an_empty_registry_allows_nothing() {
        let empty = RoleRegistry::new("council-summary", Vec::<String>::new()).unwrap();
        assert!(empty.is_empty());
        assert!(
            empty.resolve("product").is_err(),
            "empty means nothing allowed, never everything"
        );
    }

    #[test]
    fn case_and_padding_do_not_create_a_second_scope() {
        let registry = RoleRegistry::new("Council-Summary", ["Product"]).unwrap();
        assert_eq!(
            registry.resolve("  PRODUCT  ").unwrap().as_key(),
            "council-summary/product"
        );
    }

    #[test]
    fn a_key_round_trips_through_its_canonical_form() {
        let key = registry().resolve("account-history").unwrap();
        assert_eq!(RoleKey::parse(&key.as_key()).unwrap(), key);
    }

    #[test]
    fn a_separator_inside_a_segment_is_rejected() {
        // Otherwise "a/b/c" parses two ways and two roles can collide on one scope.
        assert!(RoleKey::new("a/b", "c").is_err());
        assert!(RoleKey::new("a", "b/c").is_err());
    }

    #[test]
    fn a_key_without_a_separator_does_not_parse() {
        assert!(RoleKey::parse("council-summary").is_err());
    }

    #[test]
    fn empty_segments_are_rejected() {
        assert!(RoleKey::new("", "product").is_err());
        assert!(RoleKey::new("council-summary", "  ").is_err());
        assert!(RoleKey::parse("/product").is_err());
        assert!(RoleKey::parse("council-summary/").is_err());
    }

    #[test]
    fn validating_a_whole_dag_reports_every_offender_at_once() {
        let error = registry()
            .validate_all(["product", "billing", "prodcut"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("billing"), "{error}");
        assert!(
            error.contains("prodcut"),
            "a five-typo DAG must not take five builds to fix: {error}"
        );
    }

    #[test]
    fn a_clean_dag_validates_to_its_keys() {
        let keys = registry().validate_all(["product", "consensus"]).unwrap();
        assert_eq!(
            keys.iter().map(RoleKey::as_key).collect::<Vec<_>>(),
            ["council-summary/product", "council-summary/consensus"]
        );
    }
}
