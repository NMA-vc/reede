//! Depth bands, and the rule that a round reads before it writes.
//!
//! ## Bands are depth, not products
//!
//! The spec is emphatic: *"Depth bands are one agent plus a router, not three
//! products. Route depth first, model second."* A triage node classifies the task and
//! routes to one of three shapes -- a single grounded answer, a multi-role panel with
//! a consensus node, or a human with a brief attached.
//!
//! "One agent plus a router" is the constraint that matters, because the tempting
//! alternative is three agents with three manifests, three sets of roles and three
//! deploy paths -- at which point the band is a product decision rather than a routing
//! one, and changing where the line falls means shipping three things. Here a band is
//! a choice of *which declared roles run*, made per task, inside one agent.
//!
//! "Route depth first, model second" follows from the same idea: reach for another
//! role before reaching for a bigger model. A second opinion catches a different class
//! of mistake than more parameters does.
//!
//! ## The read-before-write rule is structural, not documented
//!
//! The spec names a specific bug to fix: *"it retrieves in round 1 and writes in both
//! rounds, so later rounds never see what was just learned. Read before every round
//! that writes."*
//!
//! That bug is not a slip, it is what happens when reading and writing are two
//! independent calls a caller makes in whatever order: round 2 writes because writing
//! is what rounds do, and nobody notices the read is missing because nothing fails --
//! the round just works from stale context and the loop quietly stops compounding.
//!
//! So [`MemoryRound`] is the only way to write, and the only way to get one is
//! [`MemoryRound::open`], which reads. A round that writes without reading is not a
//! bug you can commit; it is a program that does not compile.

use crate::error::ReedeError;
use crate::memory::{Memory, MemoryQuery, MemoryStore};
use crate::role::RoleKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How much depth a task gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    /// One grounded answer. Most traffic.
    Low,
    /// A panel of roles plus a consensus node.
    Moderate,
    /// A human, with a brief attached. The agent stops.
    High,
}

impl Band {
    pub fn as_str(&self) -> &'static str {
        match self {
            Band::Low => "low",
            Band::Moderate => "moderate",
            Band::High => "high",
        }
    }

    /// Whether this band answers at all.
    ///
    /// `High` does not: it routes to a human. Worth a named method because the
    /// difference between "the agent answered" and "the agent escalated" is the one a
    /// caller most often gets wrong by treating the brief as a draft.
    pub fn answers(&self) -> bool {
        !matches!(self, Band::High)
    }
}

impl std::fmt::Display for Band {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which of an agent's declared roles run in each band.
///
/// Names roles rather than holding sub-DAGs: the three shapes differ in which roles
/// participate and whether a consensus role closes them, and expressing that as a
/// role list keeps "one agent plus a router" true. A `BandPlan` holding three graphs
/// would be three products wearing one manifest.
/// The fields are private and every route in is [`BandPlan::new`], including
/// deserialization (`#[serde(try_from)]`).
///
/// They were public with a derived `Deserialize`, which meant a plan loaded from
/// JSON or TOML -- the way a plan will actually arrive -- never saw the constructor.
/// A one-role panel and a consensus role sitting on its own panel both deserialized
/// happily, and `roles_for` then ran the shape the constructor exists to reject.
/// There is no separate `validate()` to call afterwards, so nothing would have
/// caught it later either. A constructor that can be walked around is documentation,
/// not a check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "BandPlanFields")]
pub struct BandPlan {
    /// The single role that answers a low-band task.
    low: RoleKey,
    /// The panel. Two or more distinct roles; a one-role panel is just the low band
    /// with extra ceremony.
    moderate: Vec<RoleKey>,
    /// The role that reconciles the panel. Required for `moderate`: a panel with no
    /// consensus step produces two answers and no decision, which is worse than one
    /// answer.
    consensus: RoleKey,
    /// The role that writes the brief a human receives. Answers nothing itself.
    high: RoleKey,
}

/// The wire shape. Exists only so `Deserialize` has somewhere unvalidated to land
/// before [`BandPlan::new`] passes judgement on it.
#[derive(Deserialize)]
struct BandPlanFields {
    low: RoleKey,
    moderate: Vec<RoleKey>,
    consensus: RoleKey,
    high: RoleKey,
}

impl TryFrom<BandPlanFields> for BandPlan {
    type Error = ReedeError;

    fn try_from(fields: BandPlanFields) -> Result<Self, Self::Error> {
        BandPlan::new(fields.low, fields.moderate, fields.consensus, fields.high)
    }
}

impl BandPlan {
    /// Build a plan, refusing shapes that cannot work.
    pub fn new(
        low: RoleKey,
        moderate: Vec<RoleKey>,
        consensus: RoleKey,
        high: RoleKey,
    ) -> Result<Self, ReedeError> {
        // Distinct, not merely present. `[product, product]` passed a length check
        // and then ran one perspective twice before consensus -- which is the low
        // band paying for two calls, with the multi-role disagreement that defines
        // the moderate band structurally impossible.
        let mut seen = std::collections::BTreeSet::new();
        if let Some(duplicate) = moderate.iter().find(|role| !seen.insert(role.as_key())) {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "the moderate panel names {duplicate} twice; one perspective run \
                     twice is not two perspectives"
                ),
            });
        }
        if seen.len() < 2 {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "a moderate band needs at least two roles; {} is the low band \
                     with extra ceremony",
                    seen.len()
                ),
            });
        }
        if moderate.contains(&consensus) {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "the consensus role {consensus} is also on the panel; it would be \
                     reconciling its own answer"
                ),
            });
        }
        Ok(Self {
            low,
            moderate,
            consensus,
            high,
        })
    }

    /// The role that answers a low-band task.
    pub fn low(&self) -> &RoleKey {
        &self.low
    }

    /// The moderate band's panel, in order.
    pub fn moderate(&self) -> &[RoleKey] {
        &self.moderate
    }

    /// The role that reconciles the panel.
    pub fn consensus(&self) -> &RoleKey {
        &self.consensus
    }

    /// The role that writes the brief a human receives.
    pub fn high(&self) -> &RoleKey {
        &self.high
    }

    /// The roles that run for `band`, in execution order.
    ///
    /// For `moderate` the consensus role comes last, because it reads the panel's
    /// output. For `high` it is the brief writer alone -- the agent is not answering.
    pub fn roles_for(&self, band: Band) -> Vec<RoleKey> {
        match band {
            Band::Low => vec![self.low.clone()],
            Band::Moderate => {
                let mut roles = self.moderate.clone();
                roles.push(self.consensus.clone());
                roles
            }
            Band::High => vec![self.high.clone()],
        }
    }

    /// Every role this plan can ever run.
    ///
    /// What a manifest's role allowlist has to cover, so a plan naming a role the
    /// agent never declared fails at build time rather than at the first task that
    /// routes to it.
    pub fn all_roles(&self) -> Vec<RoleKey> {
        let mut roles = vec![self.low.clone()];
        roles.extend(self.moderate.iter().cloned());
        roles.push(self.consensus.clone());
        roles.push(self.high.clone());
        roles.sort();
        roles.dedup();
        roles
    }
}

/// What the triage node decided, as it appears in the run timeline.
///
/// The spec's acceptance criterion is *"Band classification appears in the run
/// timeline"*, and the reason is that a band is the single most consequential thing
/// about a run: it decides how much was spent and whether a human was involved. A
/// timeline that records the answer but not the band cannot explain either.
///
/// Carries the reason as well as the verdict. "Why was this escalated?" is the
/// question a band record exists to answer, and a bare enum cannot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BandRecord {
    pub run_id: String,
    pub tenant_id: String,
    pub band: Band,
    /// Why the classifier chose it, in its own words.
    pub reason: String,
    /// The roles this band will run, recorded at decision time.
    ///
    /// Stored rather than derived later, because the plan can change between the run
    /// and the reading, and the timeline should say what actually ran.
    pub roles: Vec<String>,
    pub decided_at: DateTime<Utc>,
}

/// Classifies a task into a band.
///
/// A trait because real triage is a model call, and that lives host-side.
#[async_trait::async_trait]
pub trait BandClassifier: Send + Sync {
    async fn classify(&self, task: &str) -> Result<(Band, String), ReedeError>;
}

/// The fail-safe classifier: everything is `High`.
///
/// Used where no classifier is configured. `High` and not `Low`, which is the whole
/// point: with no way to judge a task, the safe answer is to put it in front of a
/// human, not to answer it cheaply and hope. A default of `Low` would make a missing
/// classifier indistinguishable from a confidently easy task.
pub struct EscalateEverything;

#[async_trait::async_trait]
impl BandClassifier for EscalateEverything {
    async fn classify(&self, _task: &str) -> Result<(Band, String), ReedeError> {
        Ok((
            Band::High,
            "no band classifier is configured, so this goes to a human".to_string(),
        ))
    }
}

impl BandRecord {
    /// Record a classification against a plan.
    pub fn new(
        run_id: impl Into<String>,
        tenant_id: impl Into<String>,
        band: Band,
        reason: impl Into<String>,
        plan: &BandPlan,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            tenant_id: tenant_id.into(),
            band,
            reason: reason.into(),
            roles: plan.roles_for(band).iter().map(RoleKey::as_key).collect(),
            decided_at: now,
        }
    }

    /// One line for the timeline.
    pub fn summary(&self) -> String {
        format!(
            "band {} ({}): {}",
            self.band,
            self.roles.join(" -> "),
            self.reason
        )
    }
}

/// One role's turn in one round, holding what it read.
///
/// The only way to write a memory for a role, and the only way to get one is
/// [`MemoryRound::open`], which reads first. That is the spec's "read before every
/// round that writes", enforced by construction rather than by a comment somebody
/// will not read on the round that skips it.
pub struct MemoryRound<'a> {
    store: &'a dyn MemoryStore,
    role: RoleKey,
    tenant_id: String,
    scope_key: String,
    /// 1-based. Round 2 reading what round 1 wrote is the property this whole type
    /// exists for.
    round: u32,
    retrieved: Vec<Memory>,
}

impl<'a> MemoryRound<'a> {
    /// Open a round by reading this role's memories in scope.
    ///
    /// The read is not optional and not deferred: a round exists only after it has
    /// happened.
    pub async fn open(
        store: &'a dyn MemoryStore,
        tenant_id: &str,
        role: &RoleKey,
        scope_key: &str,
        round: u32,
        limit: usize,
        query_embedding: Vec<f32>,
    ) -> Result<Self, ReedeError> {
        let query =
            MemoryQuery::new(tenant_id, role, scope_key, limit).with_embedding(query_embedding);
        let retrieved = store.retrieve(&query).await?;
        Ok(Self {
            store,
            role: role.clone(),
            tenant_id: tenant_id.to_string(),
            scope_key: scope_key.to_string(),
            round,
            retrieved,
        })
    }

    /// What this role knew going into the round.
    pub fn retrieved(&self) -> &[Memory] {
        &self.retrieved
    }

    pub fn role(&self) -> &RoleKey {
        &self.role
    }

    pub fn round(&self) -> u32 {
        self.round
    }

    /// Write a memory for this role.
    ///
    /// Rejects a memory whose role or tenant is not this round's. The round is what
    /// proves a read happened *for this role* -- letting it write for another would
    /// hand one role's read to another role's write, which is the same
    /// cross-contamination the role key exists to prevent, one level up.
    pub async fn write(&self, memory: Memory) -> Result<Memory, ReedeError> {
        if memory.role != self.role.as_key() {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "round for role {} cannot write a memory for role {}",
                    self.role.as_key(),
                    memory.role
                ),
            });
        }
        if memory.tenant_id != self.tenant_id {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "round for tenant {} cannot write a memory for tenant {}",
                    self.tenant_id, memory.tenant_id
                ),
            });
        }
        if memory.scope_key != self.scope_key {
            return Err(ReedeError::SpecValidationFailed {
                reason: format!(
                    "round in scope {:?} cannot write a memory in scope {:?}; it read \
                     the wrong shelf to be writing to this one",
                    self.scope_key, memory.scope_key
                ),
            });
        }
        self.store.write(memory).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{InMemoryMemoryStore, MemoryKind};

    fn role(step: &str) -> RoleKey {
        RoleKey::new("support", step).unwrap()
    }

    fn plan() -> BandPlan {
        BandPlan::new(
            role("grounded"),
            vec![role("product"), role("account-history")],
            role("consensus"),
            role("brief"),
        )
        .unwrap()
    }

    #[test]
    fn a_low_band_runs_one_role() {
        assert_eq!(plan().roles_for(Band::Low), vec![role("grounded")]);
    }

    #[test]
    fn a_moderate_band_runs_the_panel_then_consensus() {
        assert_eq!(
            plan().roles_for(Band::Moderate),
            vec![role("product"), role("account-history"), role("consensus")],
            "consensus reads the panel's output, so it goes last"
        );
    }

    #[test]
    fn a_high_band_writes_a_brief_and_does_not_answer() {
        assert_eq!(plan().roles_for(Band::High), vec![role("brief")]);
        assert!(!Band::High.answers());
        assert!(Band::Low.answers() && Band::Moderate.answers());
    }

    #[test]
    fn a_one_role_panel_is_refused() {
        // It is the low band with extra ceremony, and calling it moderate would make
        // the band mean nothing.
        assert!(BandPlan::new(
            role("grounded"),
            vec![role("product")],
            role("consensus"),
            role("brief")
        )
        .is_err());
    }

    #[test]
    fn a_consensus_role_on_its_own_panel_is_refused() {
        assert!(BandPlan::new(
            role("grounded"),
            vec![role("product"), role("consensus")],
            role("consensus"),
            role("brief")
        )
        .is_err());
    }

    #[test]
    fn all_roles_covers_every_band_without_duplicates() {
        // What a manifest's allowlist has to declare, so a plan naming an undeclared
        // role fails at build time rather than at the first task that routes to it.
        let all = plan().all_roles();
        assert_eq!(all.len(), 5);
        for band in [Band::Low, Band::Moderate, Band::High] {
            for r in plan().roles_for(band) {
                assert!(all.contains(&r), "{r} runs but is not in all_roles");
            }
        }
    }

    #[tokio::test]
    async fn with_no_classifier_everything_goes_to_a_human() {
        // Fail-safe: a missing classifier must not be indistinguishable from a
        // confidently easy task.
        let (band, reason) = EscalateEverything.classify("anything").await.unwrap();
        assert_eq!(band, Band::High);
        assert!(reason.contains("human"), "{reason}");
    }

    // The spec's acceptance criterion: band classification appears in the timeline.
    #[test]
    fn the_band_record_carries_the_band_the_roles_and_the_reason() {
        let now = Utc::now();
        let record = BandRecord::new(
            "run-1",
            "tenant-1",
            Band::Moderate,
            "the customer disputes a charge and cites their plan history",
            &plan(),
            now,
        );
        assert_eq!(record.band, Band::Moderate);
        assert_eq!(
            record.roles,
            vec![
                "support/product",
                "support/account-history",
                "support/consensus"
            ]
        );
        assert!(record.summary().contains("moderate"));
        assert!(
            record.summary().contains("disputes a charge"),
            "'why was this escalated' is the question the record exists to answer"
        );
        // Round-trips, so the timeline row is the record rather than a rendering.
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<BandRecord>(&json).unwrap(), record);
    }

    fn memory_for(role: &RoleKey, scope: &str, text: &str) -> Memory {
        Memory::builder(role, scope)
            .tenant("tenant-1")
            .text(text)
            .kind(MemoryKind::Correction)
            .promoted_from(format!("diff-capture:{text}"), "receipt-1")
            .build()
            .unwrap()
    }

    // The spec's acceptance criterion: every round that writes memory also reads it
    // first. Enforced by construction -- there is no way to write except through a
    // round, and no way to get a round except by reading.
    #[tokio::test]
    async fn round_two_sees_what_round_one_wrote() {
        let store = InMemoryMemoryStore::new();
        let product = role("product");

        let first = MemoryRound::open(&store, "tenant-1", &product, "billing", 1, 10, vec![])
            .await
            .unwrap();
        assert!(first.retrieved().is_empty());
        first
            .write(memory_for(
                &product,
                "billing",
                "the balance is from account-history",
            ))
            .await
            .unwrap();

        let second = MemoryRound::open(&store, "tenant-1", &product, "billing", 2, 10, vec![])
            .await
            .unwrap();
        assert_eq!(
            second.retrieved().len(),
            1,
            "this is the bug the spec names: a later round must see what was just \
             learned, or the loop stops compounding"
        );
        assert_eq!(second.round(), 2);
    }

    // The other acceptance criterion: a correction written by one role is not
    // retrieved by another.
    #[tokio::test]
    async fn one_roles_correction_is_not_retrieved_by_another() {
        let store = InMemoryMemoryStore::new();
        let product = role("product");
        let history = role("account-history");

        MemoryRound::open(&store, "tenant-1", &product, "billing", 1, 10, vec![])
            .await
            .unwrap()
            .write(memory_for(&product, "billing", "product's lesson"))
            .await
            .unwrap();

        let other = MemoryRound::open(&store, "tenant-1", &history, "billing", 1, 10, vec![])
            .await
            .unwrap();
        assert!(
            other.retrieved().is_empty(),
            "teaching one role another's lesson is the failure nothing downstream \
             can detect"
        );
    }

    #[tokio::test]
    async fn a_round_cannot_write_for_another_role() {
        // The round is what proves a read happened FOR THIS ROLE. Letting it write
        // for another hands one role's read to another role's write.
        let store = InMemoryMemoryStore::new();
        let round = MemoryRound::open(
            &store,
            "tenant-1",
            &role("product"),
            "billing",
            1,
            10,
            vec![],
        )
        .await
        .unwrap();
        let error = round
            .write(memory_for(&role("account-history"), "billing", "not mine"))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot write a memory for role"), "{error}");
    }

    #[tokio::test]
    async fn a_round_cannot_write_outside_the_scope_it_read() {
        let store = InMemoryMemoryStore::new();
        let product = role("product");
        let round = MemoryRound::open(&store, "tenant-1", &product, "billing", 1, 10, vec![])
            .await
            .unwrap();
        assert!(round
            .write(memory_for(&product, "onboarding", "wrong shelf"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_round_cannot_write_for_another_tenant() {
        let store = InMemoryMemoryStore::new();
        let product = role("product");
        let round = MemoryRound::open(&store, "tenant-1", &product, "billing", 1, 10, vec![])
            .await
            .unwrap();
        let mut other = memory_for(&product, "billing", "someone else's");
        other.tenant_id = "tenant-2".to_string();
        assert!(round.write(other).await.is_err());
    }

    #[tokio::test]
    async fn every_role_in_a_moderate_band_reads_before_it_writes() {
        // The panel, run as the plan orders it. Each role opens its own round, so the
        // rule holds for all of them without anyone remembering it.
        let store = InMemoryMemoryStore::new();
        let plan = plan();
        for (index, role) in plan.roles_for(Band::Moderate).iter().enumerate() {
            let round = MemoryRound::open(&store, "tenant-1", role, "billing", 1, 10, vec![])
                .await
                .unwrap();
            assert!(
                round.retrieved().is_empty(),
                "role {index} starts with an empty scope of its own"
            );
            round
                .write(memory_for(role, "billing", &format!("lesson {index}")))
                .await
                .unwrap();
        }
        // ...and each role's second round sees only its own.
        for role in plan.roles_for(Band::Moderate) {
            let round = MemoryRound::open(&store, "tenant-1", &role, "billing", 2, 10, vec![])
                .await
                .unwrap();
            assert_eq!(
                round.retrieved().len(),
                1,
                "{role} should see exactly its own"
            );
        }
    }
    /// A one-role panel and a self-reconciling consensus are refused, and stay
    /// refused when the plan arrives as JSON.
    ///
    /// The fields were public with a derived `Deserialize`, so a plan loaded from
    /// config -- the way a plan will actually arrive -- never met the constructor,
    /// and `roles_for` then ran the exact shape it exists to reject. There is no
    /// later `validate()` to catch it either.
    #[test]
    fn an_invalid_plan_cannot_be_deserialized_around_the_constructor() {
        let valid = serde_json::to_value(plan()).unwrap();
        serde_json::from_value::<BandPlan>(valid).expect("a good plan round-trips");

        let one_role = serde_json::json!({
            "low": "support/grounded",
            "moderate": ["support/product"],
            "consensus": "support/consensus",
            "high": "support/brief",
        });
        assert!(
            serde_json::from_value::<BandPlan>(one_role).is_err(),
            "a one-role panel is the low band with extra ceremony, however it arrives"
        );

        let self_reconciling = serde_json::json!({
            "low": "support/grounded",
            "moderate": ["support/product", "support/consensus"],
            "consensus": "support/consensus",
            "high": "support/brief",
        });
        assert!(
            serde_json::from_value::<BandPlan>(self_reconciling).is_err(),
            "the consensus role would be reconciling its own answer"
        );
    }

    /// Two entries is not two perspectives.
    ///
    /// `[product, product]` passed the length check and ran one role twice before
    /// consensus: the low band paying for two calls, with the disagreement that
    /// defines the moderate band made structurally impossible.
    #[test]
    fn a_panel_naming_one_role_twice_is_refused() {
        let err = BandPlan::new(
            role("grounded"),
            vec![role("product"), role("product")],
            role("consensus"),
            role("brief"),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("twice"), "{err}");

        // ...and the same shape through deserialization.
        let duplicated = serde_json::json!({
            "low": "support/grounded",
            "moderate": ["support/product", "support/product"],
            "consensus": "support/consensus",
            "high": "support/brief",
        });
        assert!(serde_json::from_value::<BandPlan>(duplicated).is_err());
    }
}
