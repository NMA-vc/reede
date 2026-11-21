//! Where a signal is allowed to go.
//!
//! The spec's warning, in its own words: *"Wrong: push analytics into per-role
//! memory. 'Nobody read the article' is a population-level fact. It tells a specific
//! role nothing about a specific run."* A memory written from an aggregate is not
//! merely useless -- it is a lesson a role will retrieve and act on, derived from
//! evidence that was never about that role's work.
//!
//! So routing is an allowlist, and the allowlist is code. There is no
//! configuration path, no environment override and no inference from the signal's
//! shape: adding an entry is a deliberate edit with a test, which is the only kind
//! of change that gets reviewed. Anything not on it routes to `dataset` and warns.
//!
//! The allowlist keys on **`(source, kind)`**, not on the source alone. Trusting the
//! producer and then accepting whatever it emits is trusting it about the wrong
//! thing: `diff-capture` is allowlisted because a human edited a draft, which is a
//! `Correction`. The day it also emits a `Metric` -- a new feature, a bug, a
//! refactor that reuses the producer id -- that metric is a population-level fact
//! and would have walked straight into per-role memory, which is the exact mistake
//! the module note above quotes the spec warning about. Naming the kind makes the
//! new emission a review conversation instead of a silent one.
//!
//! ## Every signal reaches `dataset`
//!
//! `memory` is the *additional* destination, not the alternative one. A correction
//! is both a lesson for one role and a data point about the cohort, and dropping it
//! from the dataset to "promote" it would make the population view depend on which
//! producers happen to be allowlisted. `Destination::Dataset` is therefore
//! unconditional; the interesting question is only ever whether `Memory` joins it.
//!
//! ## Three refusals that outrank the allowlist
//!
//! An allowlisted producer still does not reach memory when:
//!
//! - `cohort_only` is set -- the producer said this row is population-level
//!   and a per-producer allowlist must not override a per-signal
//!   declaration.
//! - `is_promotable()` is false -- Phase 1's gate. No run, no role, or no
//!   attribution means there is no scope to write the memory into.
//! - the kind is `Withdrawal` -- it retracts evidence rather than being evidence.
//!   Promoting one would write a memory *from* the act of taking something back.
//!
//! Each is checked separately and reported separately, because "this did not
//! promote" is a question someone will ask of a specific row, and "not allowed" is a
//! different answer from "not attributed yet".

use crate::signal::{Signal, SignalKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Where a signal may be consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// Per-role memory: instance-level supervision a role will retrieve later.
    Memory,
    /// The population-level dataset: cohort statistics, scorecards, analytics.
    Dataset,
}

impl Destination {
    pub fn as_str(&self) -> &'static str {
        match self {
            Destination::Memory => "memory",
            Destination::Dataset => "dataset",
        }
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a signal did not reach `Memory`.
///
/// Named cases rather than a string, so a consumer can count them: a rising
/// `Unattributed` rate is an attribution problem, a rising `ProducerNotAllowlisted`
/// rate means a new producer shipped without being classified. A single "rejected"
/// counter would hide both behind each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRefusal {
    /// The producer is not on the memory allowlist. The default for anything new.
    ProducerNotAllowlisted { source: String },
    /// The producer is allowlisted, but not for this kind of signal.
    KindNotAllowlisted { source: String, kind: SignalKind },
    /// The producer marked this row population-level.
    CohortOnly,
    /// Phase 1's gate: no run, no role, or no attribution.
    Unattributed,
    /// A retraction is not evidence.
    Retraction,
}

impl MemoryRefusal {
    pub fn reason(&self) -> String {
        match self {
            MemoryRefusal::ProducerNotAllowlisted { source } => format!(
                "producer {source:?} is not on the memory allowlist; \
                 adding it is a deliberate code change"
            ),
            MemoryRefusal::KindNotAllowlisted { source, kind } => format!(
                "producer {source:?} is allowlisted for memory, but not for {kind} \
                 signals; adding the pair is a deliberate code change"
            ),
            MemoryRefusal::CohortOnly => {
                "the producer marked this signal cohort-only (population-level)".to_string()
            }
            MemoryRefusal::Unattributed => {
                "the signal is not attributed to a run and role, so it has no memory scope"
                    .to_string()
            }
            MemoryRefusal::Retraction => {
                "a withdrawal retracts evidence rather than being evidence".to_string()
            }
        }
    }
}

/// The routing verdict for one signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    destinations: BTreeSet<Destination>,
    memory_refusal: Option<MemoryRefusal>,
}

impl Routing {
    pub fn destinations(&self) -> impl Iterator<Item = Destination> + '_ {
        self.destinations.iter().copied()
    }

    pub fn allows(&self, destination: Destination) -> bool {
        self.destinations.contains(&destination)
    }

    /// Shorthand for the question every consumer actually asks.
    pub fn allows_memory(&self) -> bool {
        self.allows(Destination::Memory)
    }

    /// Why memory was refused, if it was. `None` when memory is allowed.
    pub fn memory_refusal(&self) -> Option<&MemoryRefusal> {
        self.memory_refusal.as_ref()
    }
}

/// The `(producer, kind)` pairs that may promote into per-role memory.
///
/// Each is here because *that producer emitting that kind* records one human's
/// judgement of one run's output, which is what a per-role memory can legitimately
/// be written from:
///
/// - `diff-capture` / `Correction` -- a human edited a specific draft. The spec
///   calls this the highest-value signal, and it is the least ambiguous: someone
///   looked at this output and changed it.
/// - `inquiry` (legacy wire name `frogen`) / `Response` -- a real answer to a specific inquiry this run sent.
///   Evidence about that exchange, not about a population.
///
/// The kind is half the entry, not decoration. `diff-capture` is trusted for having
/// watched a human edit a draft; it is not thereby trusted for a `Metric`, which is
/// a population-level fact whichever producer emits it. Keying on the source alone
/// meant any new or mistaken emission from an allowlisted producer inherited its
/// trust silently.
///
/// Everything else in the tree is deliberately absent, including two that look
/// close:
///
/// - `rating` -- a thumbs vote is about one artifact, but a widget rating carries no
///   role of its own and arrives without one in practice, so it fails the
///   attribution gate anyway. Allowlisting it would make the refusal read as
///   "not attributed" instead of "not classified", which is the less honest of the
///   two. It can be added when a rating surface records a role (D5).
/// - `analytics-poller` -- the spec's own worked example of what must never reach
///   memory.
const MEMORY_ALLOWLISTED_ROUTES: &[(&str, SignalKind)] = &[
    ("diff-capture", SignalKind::Correction),
    ("frogen", SignalKind::Response),
    ("inquiry", SignalKind::Response),
];

/// Routes signals to their permitted destinations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalFork {
    memory_routes: BTreeSet<(String, SignalKind)>,
}

impl Default for SignalFork {
    fn default() -> Self {
        Self::standard()
    }
}

impl SignalFork {
    /// The shipped classification. This is the table the spec asks for.
    pub fn standard() -> Self {
        Self {
            memory_routes: MEMORY_ALLOWLISTED_ROUTES
                .iter()
                .map(|(source, kind)| ((*source).to_string(), *kind))
                .collect(),
        }
    }

    /// A fork with an explicit `(producer, kind)` set.
    ///
    /// For tests and for a caller that genuinely owns a different set. Note that
    /// this cannot loosen the three per-signal refusals -- those are not part of the
    /// allowlist and no constructor can turn them off.
    pub fn with_memory_routes<I, S>(routes: I) -> Self
    where
        I: IntoIterator<Item = (S, SignalKind)>,
        S: Into<String>,
    {
        Self {
            memory_routes: routes
                .into_iter()
                .map(|(source, kind)| (source.into(), kind))
                .collect(),
        }
    }

    /// The `(producer, kind)` pairs currently allowed to promote, in a stable order.
    pub fn memory_routes(&self) -> impl Iterator<Item = (&str, SignalKind)> {
        self.memory_routes
            .iter()
            .map(|(source, kind)| (source.as_str(), *kind))
    }

    /// The producers with at least one allowlisted kind, in a stable order.
    pub fn memory_producers(&self) -> impl Iterator<Item = &str> {
        let mut seen: Vec<&str> = self
            .memory_routes
            .iter()
            .map(|(source, _)| source.as_str())
            .collect();
        seen.dedup();
        seen.into_iter()
    }

    /// Route one signal.
    ///
    /// The order of checks is the order of the answers' usefulness. The allowlist is
    /// tested first because an unclassified producer is a shipping mistake worth
    /// hearing about even when the row would have been refused for another reason
    /// too -- otherwise a new producer emitting only unattributed signals stays
    /// invisible until someone fixes attribution.
    pub fn route(&self, signal: &Signal) -> Routing {
        let mut destinations = BTreeSet::new();
        // Unconditional: see the module note. Population statistics must not depend
        // on which producers happen to be allowlisted for memory.
        destinations.insert(Destination::Dataset);

        let source_known = self
            .memory_routes
            .iter()
            .any(|(source, _)| source == &signal.source);
        let pair_allowed = self
            .memory_routes
            .contains(&(signal.source.clone(), signal.kind));

        let refusal = if !source_known {
            tracing::warn!(
                source = %signal.source,
                kind = signal.kind.as_str(),
                tenant_id = %signal.tenant_id,
                "producer is not classified for memory; routing to dataset only"
            );
            Some(MemoryRefusal::ProducerNotAllowlisted {
                source: signal.source.clone(),
            })
        } else if signal.cohort_only {
            Some(MemoryRefusal::CohortOnly)
        } else if signal.kind == SignalKind::Withdrawal {
            // Ahead of the kind check below on purpose: a withdrawal is structurally
            // never evidence, for any producer, so "a retraction is not evidence" is
            // the true answer -- "that pair is not allowlisted" would invite someone
            // to allowlist it.
            Some(MemoryRefusal::Retraction)
        } else if !pair_allowed {
            // An allowlisted producer emitting a kind nobody classified. Reported
            // separately from an unknown producer because it means something
            // different: not "a new producer shipped unclassified" but "a known one
            // started emitting something new", which is a change in that producer.
            tracing::warn!(
                source = %signal.source,
                kind = signal.kind.as_str(),
                tenant_id = %signal.tenant_id,
                "producer is allowlisted for memory but not for this kind; \
                 routing to dataset only"
            );
            Some(MemoryRefusal::KindNotAllowlisted {
                source: signal.source.clone(),
                kind: signal.kind,
            })
        } else if !signal.is_promotable() {
            Some(MemoryRefusal::Unattributed)
        } else {
            destinations.insert(Destination::Memory);
            None
        };

        Routing {
            destinations,
            memory_refusal: refusal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::AttributionSource;

    /// An attributed signal from `source`, i.e. one that clears Phase 1's gate.
    fn attributed(source: &str, kind: SignalKind) -> Signal {
        let mut signal = Signal::builder("sub_1")
            .tenant("tenant-1")
            // The capability must agree with the role key's capability half, or
            // `Signal::role_key` refuses the pair (they are two names for one thing).
            .capability("council-summary")
            .kind(kind)
            .source(source)
            .idempotency("k-1")
            .run("run-1")
            .build();
        signal.role = Some("council-summary/product".to_string());
        signal.attribution_source = AttributionSource::Explicit;
        signal
    }

    #[test]
    fn an_attributed_diff_capture_signal_reaches_both_destinations() {
        let routing =
            SignalFork::standard().route(&attributed("diff-capture", SignalKind::Correction));
        assert!(routing.allows_memory());
        assert!(routing.allows(Destination::Dataset));
        assert_eq!(routing.memory_refusal(), None);
    }

    // The spec's acceptance criterion, verbatim: "an analytics signal can never
    // produce a memory row".
    #[test]
    fn an_analytics_signal_can_never_reach_memory() {
        let fork = SignalFork::standard();
        // Tried every way it could sneak through: fully attributed, not cohort-only,
        // a kind that promotes for other producers. The producer alone stops it.
        let routing = fork.route(&attributed("analytics-poller", SignalKind::Metric));
        assert!(!routing.allows_memory());
        assert!(routing.allows(Destination::Dataset));
        assert!(matches!(
            routing.memory_refusal(),
            Some(MemoryRefusal::ProducerNotAllowlisted { .. })
        ));

        // ...and it is not in the allowlist by any spelling.
        assert!(!fork.memory_producers().any(|p| p.contains("analytics")));
    }

    // The other acceptance criterion: unclassified routes to dataset and warns.
    #[test]
    fn an_unclassified_producer_routes_to_dataset_only() {
        let routing =
            SignalFork::standard().route(&attributed("some-new-producer", SignalKind::Correction));
        assert_eq!(
            routing.destinations().collect::<Vec<_>>(),
            vec![Destination::Dataset],
            "a producer nobody classified must not default into memory"
        );
        let refusal = routing.memory_refusal().unwrap();
        assert!(
            refusal.reason().contains("deliberate code change"),
            "the reason must say how to fix it: {}",
            refusal.reason()
        );
    }

    #[test]
    fn cohort_only_outranks_the_allowlist() {
        let mut signal = attributed("diff-capture", SignalKind::Correction);
        signal.cohort_only = true;
        let routing = SignalFork::standard().route(&signal);
        assert!(!routing.allows_memory());
        assert_eq!(routing.memory_refusal(), Some(&MemoryRefusal::CohortOnly));
    }

    #[test]
    fn an_unattributed_signal_from_an_allowlisted_producer_is_refused() {
        // Phase 1's gate, reached through the fork: diff capture emits exactly this
        // today (it knows the run, not the role).
        let mut signal = attributed("diff-capture", SignalKind::Correction);
        signal.role = None;
        signal.attribution_source = AttributionSource::None;
        let routing = SignalFork::standard().route(&signal);
        assert!(!routing.allows_memory());
        assert_eq!(routing.memory_refusal(), Some(&MemoryRefusal::Unattributed));
    }

    #[test]
    fn a_withdrawal_never_promotes() {
        let signal = attributed("diff-capture", SignalKind::Withdrawal);
        let routing = SignalFork::standard().route(&signal);
        assert!(!routing.allows_memory());
        assert_eq!(routing.memory_refusal(), Some(&MemoryRefusal::Retraction));
    }

    #[test]
    fn the_refusals_are_distinguishable_from_each_other() {
        // Why they are separate variants: a consumer counting them can tell an
        // attribution problem from an unclassified new producer. One "rejected"
        // counter would hide each behind the other.
        let fork = SignalFork::standard();
        let mut unattributed = attributed("diff-capture", SignalKind::Correction);
        unattributed.role = None;
        unattributed.attribution_source = AttributionSource::None;

        assert_ne!(
            fork.route(&unattributed).memory_refusal(),
            fork.route(&attributed("unknown", SignalKind::Correction))
                .memory_refusal()
        );
    }

    #[test]
    fn every_signal_reaches_the_dataset_whatever_else_happens() {
        let fork = SignalFork::standard();
        let mut cohort = attributed("analytics-poller", SignalKind::Metric);
        cohort.cohort_only = true;
        let mut bare = attributed("unknown", SignalKind::Rating);
        bare.role = None;
        bare.attribution_source = AttributionSource::None;

        for signal in [
            attributed("diff-capture", SignalKind::Correction),
            attributed("frogen", SignalKind::Response),
            attributed("diff-capture", SignalKind::Withdrawal),
            cohort,
            bare,
        ] {
            assert!(
                fork.route(&signal).allows(Destination::Dataset),
                "population statistics must not depend on the memory allowlist: {}",
                signal.source
            );
        }
    }

    #[test]
    fn a_custom_producer_set_cannot_switch_off_the_per_signal_refusals() {
        // The allowlist is the only thing a constructor controls. Someone handing in
        // "analytics-poller" still cannot promote a cohort-only or unattributed row.
        let permissive = SignalFork::with_memory_routes([("analytics-poller", SignalKind::Metric)]);
        let mut cohort = attributed("analytics-poller", SignalKind::Metric);
        cohort.cohort_only = true;
        assert!(!permissive.route(&cohort).allows_memory());

        let mut unattributed = attributed("analytics-poller", SignalKind::Metric);
        unattributed.role = None;
        unattributed.attribution_source = AttributionSource::None;
        assert!(!permissive.route(&unattributed).allows_memory());
    }

    #[test]
    fn the_shipped_allowlist_is_the_documented_one() {
        // A guard on the thing the module doc promises: if someone adds a pair, this
        // test fails and they have to say so here as well as in the constant.
        assert_eq!(
            SignalFork::standard().memory_routes().collect::<Vec<_>>(),
            vec![
                ("diff-capture", SignalKind::Correction),
                ("frogen", SignalKind::Response),
                ("inquiry", SignalKind::Response),
            ]
        );
    }

    /// The kind is half the allowlist entry.
    ///
    /// Keying on the producer alone meant an allowlisted producer's *other* kinds
    /// inherited its trust. A `Metric` is a population-level fact whoever emits it,
    /// so `diff-capture` emitting one -- a new feature, a bug, a producer id reused
    /// by a refactor -- would have walked into per-role memory with nothing going
    /// red. It is now a distinct, countable refusal.
    #[test]
    fn an_allowlisted_producer_does_not_promote_an_unclassified_kind() {
        let fork = SignalFork::standard();
        for kind in [SignalKind::Metric, SignalKind::Rating, SignalKind::Outcome] {
            let routing = fork.route(&attributed("diff-capture", kind));
            assert!(
                !routing.allows_memory(),
                "{kind} from diff-capture is not what diff-capture is trusted for"
            );
            match routing.memory_refusal() {
                Some(MemoryRefusal::KindNotAllowlisted { source, kind: k }) => {
                    assert_eq!(source, "diff-capture");
                    assert_eq!(*k, kind);
                }
                other => panic!("expected a kind refusal for {kind}, got {other:?}"),
            }
            assert!(routing.allows(Destination::Dataset));
        }
    }

    #[test]
    fn the_pair_refusal_is_distinct_from_the_producer_refusal() {
        // They mean different things: one says a new producer shipped unclassified,
        // the other that a known producer started emitting something new. A single
        // counter would hide the second behind the first.
        let fork = SignalFork::standard();
        assert_ne!(
            fork.route(&attributed("diff-capture", SignalKind::Metric))
                .memory_refusal(),
            fork.route(&attributed("nobody", SignalKind::Metric))
                .memory_refusal()
        );
    }

    #[test]
    fn each_allowlisted_pair_actually_promotes() {
        // The other direction of the guard above: every documented pair must reach
        // memory, or the allowlist claims something the router does not do.
        let fork = SignalFork::standard();
        for (source, kind) in fork.memory_routes().collect::<Vec<_>>() {
            let routing = fork.route(&attributed(source, kind));
            assert!(routing.allows_memory(), "{source}/{kind} must promote");
        }
    }
}
