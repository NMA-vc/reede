//! Per-identity attention budget.
//!
//! Any agent anywhere in the fleet that wants to interrupt a human with an
//! open question draws from this budget and is refused when it is empty.
//! Shared across every vertical (the pilot, and whatever comes after it) --
//! this is a fleet-wide human-attention primitive, not a per-product one.
//!
//! ## Why this is neither `Ledger` nor `LeaseManager`
//!
//! Both existing primitives were checked and ruled out before writing this,
//! per the design brief's own instruction not to build a new one first:
//!
//! * `ledger.rs`'s `Ledger` is a **monetary balance**: `reserve` decrements a
//!   tenant's balance and errors closed when it is insufficient, `deduct`
//!   settles the actual spend, nothing ever resets on its own. An attention
//!   budget is not spent down to zero and topped up -- it is a **cooldown**:
//!   exactly one interruption is allowed, then it recovers automatically 30
//!   days later. Modelling that on `Ledger` would mean manually "topping up"
//!   every identity's balance on a timer, which is what this module's `now`
//!   comparison already gives you directly, more cheaply.
//! * `lease.rs`'s `LeaseManager` is time-bounded **credential access**,
//!   default-deny: `check()` on a lease that was never `issue()`d is an
//!   error (`LeaseExpired`), because a lease represents a grant that must be
//!   proven valid. An attention budget is the opposite polarity,
//!   default-**allow**: an identity that was never asked has full budget,
//!   which is the *normal*, non-error case. Reusing `LeaseManager`'s trait
//!   would mean treating "never asked" (the common case) as the same error
//!   variant as "asked too recently" (the refusal case) -- distinguishable
//!   only by inspecting the error's reason string, an inversion `LeaseManager`
//!   callers don't have to deal with today. Not worth forcing.
//!
//! Both are close in spirit (time-bounded, "stops at a limit") but neither
//! fits without bending its semantics, so this is a small, dedicated
//! primitive instead -- same in-memory-reference-impl style as `lease.rs`.
//!
//! ## The identity question is deliberately NOT decided here
//!
//! The design brief flags this as "blocked on an identity decision... upstream of the
//! whole design" and explicitly hard to retrofit. This module takes an
//! opaque, caller-supplied `identity_key: &str` and makes no assumption about
//! what it is derived from -- that is a product/privacy decision, not an
//! engineering one, and this crate has no business making it unilaterally:
//!
//! * A session cookie resets on every clear, so the 30-day window becomes
//!   decorative -- ruled out by the ticket itself.
//! * An account id excludes anonymous visitors, which the ticket notes is
//!   most of the pilot's traffic -- also ruled out.
//! * A persistent first-party pseudonymous identifier (a long-lived cookie or
//!   `localStorage` value, never combined with other PII) is the closest fit
//!   to "stable enough for 30 days, works for anonymous visitors" -- but it
//!   is still personal data under GDPR the moment it is used to recognise the
//!   same person across visits, which this mechanism does by design. That
//!   needs a legal basis (consent or a documented legitimate-interest
//!   assessment) and a retention/deletion story, matching the concern
//!   already raised in the retention design (GDPR retention reaching synthesised claims).
//!   Fingerprinting (canvas/font/etc.) is explicitly NOT recommended: strictly
//!   worse for privacy than a disclosed first-party identifier for the same
//!   result, and out of step with this codebase's EU-hosted, privacy-first
//!   posture elsewhere (see the repo's Ecosia-not-scraping, cortecs-only-LLM
//!   conventions).
//!
//! This is a recommendation, not a decision made on your behalf -- confirm
//! the actual identity strategy (and its legal basis) before wiring this
//! into a real anonymous-visitor flow. Whatever is chosen, the string it
//! resolves to is all this module needs.

use crate::error::ReedeError;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

/// Opening policy from the design brief, meant to be argued with -- not load-bearing
/// defaults anyone should assume are final.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttentionBudgetPolicy {
    /// How long a "no" (or a completed ask) keeps an identity refused for.
    pub cooldown: Duration,
}

impl Default for AttentionBudgetPolicy {
    fn default() -> Self {
        Self {
            cooldown: Duration::days(30),
        }
    }
}

/// The outcome of asking "may I interrupt this identity right now".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskDecision {
    /// Budget available; the caller may ask. Does not itself consume budget
    /// -- call `record_ask`/`record_dismissal` once an ask actually happens,
    /// so a `may_ask` check alone (e.g. for a dry-run) has no side effect.
    Allowed,
    /// Refused; budget will not recover until `retry_after`.
    Refused { retry_after: DateTime<Utc> },
}

/// Per-identity attention budget: exactly one interruption per cooldown
/// window, recovering on its own -- no top-up, no reservation to release.
#[async_trait]
pub trait AttentionBudget: Send + Sync {
    /// Decide whether `identity_key` may be interrupted right now.
    ///
    /// `is_first_session` is caller-supplied and load-bearing: "0
    /// interruptions in a user's first ever session" cannot be derived from
    /// consumption history alone (an identity with no prior ask could
    /// legitimately be in session 1 or session 50) -- this primitive has no
    /// notion of sessions, so the caller must say which one this is.
    async fn may_ask(
        &self,
        identity_key: &str,
        is_first_session: bool,
        now: DateTime<Utc>,
    ) -> Result<AskDecision, ReedeError>;

    /// Record that `identity_key` was actually asked, starting the cooldown.
    async fn record_ask(&self, identity_key: &str, now: DateTime<Utc>) -> Result<(), ReedeError>;

    /// Record an explicit dismissal. Costs the same full cooldown as
    /// `record_ask` -- dismissing is not a discount on the wait, per the design brief.
    /// Kept as a distinct method (not an alias) so callers can log *why* the
    /// cooldown started without this module inferring it from a shared code
    /// path.
    async fn record_dismissal(
        &self,
        identity_key: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ReedeError>;
}

/// In-memory reference implementation, same style as `InMemoryLeaseManager`.
/// The production SurrealDB binding lands with the persistent-store work.
pub struct InMemoryAttentionBudget {
    policy: AttentionBudgetPolicy,
    /// identity_key -> refused-until timestamp. Absence means full budget.
    refused_until: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl InMemoryAttentionBudget {
    pub fn new(policy: AttentionBudgetPolicy) -> Self {
        Self {
            policy,
            refused_until: Mutex::new(HashMap::new()),
        }
    }

    fn record(&self, identity_key: &str, now: DateTime<Utc>) {
        let mut map = self.refused_until.lock().unwrap();
        map.insert(identity_key.to_string(), now + self.policy.cooldown);
    }
}

impl Default for InMemoryAttentionBudget {
    fn default() -> Self {
        Self::new(AttentionBudgetPolicy::default())
    }
}

#[async_trait]
impl AttentionBudget for InMemoryAttentionBudget {
    async fn may_ask(
        &self,
        identity_key: &str,
        is_first_session: bool,
        now: DateTime<Utc>,
    ) -> Result<AskDecision, ReedeError> {
        let map = self.refused_until.lock().unwrap();
        let recorded_until = map.get(identity_key).copied();
        drop(map);

        if is_first_session {
            // Refused regardless of consumption history -- the rule is
            // absolute for a first-ever session. But the reported
            // `retry_after` must still reflect a real recorded cooldown if
            // one exists and extends further than "immediately": a
            // first-session flag must never SHORTEN an existing refusal
            // (e.g. a caller passing is_first_session=true for an identity
            // that, per this store, already has an active cooldown). Only
            // when no later real cooldown is on record does the
            // first-session rule fall back to "not now, but the identity's
            // 30-day budget is otherwise untouched".
            let retry_after = match recorded_until {
                Some(until) if until > now => until,
                _ => now,
            };
            return Ok(AskDecision::Refused { retry_after });
        }

        match recorded_until {
            Some(until) if until > now => Ok(AskDecision::Refused { retry_after: until }),
            _ => Ok(AskDecision::Allowed),
        }
    }

    async fn record_ask(&self, identity_key: &str, now: DateTime<Utc>) -> Result<(), ReedeError> {
        self.record(identity_key, now);
        Ok(())
    }

    async fn record_dismissal(
        &self,
        identity_key: &str,
        now: DateTime<Utc>,
    ) -> Result<(), ReedeError> {
        self.record(identity_key, now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_first_session_is_always_refused_regardless_of_history() {
        let budget = InMemoryAttentionBudget::default();
        let now = Utc::now();
        let decision = budget.may_ask("visitor-1", true, now).await.unwrap();
        assert!(matches!(decision, AskDecision::Refused { .. }));
    }

    #[tokio::test]
    async fn test_first_session_flag_never_shortens_an_existing_cooldown() {
        // nk-0001 regression: a caller passing is_first_session=true for an
        // identity that already has a real recorded cooldown (e.g. a second
        // device/tab racing the "first session" flag) must still be told the
        // real retry_after, not `now` -- reporting `now` would make the
        // caller think the identity is refused-but-immediately-retryable,
        // silently discarding the rest of the 30-day cooldown.
        let budget = InMemoryAttentionBudget::default();
        let t0 = Utc::now();
        budget.record_ask("visitor-1b", t0).await.unwrap();

        let decision = budget.may_ask("visitor-1b", true, t0).await.unwrap();
        assert_eq!(
            decision,
            AskDecision::Refused {
                retry_after: t0 + Duration::days(30)
            }
        );
    }

    #[tokio::test]
    async fn test_never_asked_identity_has_full_budget_outside_first_session() {
        let budget = InMemoryAttentionBudget::default();
        let now = Utc::now();
        let decision = budget.may_ask("visitor-2", false, now).await.unwrap();
        assert_eq!(decision, AskDecision::Allowed);
    }

    #[tokio::test]
    async fn test_asking_starts_the_cooldown_and_refuses_until_it_expires() {
        let budget = InMemoryAttentionBudget::default();
        let t0 = Utc::now();
        budget.record_ask("visitor-3", t0).await.unwrap();

        let too_soon = budget
            .may_ask("visitor-3", false, t0 + Duration::days(29))
            .await
            .unwrap();
        assert!(
            matches!(too_soon, AskDecision::Refused { retry_after } if retry_after == t0 + Duration::days(30))
        );

        let after = budget
            .may_ask("visitor-3", false, t0 + Duration::days(31))
            .await
            .unwrap();
        assert_eq!(
            after,
            AskDecision::Allowed,
            "budget recovers on its own, no top-up needed"
        );
    }

    #[tokio::test]
    async fn test_dismissal_costs_the_same_full_cooldown_as_an_ask() {
        let budget = InMemoryAttentionBudget::default();
        let t0 = Utc::now();
        budget.record_dismissal("visitor-4", t0).await.unwrap();

        let decision = budget
            .may_ask("visitor-4", false, t0 + Duration::days(29))
            .await
            .unwrap();
        assert!(
            matches!(decision, AskDecision::Refused { retry_after } if retry_after == t0 + Duration::days(30)),
            "dismissal is not a discount on the wait"
        );
    }

    #[tokio::test]
    async fn test_may_ask_alone_has_no_side_effect() {
        let budget = InMemoryAttentionBudget::default();
        let now = Utc::now();
        // Calling may_ask repeatedly must not itself consume budget.
        for _ in 0..3 {
            let decision = budget.may_ask("visitor-5", false, now).await.unwrap();
            assert_eq!(decision, AskDecision::Allowed);
        }
    }

    #[tokio::test]
    async fn test_identities_are_isolated_from_each_other() {
        let budget = InMemoryAttentionBudget::default();
        let now = Utc::now();
        budget.record_ask("visitor-6", now).await.unwrap();

        let other = budget.may_ask("visitor-7", false, now).await.unwrap();
        assert_eq!(
            other,
            AskDecision::Allowed,
            "one identity's cooldown must not leak to another"
        );
    }

    #[tokio::test]
    async fn test_custom_policy_cooldown_is_honoured() {
        let short = AttentionBudgetPolicy {
            cooldown: Duration::days(7),
        };
        let budget = InMemoryAttentionBudget::new(short);
        let t0 = Utc::now();
        budget.record_ask("visitor-8", t0).await.unwrap();

        assert_eq!(
            budget
                .may_ask("visitor-8", false, t0 + Duration::days(8))
                .await
                .unwrap(),
            AskDecision::Allowed
        );
    }
}
