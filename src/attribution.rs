//! The attribution pass for coarse signals.
//!
//! Most feedback arrives pointing at nothing in particular. "This reply was
//! wrong" names a run but not which role inside it got it wrong, and a memory
//! attributed to the wrong role teaches one role another's lesson -- a failure
//! nothing downstream can detect. So a coarse signal is either resolved to a
//! role or it stays unattributed and cannot promote. There is no third option
//! where it promotes on a guess.
//!
//! Explicit capture is always preferred and is decided per surface in
//! `docs/reflection/decisions/D5`; this is the fallback for what the surface
//! could not record. The design asks for exactly one model call and no chain,
//! which is also why the contract below returns a verdict rather than prose:
//! a caller cannot accidentally accept "probably the summarizer" as an answer.
//!
//! The trait lives here and its Cortecs-backed implementation lives host-side
//! (reede never depends on a host application crate).

use crate::error::ReedeError;
use crate::role::RoleKey;
use crate::signal::{AttributionSource, Signal};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// One role's contribution to a run, as the attributor sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleOutput {
    /// Stable role key (D2). This exact string is what a verdict must name.
    pub role: String,
    /// What that role produced, trimmed to whatever the caller can afford.
    pub output: String,
}

/// A coarse criticism plus the run it belongs to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttributionRequest {
    pub tenant_id: String,
    pub run_id: String,
    /// The human's criticism, verbatim. Never summarised before it gets here:
    /// the specific wording is the evidence.
    pub criticism: String,
    /// Every role that contributed to the run. A verdict naming anything not in
    /// this list is rejected.
    pub candidates: Vec<RoleOutput>,
}

/// The verdict. Deliberately two-valued: a role, or an explicit refusal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttributionOutcome {
    /// The criticism lands on this role.
    Attributed {
        role: String,
        /// 0..1. Compared against the caller's threshold before it counts.
        confidence: f64,
    },
    /// Could not be attributed. Carries why, so a high refusal rate is
    /// diagnosable rather than just a shrug.
    Unattributable { reason: String },
}

impl AttributionOutcome {
    pub fn role(&self) -> Option<&str> {
        match self {
            AttributionOutcome::Attributed { role, .. } => Some(role.as_str()),
            AttributionOutcome::Unattributable { .. } => None,
        }
    }
}

/// Resolves a coarse criticism to the role it lands on.
///
/// Implementations must make **one** model call and must not chain. An
/// implementation that cannot decide returns `Unattributable`; returning a
/// low-confidence guess as `Attributed` and letting the caller sort it out is
/// the failure mode this trait exists to prevent.
#[async_trait]
pub trait RoleAttributor: Send + Sync {
    async fn attribute(
        &self,
        request: &AttributionRequest,
    ) -> Result<AttributionOutcome, ReedeError>;
}

/// The fail-closed attributor: refuses everything.
///
/// Used where no attributor is configured. Without it the tempting default is
/// "attribute to the only role we know about", which is a guess wearing a
/// verdict's clothes.
pub struct NeverAttributes;

#[async_trait]
impl RoleAttributor for NeverAttributes {
    async fn attribute(
        &self,
        _request: &AttributionRequest,
    ) -> Result<AttributionOutcome, ReedeError> {
        Ok(AttributionOutcome::Unattributable {
            reason: "no attributor configured".to_string(),
        })
    }
}

/// Validate a verdict against the request that produced it.
///
/// A model can return a role that was never a candidate, or a confidence
/// outside 0..1. Both are treated as a refusal rather than an error: the point
/// is that the signal stays unattributed, and a malformed verdict is exactly as
/// unusable as an honest "I cannot tell".
pub fn vet_outcome(
    request: &AttributionRequest,
    outcome: AttributionOutcome,
    min_confidence: f64,
) -> AttributionOutcome {
    match outcome {
        AttributionOutcome::Attributed { role, confidence } => {
            if !request.candidates.iter().any(|c| c.role == role) {
                return AttributionOutcome::Unattributable {
                    reason: format!("named role {role:?} was not among the run's candidates"),
                };
            }
            // ...and the candidate list itself must be made of real keys. Being a
            // candidate proves only that the *caller* named it; a caller passing
            // bare step names would have every verdict pass this check and then
            // stamp a scope the registry never issued, which `Signal::role_key`
            // would refuse at the store and which nothing before that would
            // explain. Checking it here names the caller's mistake instead.
            match RoleKey::parse(&role) {
                Ok(key) if key.as_key() == role => {}
                Ok(key) => {
                    return AttributionOutcome::Unattributable {
                        reason: format!(
                            "named role {role:?} is not canonical; it would be stored as \
                             {:?} and read from somewhere else",
                            key.as_key()
                        ),
                    };
                }
                Err(error) => {
                    return AttributionOutcome::Unattributable {
                        reason: format!("named role {role:?} is not a usable role key: {error}"),
                    };
                }
            }
            if !(0.0..=1.0).contains(&confidence) {
                return AttributionOutcome::Unattributable {
                    reason: format!("confidence {confidence} is outside 0..1"),
                };
            }
            if confidence < min_confidence {
                return AttributionOutcome::Unattributable {
                    reason: format!("confidence {confidence} below threshold {min_confidence}"),
                };
            }
            AttributionOutcome::Attributed { role, confidence }
        }
        refusal => refusal,
    }
}

/// Stamp a vetted verdict onto a signal.
///
/// An `Attributed` verdict marks the signal `Inferred`, never `Explicit`: this
/// role was worked out after the fact, and conflating that with what a surface
/// actually recorded would erase the distinction D5 is built on. A refusal
/// leaves the signal exactly as it was -- unattributed, storable, unpromotable.
pub fn apply_attribution(signal: &mut Signal, outcome: &AttributionOutcome) {
    if let AttributionOutcome::Attributed { role, .. } = outcome {
        signal.role = Some(role.clone());
        signal.attribution_source = AttributionSource::Inferred;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::SignalKind;

    fn request() -> AttributionRequest {
        AttributionRequest {
            tenant_id: "tenant-1".to_string(),
            run_id: "run-1".to_string(),
            criticism: "the billing figure was wrong".to_string(),
            candidates: vec![
                RoleOutput {
                    role: "copy/product".to_string(),
                    output: "...".to_string(),
                },
                RoleOutput {
                    role: "copy/account-history".to_string(),
                    output: "...".to_string(),
                },
            ],
        }
    }

    fn signal() -> Signal {
        Signal::builder("sub_1")
            .tenant("tenant-1")
            .capability("copy")
            .kind(SignalKind::Rating)
            .idempotency("k-1")
            .run("run-1")
            .build()
    }

    #[tokio::test]
    async fn never_attributes_refuses_rather_than_picking_the_only_candidate() {
        let mut req = request();
        req.candidates.truncate(1);
        let out = NeverAttributes.attribute(&req).await.unwrap();
        assert!(matches!(out, AttributionOutcome::Unattributable { .. }));
    }

    #[test]
    fn a_role_that_was_never_a_candidate_is_refused() {
        let out = vet_outcome(
            &request(),
            AttributionOutcome::Attributed {
                role: "copy/legal".to_string(),
                confidence: 0.99,
            },
            0.7,
        );
        assert!(matches!(out, AttributionOutcome::Unattributable { .. }));
    }

    #[test]
    fn confidence_below_threshold_is_refused_not_downgraded() {
        let out = vet_outcome(
            &request(),
            AttributionOutcome::Attributed {
                role: "copy/product".to_string(),
                confidence: 0.4,
            },
            0.7,
        );
        assert!(
            matches!(out, AttributionOutcome::Unattributable { .. }),
            "a weak verdict must refuse, never promote as a guess"
        );
    }

    #[test]
    fn confidence_outside_the_unit_interval_is_refused() {
        for bad in [-0.1_f64, 1.5] {
            let out = vet_outcome(
                &request(),
                AttributionOutcome::Attributed {
                    role: "copy/product".to_string(),
                    confidence: bad,
                },
                0.7,
            );
            assert!(
                matches!(out, AttributionOutcome::Unattributable { .. }),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_good_verdict_survives_vetting() {
        let out = vet_outcome(
            &request(),
            AttributionOutcome::Attributed {
                role: "copy/product".to_string(),
                confidence: 0.9,
            },
            0.7,
        );
        assert_eq!(out.role(), Some("copy/product"));
    }

    /// Being a candidate is not enough: the key has to be one.
    ///
    /// A caller that fills `candidates` with bare step names would otherwise have
    /// every verdict pass vetting and stamp a scope the registry never issued.
    /// The store refuses that row, far from the caller that caused it.
    #[test]
    fn a_candidate_that_is_not_a_canonical_key_is_still_refused() {
        for bad in ["summarize", "Copy/Product", "copy/"] {
            let mut req = request();
            req.candidates.push(RoleOutput {
                role: bad.to_string(),
                output: "...".to_string(),
            });
            let out = vet_outcome(
                &req,
                AttributionOutcome::Attributed {
                    role: bad.to_string(),
                    confidence: 0.99,
                },
                0.7,
            );
            assert!(
                matches!(out, AttributionOutcome::Unattributable { .. }),
                "{bad:?} is not a role key, however confidently it is named"
            );
        }
    }

    #[test]
    fn applying_a_verdict_marks_it_inferred_and_makes_it_promotable() {
        let mut s = signal();
        assert!(!s.is_promotable());
        apply_attribution(
            &mut s,
            &AttributionOutcome::Attributed {
                role: "copy/product".to_string(),
                confidence: 0.9,
            },
        );
        assert_eq!(s.role.as_deref(), Some("copy/product"));
        assert_eq!(
            s.attribution_source,
            AttributionSource::Inferred,
            "worked out after the fact is never Explicit"
        );
        assert!(s.is_promotable());
    }

    #[test]
    fn a_refusal_leaves_the_signal_unattributed_and_unpromotable() {
        let mut s = signal();
        apply_attribution(
            &mut s,
            &AttributionOutcome::Unattributable {
                reason: "too vague".to_string(),
            },
        );
        assert_eq!(s.role, None);
        assert_eq!(s.attribution_source, AttributionSource::None);
        assert!(!s.is_promotable());
    }
}
