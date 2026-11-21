//! Govern the feedback subsystem's own outbound writes.
//!
//! The feedback subsystem (the signal/inquiry/consumer spine) performs two kinds of *outbound*
//! write of its own that, until now, bypassed the leash entirely:
//!
//! 1. **inquiry respondent notify** -- the write-back loop's "your answer
//!    shipped" interruption (`inquiry::may_notify_respondent` only ever decided
//!    *whether* the attention budget allowed it; the actual send was left to
//!    the caller, unaudited, off any policy check, emitting no receipt).
//! 2. **lesson-delta application** -- `consumer::ConsumerStore::apply_delta`
//!    flips an approved delta to `Applied` and mutates the agent's live
//!    instruction set, a genuine behaviour-changing write that produced no
//!    receipt and passed through no policy check.
//!
//! Every other Reede action crosses one choke point: `Gateway::call_tool`
//! (S1, #1615), where the run's `DerivedPolicy` is checked -- a resource grant
//! the run does not hold yields `ReedeError::GrantDenied` and the call never
//! reaches dispatch. This module routes both the feedback subsystem writes through that same
//! seam, so each is (a) policy-checked at the gateway and (b) emits a chained,
//! signed `ExecutionReceipt` into the *same* tenant receipt chain as any other
//! governed action. A human-interruption write (respondent notify)
//! additionally passes the `AttentionBudget` check first, per the design brief.
//!
//! ## S8: folded into the unified send seam
//!
//! S7 originally routed the feedback subsystem's writes through the S1 gateway directly, as a
//! stopgap until S8's unified outbound send-seam existed. S8 (`reede::send`)
//! now exists, so `notify_respondent` -- a *message send* -- delegates its
//! actual send + receipt to `send_outbound`, the one audited seam shared with
//! the omnichannel transports and the HITL webhook. There is one seam, not two.
//! Its grant id moved into the unified `outbound/respondent_notify` namespace
//! (`TOOL_NOTIFY_RESPONDENT` aliases it). `apply_lesson_delta` is an internal
//! write, not an outbound message, so it stays on the direct gateway route.
//!
//! ## The seam is the only governed path
//!
//! Reede exposes no other function that performs either write *with* an audit
//! trail: the raw `ConsumerStore::apply_delta` still exists (it is the storage
//! primitive this seam calls *after* the policy check), but a caller who wants
//! the write to be governed -- policy-checked and receipted -- has exactly one
//! entry point per write, the two functions below. `test_apply_lesson_delta_*`
//! proves the storage write does not happen at all when the gateway denies.

use crate::attention_budget::{AskDecision, AttentionBudget};
use crate::consumer::ConsumerStore;
use crate::error::ReedeError;
use crate::gateway::{Gateway, TaskContext, ToolResponse};
use crate::inquiry::may_notify_respondent;
use crate::receipt::{emit_execution_receipt, ExecutionReceipt, ReceiptSigner, ReceiptStore};
use crate::send::{
    send_outbound, OutboundChannel, OutboundMessage, SendRegistry, TOOL_OUTBOUND_RESPONDENT_NOTIFY,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

/// shortcut: legacy idempotency-key prefix, still written. Stored send claims are keyed on
/// it, so renaming it would let a retry across an upgrade send twice; rename with a data
/// migration.
const LEGACY_NOTIFY_KEY_PREFIX: &str = "weeger:notify";

/// shortcut: legacy receipt-summary strings, still written. They are part of the signed
/// `payload_summary` that `validate_operation_receipt` recomputes and compares, so changing them
/// would fail re-validation of every stored lesson application; rename only with a receipt
/// format version bump.
pub(crate) const LEGACY_APPLY_SUMMARY_PREFIX: &str = "weeger:apply_lesson_delta";
pub(crate) const LEGACY_APPLY_SUMMARY_ACTION: &str = "weeger/apply_lesson_delta";
pub(crate) const LEGACY_ROLLBACK_SUMMARY_ACTION: &str = "weeger/rollback_lesson_delta";

/// Stable, injective identity for a respondent notification.  The operation
/// identity is tenant-scoped and includes every value that changes the
/// notification, so delimiter-bearing values cannot alias one another.
pub fn respondent_notify_idempotency_key(
    tenant_id: &str,
    identity_key: &str,
    response_signal_id: &str,
    shipped_ref: &str,
) -> String {
    let fields = crate::receipt::encode_fields_injective(&[
        tenant_id,
        identity_key,
        response_signal_id,
        shipped_ref,
    ]);
    format!(
        "{LEGACY_NOTIFY_KEY_PREFIX}:{}",
        hex::encode(Sha256::digest(fields))
    )
}

/// Gateway tool identifier for the inquiry respondent-notify send.
///
/// S8: this is now an alias into the unified outbound-messaging namespace
/// (`outbound/respondent_notify`). The respondent notify is a message send, so
/// it travels the one audited send seam (`reede::send`) like every other
/// outbound path — not a second bespoke path. A manifest grant for this id
/// governs it exactly as before.
pub const TOOL_NOTIFY_RESPONDENT: &str = TOOL_OUTBOUND_RESPONDENT_NOTIFY;
/// Qualified gateway tool identifier for applying an approved lesson delta.
///
/// Unlike the respondent notify, applying a lesson delta is an internal
/// behaviour-changing *write*, not an outbound message, so it stays on the S1
/// gateway route rather than the outbound send seam.
pub const TOOL_APPLY_LESSON_DELTA: &str = "feedback/apply_lesson_delta";
/// Pre-rename id of [`TOOL_APPLY_LESSON_DELTA`]; manifests and stored grants may still carry it.
pub const LEGACY_TOOL_APPLY_LESSON_DELTA: &str = "weeger/apply_lesson_delta";

/// A governed feedback-subsystem write that actually happened: the gateway tool response
/// it went through, and the receipt it produced. Callers that need to prove
/// the write was audited hold onto `receipt`.
#[derive(Debug, Clone)]
pub struct GovernedWrite {
    /// The qualified tool identifier the write was governed under.
    pub tool: &'static str,
    /// The gateway's response for the tool call (audit metadata: duration,
    /// hosts contacted).
    pub tool_response: ToolResponse,
    /// The chained, signed execution receipt appended for this write.
    pub receipt: ExecutionReceipt,
}

/// The one respondent-notify a write-back loop wants to send. Kept minimal and
/// serializable so it becomes the gateway `call_tool` input verbatim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RespondentNotice {
    /// The response signal that opened this write-back link.
    pub response_signal_id: String,
    /// The shipped change being announced ("your answer shipped in ...").
    pub shipped_ref: String,
    /// Human-facing summary of what shipped. Kept short; not the full text.
    pub summary: String,
}

/// Outcome of a governed respondent notify. A budget refusal is an expected,
/// non-error result (exactly as `AttentionBudget::may_ask` returns `Refused`):
/// no interruption is sent, no gateway call is made, and no receipt is emitted.
// Keep the established public payload type despite its larger enum variant.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum NotifyOutcome {
    /// The attention budget refused the interruption; nothing was sent.
    BudgetRefused { retry_after: DateTime<Utc> },
    /// The notify passed budget + policy and was sent and receipted.
    Notified(GovernedWrite),
}

/// Governed inquiry respondent notify, sent through the unified S8 seam.
///
/// Order is load-bearing: (1) attention-budget check -- a refused interruption
/// short-circuits before any send, so it costs neither a gateway call nor a
/// receipt; (2) `send_outbound` -- the one audited seam, which applies the
/// policy choke point (a run lacking the `outbound/respondent_notify` grant is
/// stopped with `GrantDenied`, and the budget is *not* spent) and, on success,
/// emits exactly one receipt into the tenant chain; (3) only after the send
/// succeeds is the budget spent. The respondent notify is an *internal*
/// write-back surface, so the seam skips the egress check for it.
///
/// The idempotency key ties the notify to the response signal + shipped ref, so
/// a retried write-back loop does not emit a second interruption receipt.
#[allow(clippy::too_many_arguments)]
pub async fn notify_respondent(
    gateway: &dyn Gateway,
    ctx: &TaskContext,
    budget: &dyn AttentionBudget,
    identity_key: &str,
    signer: &dyn ReceiptSigner,
    receipt_store: &dyn ReceiptStore,
    registry: &dyn SendRegistry,
    notice: &RespondentNotice,
    now: DateTime<Utc>,
) -> Result<NotifyOutcome, ReedeError> {
    let idempotency_key = respondent_notify_idempotency_key(
        &ctx.tenant_id,
        identity_key,
        &notice.response_signal_id,
        &notice.shipped_ref,
    );

    // Exact replays resolve before the attention budget. A completed send is
    // already proof that this interruption was approved and recorded; checking
    // the cooldown again could incorrectly turn a harmless retry into a
    // refusal and must never charge the budget a second time.
    if let Some(prior) = registry
        .get(ctx, &idempotency_key, OutboundChannel::RespondentNotify)
        .await?
    {
        return Ok(NotifyOutcome::Notified(GovernedWrite {
            tool: TOOL_NOTIFY_RESPONDENT,
            tool_response: prior.tool_response,
            receipt: prior.receipt,
        }));
    }

    // (1) Attention budget: a "your answer shipped" notice is an interruption
    // and draws from the same budget an ask does. Refusal is not an
    // error -- no send, no receipt.
    if let AskDecision::Refused { retry_after } =
        may_notify_respondent(budget, identity_key, now).await?
    {
        return Ok(NotifyOutcome::BudgetRefused { retry_after });
    }

    // (2) The one audited send seam: policy choke point + single receipt. A
    // denying policy blocks the write here (before the budget is spent).
    let msg = OutboundMessage {
        channel: OutboundChannel::RespondentNotify,
        destination: String::new(), // internal write-back surface: no egress host
        recipient: identity_key.to_string(),
        summary: notice.summary.clone(),
        idempotency_key,
        payload: json!({
            "response_signal_id": notice.response_signal_id,
            "shipped_ref": notice.shipped_ref,
            "summary": notice.summary,
            "identity_key": identity_key,
        }),
    };
    let sent = send_outbound(gateway, ctx, signer, receipt_store, registry, msg).await?;

    // A replay already happened in an earlier attempt; only newly dispatched
    // interruptions consume attention budget.
    if !sent.deduplicated {
        budget.record_ask(identity_key, now).await?;
    }

    Ok(NotifyOutcome::Notified(GovernedWrite {
        tool: TOOL_NOTIFY_RESPONDENT,
        tool_response: sent.tool_response,
        receipt: sent.receipt,
    }))
}

/// Governed lesson-delta application.
///
/// The gateway policy check runs *before* the storage write, so a run lacking
/// the `feedback/apply_lesson_delta` grant can never mutate the agent's live
/// instruction set: `GrantDenied` returns before `ConsumerStore::apply_delta`
/// is ever called, and no receipt is emitted. On success the delta is applied
/// (assigning its monotonic version) and a receipt naming the delta and the
/// assigned version is chained into the tenant receipt chain.
///
/// Returns the assigned version alongside the governed-write record.
#[allow(clippy::too_many_arguments)]
pub async fn apply_lesson_delta(
    gateway: &dyn Gateway,
    ctx: &TaskContext,
    consumer: &dyn ConsumerStore,
    signer: &dyn ReceiptSigner,
    receipt_store: &dyn ReceiptStore,
    tenant_id: &str,
    delta_id: &str,
) -> Result<(u32, GovernedWrite), ReedeError> {
    // Policy choke point FIRST -- the storage write must not happen if the
    // gateway denies.
    let input = json!({
        "tenant_id": tenant_id,
        "delta_id": delta_id,
    });
    let tool_response = gateway
        .call_tool(ctx, TOOL_APPLY_LESSON_DELTA, input)
        .await?;

    // The actual behaviour-changing write (requires an Approved delta).
    let version = consumer.apply_delta(tenant_id, delta_id).await?;

    let payload_summary =
        format!("{LEGACY_APPLY_SUMMARY_PREFIX} delta={delta_id} version={version}");
    let receipt = emit_execution_receipt(
        signer,
        receipt_store,
        ctx.task_id,
        &ctx.tenant_id,
        payload_summary,
        0,
        0,
        0,
        None,
    )
    .await?;

    Ok((
        version,
        GovernedWrite {
            tool: TOOL_APPLY_LESSON_DELTA,
            tool_response,
            receipt,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attention_budget::InMemoryAttentionBudget;
    use crate::consumer::{InMemoryConsumerStore, LessonDelta};
    use crate::policy::{DerivedPolicy, ResourceGrant};
    use crate::receipt::{verify_chain, InMemoryReceiptSigner, InMemoryReceiptStore};
    use crate::send::InMemorySendRegistry;
    use async_trait::async_trait;
    use serde_json::Value;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// A test double for `Gateway` that mirrors `CapabilityGateway::call_tool`
    /// faithfully: it applies the *real* `grant_permits` policy check at the
    /// choke point, so "a denying policy blocks it" is exercised by the same
    /// predicate production uses, not a stand-in. Records the tool calls that
    /// pass the check.
    #[derive(Default)]
    struct RecordingGateway {
        calls: Mutex<Vec<(String, Value)>>,
    }

    impl RecordingGateway {
        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Gateway for RecordingGateway {
        async fn call_model(
            &self,
            _ctx: &TaskContext,
            _req: crate::gateway::ModelRequest,
        ) -> Result<crate::gateway::ModelResponse, ReedeError> {
            Err(ReedeError::GatewayUnavailable {
                reason: "model calls are not exercised by govern tests".to_string(),
            })
        }

        async fn call_tool(
            &self,
            ctx: &TaskContext,
            tool: &str,
            input: Value,
        ) -> Result<ToolResponse, ReedeError> {
            // Same fail-closed grant check the real gateway performs.
            if !crate::policy::grant_permits(&ctx.policy.resource_grants, tool, "invoke") {
                return Err(ReedeError::GrantDenied {
                    resource: tool.to_string(),
                    action: "invoke".to_string(),
                });
            }
            self.calls
                .lock()
                .unwrap()
                .push((tool.to_string(), input.clone()));
            Ok(ToolResponse {
                output: json!({ "ok": true }),
                duration_ms: 1,
                hosts_contacted: vec![],
            })
        }
    }

    fn ctx_with_grants(grants: Vec<&str>) -> TaskContext {
        let resource_grants = grants
            .into_iter()
            .map(|g| ResourceGrant::new(g, vec!["invoke".to_string()]))
            .collect();
        TaskContext {
            task_id: Uuid::new_v4(),
            tenant_id: "tenant-weeger".to_string(),
            agent_spec_id: "weeger-agent".to_string(),
            policy: DerivedPolicy {
                agent_id: "weeger-agent".to_string(),
                budget_ceiling_eur: 50.0,
                hitl_above_credits: 10,
                egress_allowlist: vec![],
                resource_grants,
            },
            lease_id: None,
            receipt_chain_head: None,
            capture_content: false,
            token_budget: None,
        }
    }

    #[tokio::test]
    async fn authorize_accepts_the_legacy_apply_grant_and_refuses_others() {
        let gw = RecordingGateway::default();
        for granted in [TOOL_APPLY_LESSON_DELTA, LEGACY_TOOL_APPLY_LESSON_DELTA] {
            let ctx = ctx_with_grants(vec![granted]);
            assert!(gw
                .authorize_tool(&ctx, TOOL_APPLY_LESSON_DELTA)
                .await
                .is_ok());
        }
        let ctx = ctx_with_grants(vec!["feedback/something_else"]);
        assert!(gw
            .authorize_tool(&ctx, TOOL_APPLY_LESSON_DELTA)
            .await
            .is_err());
    }

    fn notice() -> RespondentNotice {
        RespondentNotice {
            response_signal_id: "sig_resp_1".to_string(),
            shipped_ref: "pr-#1381".to_string(),
            summary: "the 20 MB GPX upload limit is fixed".to_string(),
        }
    }

    // ---- respondent notify -------------------------------------------------

    #[tokio::test]
    async fn test_notify_respondent_permitted_sends_and_emits_receipt() {
        let gateway = RecordingGateway::default();
        let budget = InMemoryAttentionBudget::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let registry = InMemorySendRegistry::new();
        let ctx = ctx_with_grants(vec![TOOL_NOTIFY_RESPONDENT]);
        let now = Utc::now();

        let outcome = notify_respondent(
            &gateway,
            &ctx,
            &budget,
            "visitor-1",
            &signer,
            &store,
            &registry,
            &notice(),
            now,
        )
        .await
        .unwrap();

        let gw = match outcome {
            NotifyOutcome::Notified(gw) => gw,
            other => panic!("expected Notified, got {other:?}"),
        };
        assert_eq!(gw.tool, TOOL_NOTIFY_RESPONDENT);
        assert_eq!(gw.receipt.sequence_no, 1);

        // The write went through the gateway choke point (via the send seam).
        assert_eq!(gateway.calls().len(), 1);
        assert_eq!(gateway.calls()[0].0, TOOL_NOTIFY_RESPONDENT);

        // A receipt was chained into the tenant chain.
        let chain = store.chain("tenant-weeger").await.unwrap();
        assert_eq!(chain.len(), 1);
        assert!(chain[0].payload_summary.contains("respondent_notify"));

        // The interruption was spent against the budget.
        assert!(matches!(
            budget.may_ask("visitor-1", false, now).await.unwrap(),
            AskDecision::Refused { .. }
        ));
    }

    #[tokio::test]
    async fn test_notify_respondent_denied_by_policy_blocks_and_emits_no_receipt() {
        let gateway = RecordingGateway::default();
        let budget = InMemoryAttentionBudget::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let registry = InMemorySendRegistry::new();
        // No grant for outbound/respondent_notify.
        let ctx = ctx_with_grants(vec!["feedback/something_else"]);
        let now = Utc::now();

        let err = notify_respondent(
            &gateway,
            &ctx,
            &budget,
            "visitor-2",
            &signer,
            &store,
            &registry,
            &notice(),
            now,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ReedeError::GrantDenied { .. }),
            "a denying policy must block the notify at the gateway, got {err:?}"
        );

        // No receipt, no recorded gateway call.
        assert!(store.chain("tenant-weeger").await.unwrap().is_empty());
        assert!(gateway.calls().is_empty());

        // Budget must NOT have been spent -- nothing was interrupted.
        assert_eq!(
            budget.may_ask("visitor-2", false, now).await.unwrap(),
            AskDecision::Allowed
        );
    }

    #[tokio::test]
    async fn test_notify_respondent_replay_does_not_record_attention_again() {
        let gateway = RecordingGateway::default();
        let budget = InMemoryAttentionBudget::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let registry = InMemorySendRegistry::new();
        let ctx = ctx_with_grants(vec![TOOL_NOTIFY_RESPONDENT]);
        let now = Utc::now();

        let first = notify_respondent(
            &gateway,
            &ctx,
            &budget,
            "visitor-replay",
            &signer,
            &store,
            &registry,
            &notice(),
            now,
        )
        .await
        .unwrap();
        let first_receipt = match &first {
            NotifyOutcome::Notified(write) => write.receipt.clone(),
            other => panic!("expected first notify, got {other:?}"),
        };
        let second = notify_respondent(
            &gateway,
            &ctx,
            &budget,
            "visitor-replay",
            &signer,
            &store,
            &registry,
            &notice(),
            now,
        )
        .await;
        assert!(matches!(first, NotifyOutcome::Notified(_)));
        assert!(matches!(&second, Ok(NotifyOutcome::Notified(_))));
        let second_receipt = match second.unwrap() {
            NotifyOutcome::Notified(write) => write.receipt,
            other => panic!("expected replay notify, got {other:?}"),
        };
        assert_eq!(first_receipt, second_receipt);
        assert!(matches!(
            budget.may_ask("visitor-replay", false, now).await.unwrap(),
            AskDecision::Refused { .. }
        ));
        assert_eq!(gateway.calls().len(), 1);
        assert_eq!(store.chain("tenant-weeger").await.unwrap().len(), 1);
    }

    #[test]
    fn respondent_notify_key_is_injective_and_tenant_scoped() {
        let left = respondent_notify_idempotency_key("tenant:a", "visitor", "signal", "ref");
        let right = respondent_notify_idempotency_key("tenant", "a:visitor", "signal", "ref");
        let other_tenant =
            respondent_notify_idempotency_key("tenant:b", "visitor", "signal", "ref");
        assert_ne!(left, right);
        assert_ne!(left, other_tenant);
    }

    #[tokio::test]
    async fn test_notify_respondent_budget_refused_short_circuits_before_gateway() {
        let gateway = RecordingGateway::default();
        let budget = InMemoryAttentionBudget::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let registry = InMemorySendRegistry::new();
        let ctx = ctx_with_grants(vec![TOOL_NOTIFY_RESPONDENT]);
        let now = Utc::now();

        // Put the identity in cooldown.
        budget.record_ask("visitor-3", now).await.unwrap();

        let outcome = notify_respondent(
            &gateway,
            &ctx,
            &budget,
            "visitor-3",
            &signer,
            &store,
            &registry,
            &notice(),
            now,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, NotifyOutcome::BudgetRefused { .. }));
        // Neither the gateway nor the receipt store were touched.
        assert!(gateway.calls().is_empty());
        assert!(store.chain("tenant-weeger").await.unwrap().is_empty());
    }

    // ---- lesson-delta application ------------------------------------------

    async fn approved_delta(consumer: &InMemoryConsumerStore, tenant: &str) -> String {
        let delta = LessonDelta::propose(
            tenant,
            "weeger-agent",
            "battlecard",
            "specificity",
            "cite the source deep link for every claim",
            3,
        );
        let id = delta.id.clone();
        consumer.propose_delta(&delta).await.unwrap();
        consumer
            .approve_delta(tenant, &id, "owner@example.com")
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn test_apply_lesson_delta_permitted_applies_and_emits_receipt() {
        let gateway = RecordingGateway::default();
        let consumer = InMemoryConsumerStore::new();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let ctx = ctx_with_grants(vec![TOOL_APPLY_LESSON_DELTA]);
        let delta_id = approved_delta(&consumer, "tenant-weeger").await;

        let (version, gw) = apply_lesson_delta(
            &gateway,
            &ctx,
            &consumer,
            &signer,
            &store,
            "tenant-weeger",
            &delta_id,
        )
        .await
        .unwrap();

        assert_eq!(version, 1);
        assert_eq!(gw.tool, TOOL_APPLY_LESSON_DELTA);
        assert!(gw.receipt.payload_summary.contains(&delta_id));

        // The delta actually applied.
        let applied = consumer
            .applied_deltas("tenant-weeger", "weeger-agent", "battlecard")
            .await
            .unwrap();
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].version, 1);

        // Went through the gateway and produced a receipt.
        assert_eq!(gateway.calls().len(), 1);
        assert_eq!(store.chain("tenant-weeger").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_apply_lesson_delta_denied_by_policy_blocks_write_and_receipt() {
        let gateway = RecordingGateway::default();
        let consumer = InMemoryConsumerStore::new();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        // No grant for feedback/apply_lesson_delta.
        let ctx = ctx_with_grants(vec![]);
        let delta_id = approved_delta(&consumer, "tenant-weeger").await;

        let err = apply_lesson_delta(
            &gateway,
            &ctx,
            &consumer,
            &signer,
            &store,
            "tenant-weeger",
            &delta_id,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ReedeError::GrantDenied { .. }),
            "a denying policy must block the apply at the gateway, got {err:?}"
        );

        // The behaviour-changing write must NOT have happened.
        let applied = consumer
            .applied_deltas("tenant-weeger", "weeger-agent", "battlecard")
            .await
            .unwrap();
        assert!(
            applied.is_empty(),
            "the lesson delta must not be applied when the gateway denies"
        );
        // No receipt, no gateway call recorded.
        assert!(store.chain("tenant-weeger").await.unwrap().is_empty());
        assert!(gateway.calls().is_empty());
    }

    // ---- shared receipt chain ---------------------------------------------

    #[tokio::test]
    async fn test_governed_writes_chain_into_one_tenant_receipt_chain() {
        let gateway = RecordingGateway::default();
        let budget = InMemoryAttentionBudget::default();
        let consumer = InMemoryConsumerStore::new();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let registry = InMemorySendRegistry::new();
        let ctx = ctx_with_grants(vec![TOOL_NOTIFY_RESPONDENT, TOOL_APPLY_LESSON_DELTA]);
        let now = Utc::now();

        notify_respondent(
            &gateway,
            &ctx,
            &budget,
            "visitor-x",
            &signer,
            &store,
            &registry,
            &notice(),
            now,
        )
        .await
        .unwrap();

        let delta_id = approved_delta(&consumer, "tenant-weeger").await;
        apply_lesson_delta(
            &gateway,
            &ctx,
            &consumer,
            &signer,
            &store,
            "tenant-weeger",
            &delta_id,
        )
        .await
        .unwrap();

        let chain = store.chain("tenant-weeger").await.unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].sequence_no, 1);
        assert_eq!(chain[1].sequence_no, 2);
        assert_eq!(chain[1].prev_hash, Some(chain[0].content_hash.clone()));
        verify_chain(&chain, None).expect("both governed writes chain cleanly");
    }
}
