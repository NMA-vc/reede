//! The unified audited outbound-messaging seam (criterion 6).
//!
//! Criterion 6 asks for *one* place where every outbound message passes one
//! policy check, one egress check, and emits exactly one idempotent
//! audit/receipt row. The audit found **two unconverged seams**: the
//! compose-managed the host gateway (email/Slack/Teams/WhatsApp/
//! threads, with its own audit + idempotency but no Reede policy/egress/receipt
//! check) and the runtime + the feedback subsystem write-backs (HMAC HITL webhook, respondent
//! notify). Nothing forced every send through a single choke point.
//!
//! This module is that choke point, reede-native (host-independent, one-way dep
//! preserved). It reuses the S1 gateway (`Gateway::call_tool`, the
//! `DerivedPolicy` grant check) and the S5/S7 receipt helper
//! (`emit_execution_receipt`, the `reede-v1` injective encoding + chained
//! signing), so the offline verifier and golden vector still hold for whatever
//! it writes.
//!
//! ## The interface the host-side transports call
//!
//! [`OutboundSeam`] is the one interface every outbound path calls.
//! [`AuditedSendSeam`] is the reference implementation. A **host-side**
//! adapter (the `[prod]` remainder, see the S8 design note) implements
//! `OutboundSeam` over the real `CapabilityGateway` + durable receipt store +
//! durable [`SendRegistry`] and rewires each omnichannel transport and the
//! runtime HITL webhook to build an [`OutboundMessage`] and call `send`. That
//! wiring is not done here (it touches compose-managed infra under the
//! deployment lockdown); the interface it wires onto is.
//!
//! ## No bypass
//!
//! `send.rs` is the only reede module that names an `outbound/*` tool id. The
//! `no_outbound_send_bypasses_the_seam` test asserts the `"outbound/` literal
//! appears in no other `reede/src` file, so any outbound send can only reach an
//! `outbound/*` grant through this seam.

use crate::egress::{AllowlistEgress, EgressPolicy};
use crate::error::ReedeError;
use crate::gateway::{Gateway, TaskContext, ToolResponse};
use crate::receipt::{emit_execution_receipt, ExecutionReceipt, ReceiptSigner, ReceiptStore};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;

/// Stable gateway tool ids for the unified outbound namespace. A run's manifest
/// grants `outbound/<channel>` govern each send exactly like any connector tool
/// (the `server/tool` convention `CapabilityGateway` splits on).
pub const TOOL_OUTBOUND_EMAIL: &str = "outbound/email";
pub const TOOL_OUTBOUND_SLACK: &str = "outbound/slack";
pub const TOOL_OUTBOUND_TEAMS: &str = "outbound/teams";
pub const TOOL_OUTBOUND_WHATSAPP: &str = "outbound/whatsapp";
pub const TOOL_OUTBOUND_THREADS: &str = "outbound/threads";
pub const TOOL_OUTBOUND_WEBHOOK: &str = "outbound/webhook";
pub const TOOL_OUTBOUND_MEDIA_INTAKE: &str = "outbound/media_intake";
pub const TOOL_OUTBOUND_RESPONDENT_NOTIFY: &str = "outbound/respondent_notify";

/// The channel an outbound message travels over. Reede-native; the host-side
/// transports map onto these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutboundChannel {
    Email,
    Slack,
    Teams,
    WhatsApp,
    Threads,
    /// The HMAC HITL webhook (`the host runtime`).
    Webhook,
    /// Internal HTTP handoff to the compose-managed media intake service. It
    /// still crosses a network boundary and therefore remains egress-gated.
    MediaIntake,
    /// The feedback subsystem's "your answer shipped" respondent notify. Internal write-back
    /// surface — contacts no external host, so egress does not apply.
    RespondentNotify,
}

impl OutboundChannel {
    /// The stable gateway tool id this channel is policy-checked under.
    pub fn tool_id(&self) -> &'static str {
        match self {
            OutboundChannel::Email => TOOL_OUTBOUND_EMAIL,
            OutboundChannel::Slack => TOOL_OUTBOUND_SLACK,
            OutboundChannel::Teams => TOOL_OUTBOUND_TEAMS,
            OutboundChannel::WhatsApp => TOOL_OUTBOUND_WHATSAPP,
            OutboundChannel::Threads => TOOL_OUTBOUND_THREADS,
            OutboundChannel::Webhook => TOOL_OUTBOUND_WEBHOOK,
            OutboundChannel::MediaIntake => TOOL_OUTBOUND_MEDIA_INTAKE,
            OutboundChannel::RespondentNotify => TOOL_OUTBOUND_RESPONDENT_NOTIFY,
        }
    }

    /// Whether a send on this channel contacts an external host and must clear
    /// the egress allowlist. Only the internal write-back surface does not.
    pub fn is_external(&self) -> bool {
        !matches!(self, OutboundChannel::RespondentNotify)
    }
}

/// One outbound message to be sent through the audited seam.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboundMessage {
    pub channel: OutboundChannel,
    /// Host/domain/URL the egress check runs against. Required (non-empty) for
    /// an external channel; ignored for an internal one.
    pub destination: String,
    /// Logical recipient (address, thread id, …). Audit metadata only.
    pub recipient: String,
    /// Short human-facing summary, recorded verbatim in the receipt payload.
    pub summary: String,
    /// De-duplication key. A repeated key emits no second receipt.
    pub idempotency_key: String,
    /// Transport-specific body handed to the gateway `call_tool` input.
    pub payload: serde_json::Value,
}

/// The result of a governed send: proof it was policy/egress-checked and
/// receipted. `deduplicated` is true when this was a replay of an
/// already-sent idempotency key (the receipt is the original one).
#[derive(Debug, Clone)]
pub struct OutboundSend {
    pub channel: OutboundChannel,
    pub idempotency_key: String,
    pub deduplicated: bool,
    pub tool_response: ToolResponse,
    pub receipt: ExecutionReceipt,
}

/// Result of atomically claiming an outbound idempotency key.
// Keep the established public payload type despite its larger enum variant.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum SendClaim {
    /// This caller owns the pending send and may perform the transport call.
    Claimed,
    /// A completed send already exists; return it without dispatching.
    Completed(OutboundSend),
    /// Another worker currently owns the pending send.
    Pending,
    /// A prior worker may have reached the external provider, but could not
    /// durably finalize the result. Redispatch is forbidden without explicit
    /// reconciliation.
    SideEffectUnknown,
}

/// Idempotency ledger for outbound sends: key -> the prior [`OutboundSend`], so
/// a replay short-circuits before any second gateway call or receipt. A
/// host-side durable impl (SurrealDB, keyed off the omnichannel idempotency
/// hash) backs it in prod; this trait keeps that binding one-way.
#[async_trait]
pub trait SendRegistry: Send + Sync {
    /// The completed prior send for `key`, if any.
    async fn get(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<Option<OutboundSend>, ReedeError>;
    /// Atomically claim `key` before the external transport is invoked.
    async fn claim(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<SendClaim, ReedeError>;
    /// Finalize a claim with the completed receipt and transport result.
    async fn finalize(
        &self,
        ctx: &TaskContext,
        key: &str,
        send: &OutboundSend,
    ) -> Result<(), ReedeError>;
    /// Permanently fence a claim after a transport call or post-send durable
    /// step failed. This must never make the key dispatchable again.
    async fn mark_side_effect_unknown(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<(), ReedeError>;
    /// Return a webhook claim to the retryable state. Webhook receivers get
    /// the stable idempotency key and can deduplicate a request that succeeded
    /// remotely but whose response was lost; a later inbound redelivery may
    /// therefore safely resume a failed callback.
    async fn mark_retryable(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<(), ReedeError>;
}

/// In-memory reference [`SendRegistry`].
#[derive(Default)]
pub struct InMemorySendRegistry {
    sent: Mutex<HashMap<(String, OutboundChannel, String), InMemorySendState>>,
}

#[derive(Clone)]
enum InMemorySendState {
    Pending,
    SideEffectUnknown,
    Retryable,
    Completed(Box<OutboundSend>),
}

impl InMemorySendRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SendRegistry for InMemorySendRegistry {
    async fn get(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<Option<OutboundSend>, ReedeError> {
        let scoped_key = (ctx.tenant_id.clone(), channel, key.to_string());
        Ok(match self.sent.lock().unwrap().get(&scoped_key) {
            Some(InMemorySendState::Completed(send)) => Some(send.as_ref().clone()),
            _ => None,
        })
    }

    async fn claim(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<SendClaim, ReedeError> {
        let mut sent = self.sent.lock().unwrap();
        let scoped_key = (ctx.tenant_id.clone(), channel, key.to_string());
        Ok(match sent.get(&scoped_key) {
            Some(InMemorySendState::Completed(send)) => SendClaim::Completed(send.as_ref().clone()),
            Some(InMemorySendState::Pending) => SendClaim::Pending,
            Some(InMemorySendState::SideEffectUnknown) => SendClaim::SideEffectUnknown,
            Some(InMemorySendState::Retryable) => {
                sent.insert(scoped_key.clone(), InMemorySendState::Pending);
                SendClaim::Claimed
            }
            None => {
                sent.insert(scoped_key, InMemorySendState::Pending);
                SendClaim::Claimed
            }
        })
    }

    async fn finalize(
        &self,
        ctx: &TaskContext,
        key: &str,
        send: &OutboundSend,
    ) -> Result<(), ReedeError> {
        let mut sent = self.sent.lock().unwrap();
        let scoped_key = (ctx.tenant_id.clone(), send.channel, key.to_string());
        match sent.get(&scoped_key) {
            Some(InMemorySendState::Pending) => {
                sent.insert(
                    scoped_key,
                    InMemorySendState::Completed(Box::new(send.clone())),
                );
                Ok(())
            }
            Some(InMemorySendState::Completed(existing)) if existing.receipt == send.receipt => {
                Ok(())
            }
            Some(InMemorySendState::SideEffectUnknown) => {
                Err(ReedeError::OutboundSideEffectUnknown {
                    key: key.to_string(),
                })
            }
            _ => Err(ReedeError::GatewayError {
                reason: format!("outbound-seam finalize without claim: {key}"),
            }),
        }
    }

    async fn mark_side_effect_unknown(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<(), ReedeError> {
        let mut sent = self.sent.lock().unwrap();
        let scoped_key = (ctx.tenant_id.clone(), channel, key.to_string());
        if !sent.contains_key(&scoped_key) {
            return Err(ReedeError::GatewayError {
                reason: format!("outbound-seam unknown-side-effect mark without claim: {key}"),
            });
        }
        let pending = match sent.get(&scoped_key) {
            Some(InMemorySendState::Pending) => true,
            Some(InMemorySendState::SideEffectUnknown)
            | Some(InMemorySendState::Completed(_))
            | Some(InMemorySendState::Retryable)
            | None => false,
        };
        if pending {
            sent.insert(scoped_key, InMemorySendState::SideEffectUnknown);
        }
        Ok(())
    }

    async fn mark_retryable(
        &self,
        ctx: &TaskContext,
        key: &str,
        channel: OutboundChannel,
    ) -> Result<(), ReedeError> {
        let mut sent = self.sent.lock().unwrap();
        let scoped_key = (ctx.tenant_id.clone(), channel, key.to_string());
        if !sent.contains_key(&scoped_key) {
            return Err(ReedeError::GatewayError {
                reason: format!("outbound-seam retry mark without claim: {key}"),
            });
        }
        if matches!(sent.get(&scoped_key), Some(InMemorySendState::Pending)) {
            sent.insert(scoped_key, InMemorySendState::Retryable);
        }
        Ok(())
    }
}

/// The one audited outbound-messaging seam. Every outbound path — the
/// omnichannel transports, the HITL webhook, the feedback subsystem respondent notify —
/// calls exactly this.
#[async_trait]
pub trait OutboundSeam: Send + Sync {
    async fn send(
        &self,
        ctx: &TaskContext,
        msg: OutboundMessage,
    ) -> Result<OutboundSend, ReedeError>;
}

/// Reference implementation of [`OutboundSeam`]: policy check (gateway) +
/// egress check + exactly one idempotent receipt, in that order. Binds the four
/// collaborators; a host-side adapter binds their durable equivalents.
pub struct AuditedSendSeam<'a> {
    pub gateway: &'a dyn Gateway,
    pub signer: &'a dyn ReceiptSigner,
    pub receipts: &'a dyn ReceiptStore,
    pub registry: &'a dyn SendRegistry,
}

impl<'a> AuditedSendSeam<'a> {
    pub fn new(
        gateway: &'a dyn Gateway,
        signer: &'a dyn ReceiptSigner,
        receipts: &'a dyn ReceiptStore,
        registry: &'a dyn SendRegistry,
    ) -> Self {
        Self {
            gateway,
            signer,
            receipts,
            registry,
        }
    }
}

#[async_trait]
impl OutboundSeam for AuditedSendSeam<'_> {
    async fn send(
        &self,
        ctx: &TaskContext,
        msg: OutboundMessage,
    ) -> Result<OutboundSend, ReedeError> {
        send_outbound(
            self.gateway,
            ctx,
            self.signer,
            self.receipts,
            self.registry,
            msg,
        )
        .await
    }
}

/// The single choke point every outbound message crosses. Order is
/// load-bearing:
///
/// 1. **Idempotency claim** — a completed key returns its prior
///    `OutboundSend`; pending/unknown keys fail closed and never dispatch
///    again.
/// 2. **Egress** — an external channel's `destination` must clear the run's
///    allowlist (empty allowlist fails closed; an external channel with an
///    empty destination is denied). `EgressDenied` blocks the send with no
///    receipt and no idempotency record.
/// 3. **Policy choke point** — `gateway.authorize_tool` applies the run's
///    `DerivedPolicy` grant check before the durable claim; `call_tool` remains
///    the final dispatch boundary.
/// 4. **Exactly one receipt** — one chained, signed `reede-v1`
///    `ExecutionReceipt` into the tenant chain.
/// 5. **Finalize idempotency**. Any dispatch, receipt, or finalize failure
///    permanently marks the key side-effect-unknown, so retries cannot
///    redispatch an external action.
///
/// A denial at step 2 or 3 leaves nothing recorded: no send happened, so there
/// is nothing to audit and a retry is still allowed.
pub async fn send_outbound(
    gateway: &dyn Gateway,
    ctx: &TaskContext,
    signer: &dyn ReceiptSigner,
    receipts: &dyn ReceiptStore,
    registry: &dyn SendRegistry,
    msg: OutboundMessage,
) -> Result<OutboundSend, ReedeError> {
    // (1) Egress: an external send must clear the allowlist before claiming.
    if msg.channel.is_external() {
        let egress = AllowlistEgress::from_policy(&ctx.policy);
        if msg.destination.trim().is_empty() || !egress.is_allowed(&msg.destination) {
            return Err(ReedeError::EgressDenied {
                destination: msg.destination.clone(),
            });
        }
        if msg.recipient.trim().is_empty() {
            return Err(ReedeError::GatewayError {
                reason: format!("outbound {:?} recipient is empty", msg.channel),
            });
        }
    }

    // (2) Authorize before claiming. A missing grant must not leave a pending
    // row behind, and the concrete gateway repeats this at dispatch time.
    let tool = msg.channel.tool_id();
    gateway.authorize_tool(ctx, tool).await?;

    // (3) Atomic claim: only one worker may reach the transport for a key.
    match registry
        .claim(ctx, &msg.idempotency_key, msg.channel)
        .await?
    {
        SendClaim::Completed(prior) => {
            return Ok(OutboundSend {
                deduplicated: true,
                ..prior
            });
        }
        SendClaim::Pending => {
            return Err(ReedeError::OutboundPending {
                key: msg.idempotency_key,
            });
        }
        SendClaim::SideEffectUnknown => {
            return Err(ReedeError::OutboundSideEffectUnknown {
                key: msg.idempotency_key,
            });
        }
        SendClaim::Claimed => {}
    }

    // (4) Policy choke point and transport dispatch.
    let input = json!({
        "channel": tool,
        "destination": msg.destination,
        "recipient": msg.recipient,
        "summary": msg.summary,
        "idempotency_key": msg.idempotency_key,
        "payload": msg.payload,
    });
    let tool_response = match gateway.call_tool(ctx, tool, input).await {
        Ok(response) => response,
        Err(error) => {
            if msg.channel == OutboundChannel::Webhook {
                let _ = registry
                    .mark_retryable(ctx, &msg.idempotency_key, msg.channel)
                    .await;
            } else {
                let _ = registry
                    .mark_side_effect_unknown(ctx, &msg.idempotency_key, msg.channel)
                    .await;
            }
            return Err(error);
        }
    };

    // (5) Exactly one receipt into the tenant chain. Once transport returned,
    // any failure here is side-effect-unknown and must fence retries.
    let payload_summary = format!(
        "outbound:{} to={} key={}",
        tool, msg.recipient, msg.idempotency_key
    );
    let receipt = match emit_execution_receipt(
        signer,
        receipts,
        ctx.task_id,
        &ctx.tenant_id,
        payload_summary,
        0,
        0,
        0,
        // The operation key is the receipt's durable identity within a task;
        // one TaskContext may legitimately perform multiple distinct sends.
        Some(msg.idempotency_key.clone()),
    )
    .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            if msg.channel == OutboundChannel::Webhook {
                let _ = registry
                    .mark_retryable(ctx, &msg.idempotency_key, msg.channel)
                    .await;
            } else {
                let _ = registry
                    .mark_side_effect_unknown(ctx, &msg.idempotency_key, msg.channel)
                    .await;
            }
            return Err(error);
        }
    };

    let send = OutboundSend {
        channel: msg.channel,
        idempotency_key: msg.idempotency_key.clone(),
        deduplicated: false,
        tool_response,
        receipt,
    };

    // (6) Finalize so a later replay short-circuits at step 1. A failed
    // finalize remains fenced; never attempt the external call again.
    if let Err(error) = registry.finalize(ctx, &msg.idempotency_key, &send).await {
        if msg.channel == OutboundChannel::Webhook {
            let _ = registry
                .mark_retryable(ctx, &msg.idempotency_key, msg.channel)
                .await;
        } else {
            let _ = registry
                .mark_side_effect_unknown(ctx, &msg.idempotency_key, msg.channel)
                .await;
        }
        return Err(error);
    }

    Ok(send)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{DerivedPolicy, ResourceGrant};
    use crate::receipt::{verify_chain, InMemoryReceiptSigner, InMemoryReceiptStore};
    use serde_json::Value;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::{Barrier, Notify};
    use uuid::Uuid;

    /// Gateway double that applies the *real* `grant_permits` policy check at
    /// the choke point (same predicate production uses), and records the tool
    /// calls that pass.
    #[derive(Default)]
    struct RecordingGateway {
        calls: StdMutex<Vec<(String, Value)>>,
    }

    impl RecordingGateway {
        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().unwrap().clone()
        }
    }

    struct BlockingGateway {
        started: Arc<Notify>,
        release: Arc<Notify>,
        calls: StdMutex<usize>,
    }

    #[async_trait]
    impl Gateway for BlockingGateway {
        async fn call_model(
            &self,
            _ctx: &TaskContext,
            _req: crate::gateway::ModelRequest,
        ) -> Result<crate::gateway::ModelResponse, ReedeError> {
            Err(ReedeError::GatewayUnavailable {
                reason: "model calls are not exercised by send tests".to_string(),
            })
        }

        async fn call_tool(
            &self,
            _ctx: &TaskContext,
            _tool: &str,
            _input: Value,
        ) -> Result<ToolResponse, ReedeError> {
            *self.calls.lock().unwrap() += 1;
            self.started.notify_one();
            self.release.notified().await;
            Ok(ToolResponse {
                output: json!({ "ok": true }),
                duration_ms: 1,
                hosts_contacted: vec![],
            })
        }
    }

    struct FailingSigner;

    #[async_trait]
    impl ReceiptSigner for FailingSigner {
        fn sign(&self, _payload: &[u8]) -> Result<Vec<u8>, ReedeError> {
            Err(ReedeError::ReceiptSigningFailed {
                reason: "test signer failure".to_string(),
            })
        }

        fn verify(&self, _payload: &[u8], _signature: &[u8]) -> Result<bool, ReedeError> {
            Ok(false)
        }
    }

    struct RacingReceiptStore {
        inner: Arc<InMemoryReceiptStore>,
        first_appends: Arc<Barrier>,
        append_attempts: AtomicUsize,
    }

    #[async_trait]
    impl ReceiptStore for RacingReceiptStore {
        async fn append(&self, receipt: ExecutionReceipt) -> Result<(), ReedeError> {
            if self.append_attempts.fetch_add(1, Ordering::SeqCst) < 2 {
                self.first_appends.wait().await;
            }
            self.inner.append(receipt).await
        }

        async fn chain(&self, tenant_id: &str) -> Result<Vec<ExecutionReceipt>, ReedeError> {
            self.inner.chain(tenant_id).await
        }

        async fn latest_hash(&self, tenant_id: &str) -> Result<Option<String>, ReedeError> {
            self.inner.latest_hash(tenant_id).await
        }

        async fn latest_sequence(&self, tenant_id: &str) -> Result<u64, ReedeError> {
            self.inner.latest_sequence(tenant_id).await
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
                reason: "model calls are not exercised by send tests".to_string(),
            })
        }

        async fn call_tool(
            &self,
            ctx: &TaskContext,
            tool: &str,
            input: Value,
        ) -> Result<ToolResponse, ReedeError> {
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

    fn ctx(grants: Vec<&str>, allowlist: Vec<&str>) -> TaskContext {
        TaskContext {
            task_id: Uuid::new_v4(),
            tenant_id: "tenant-send".to_string(),
            agent_spec_id: "agent-send".to_string(),
            policy: DerivedPolicy {
                agent_id: "agent-send".to_string(),
                budget_ceiling_eur: 50.0,
                hitl_above_credits: 10,
                egress_allowlist: allowlist.into_iter().map(String::from).collect(),
                resource_grants: grants
                    .into_iter()
                    .map(|g| ResourceGrant::new(g, vec!["invoke".to_string()]))
                    .collect(),
            },
            capture_content: false,
            token_budget: None,
            lease_id: None,
            receipt_chain_head: None,
        }
    }

    fn email(key: &str) -> OutboundMessage {
        OutboundMessage {
            channel: OutboundChannel::Email,
            destination: "mail.example.eu".to_string(),
            recipient: "founder@example.eu".to_string(),
            summary: "your weekly digest".to_string(),
            idempotency_key: key.to_string(),
            payload: json!({ "subject": "Digest", "body": "..." }),
        }
    }

    #[tokio::test]
    async fn permitted_send_emits_exactly_one_receipt() {
        let gw = RecordingGateway::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let reg = InMemorySendRegistry::new();
        let ctx = ctx(vec![TOOL_OUTBOUND_EMAIL], vec!["mail.example.eu"]);

        let seam = AuditedSendSeam::new(&gw, &signer, &store, &reg);
        let out = seam.send(&ctx, email("k1")).await.unwrap();

        assert!(!out.deduplicated);
        assert_eq!(out.channel, OutboundChannel::Email);
        assert_eq!(out.receipt.sequence_no, 1);
        assert_eq!(gw.calls().len(), 1);
        assert_eq!(gw.calls()[0].0, TOOL_OUTBOUND_EMAIL);

        // Exactly one receipt in the tenant chain.
        let chain = store.chain("tenant-send").await.unwrap();
        assert_eq!(chain.len(), 1);
        assert!(chain[0].payload_summary.contains("outbound:outbound/email"));
    }

    #[tokio::test]
    async fn denying_policy_blocks_send_and_emits_no_receipt() {
        let gw = RecordingGateway::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let reg = InMemorySendRegistry::new();
        // Allowlisted destination, but NO grant for outbound/email.
        let ctx = ctx(vec!["outbound/slack"], vec!["mail.example.eu"]);

        let seam = AuditedSendSeam::new(&gw, &signer, &store, &reg);
        let err = seam.send(&ctx, email("k1")).await.unwrap_err();

        assert!(
            matches!(err, ReedeError::GrantDenied { .. }),
            "a denying policy must block the send at the gateway, got {err:?}"
        );
        assert!(store.chain("tenant-send").await.unwrap().is_empty());
        assert!(gw.calls().is_empty());
        // Nothing recorded -> a later retry is still allowed.
        assert!(reg
            .get(&ctx, "k1", OutboundChannel::Email)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn egress_denied_destination_blocks_before_gateway() {
        let gw = RecordingGateway::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let reg = InMemorySendRegistry::new();
        // Grant present, but the destination is not on the allowlist.
        let ctx = ctx(vec![TOOL_OUTBOUND_EMAIL], vec!["other.eu"]);

        let seam = AuditedSendSeam::new(&gw, &signer, &store, &reg);
        let err = seam.send(&ctx, email("k1")).await.unwrap_err();

        assert!(
            matches!(err, ReedeError::EgressDenied { .. }),
            "an off-allowlist destination must be blocked, got {err:?}"
        );
        // Egress ran before the gateway: no call, no receipt, no record.
        assert!(gw.calls().is_empty());
        assert!(store.chain("tenant-send").await.unwrap().is_empty());
        assert!(reg
            .get(&ctx, "k1", OutboundChannel::Email)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn empty_external_recipient_is_rejected_before_claim_or_dispatch() {
        let gw = RecordingGateway::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let reg = InMemorySendRegistry::new();
        let ctx = ctx(vec![TOOL_OUTBOUND_EMAIL], vec!["mail.example.eu"]);
        let mut message = email("empty-recipient");
        message.recipient = "   ".to_string();

        let seam = AuditedSendSeam::new(&gw, &signer, &store, &reg);
        let error = seam
            .send(&ctx, message)
            .await
            .expect_err("empty recipient must fail closed");

        assert!(matches!(error, ReedeError::GatewayError { .. }));
        assert!(gw.calls().is_empty());
        assert!(store.chain("tenant-send").await.unwrap().is_empty());
        assert!(reg
            .get(&ctx, "empty-recipient", OutboundChannel::Email)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn replayed_idempotency_key_emits_no_second_receipt() {
        let gw = RecordingGateway::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let reg = InMemorySendRegistry::new();
        let ctx = ctx(vec![TOOL_OUTBOUND_EMAIL], vec!["mail.example.eu"]);
        let seam = AuditedSendSeam::new(&gw, &signer, &store, &reg);

        let first = seam.send(&ctx, email("dup")).await.unwrap();
        assert!(!first.deduplicated);
        let second = seam.send(&ctx, email("dup")).await.unwrap();
        assert!(second.deduplicated);

        // One gateway call, one receipt — the replay short-circuited.
        assert_eq!(gw.calls().len(), 1);
        assert_eq!(store.chain("tenant-send").await.unwrap().len(), 1);
        assert_eq!(second.receipt.sequence_no, first.receipt.sequence_no);
    }

    #[tokio::test]
    async fn distinct_sends_chain_into_one_verifiable_chain() {
        let gw = RecordingGateway::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let reg = InMemorySendRegistry::new();
        let ctx = ctx(
            vec![TOOL_OUTBOUND_EMAIL, TOOL_OUTBOUND_SLACK],
            vec!["mail.example.eu", "hooks.slack.example.eu"],
        );
        let seam = AuditedSendSeam::new(&gw, &signer, &store, &reg);

        seam.send(&ctx, email("a")).await.unwrap();
        let slack = OutboundMessage {
            channel: OutboundChannel::Slack,
            destination: "hooks.slack.example.eu".to_string(),
            recipient: "#alerts".to_string(),
            summary: "deploy shipped".to_string(),
            idempotency_key: "b".to_string(),
            payload: json!({ "text": "shipped" }),
        };
        seam.send(&ctx, slack).await.unwrap();

        let chain = store.chain("tenant-send").await.unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].prev_hash, Some(chain[0].content_hash.clone()));
        verify_chain(&chain, None).expect("both sends chain cleanly");
    }

    /// Internal write-back surface: egress does not apply (no external host),
    /// but the policy grant and the single receipt still do.
    #[tokio::test]
    async fn internal_channel_skips_egress_but_still_gated_and_receipted() {
        let gw = RecordingGateway::default();
        let signer = InMemoryReceiptSigner::generate_random();
        let store = InMemoryReceiptStore::new();
        let reg = InMemorySendRegistry::new();
        // Empty allowlist would fail closed for an external channel; internal
        // channel must still succeed because it contacts no external host.
        let ctx = ctx(vec![TOOL_OUTBOUND_RESPONDENT_NOTIFY], vec![]);
        let seam = AuditedSendSeam::new(&gw, &signer, &store, &reg);

        let msg = OutboundMessage {
            channel: OutboundChannel::RespondentNotify,
            destination: String::new(),
            recipient: "visitor-1".to_string(),
            summary: "your answer shipped".to_string(),
            idempotency_key: "notify-1".to_string(),
            payload: json!({ "shipped_ref": "pr-#1" }),
        };
        let out = seam.send(&ctx, msg).await.unwrap();
        assert_eq!(out.channel, OutboundChannel::RespondentNotify);
        assert_eq!(store.chain("tenant-send").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn concurrent_same_key_has_one_transport_owner() {
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let gateway = Arc::new(BlockingGateway {
            started: started.clone(),
            release: release.clone(),
            calls: StdMutex::new(0),
        });
        let signer = Arc::new(InMemoryReceiptSigner::generate_random());
        let receipts = Arc::new(InMemoryReceiptStore::new());
        let registry = Arc::new(InMemorySendRegistry::new());
        let ctx = Arc::new(ctx(vec![TOOL_OUTBOUND_EMAIL], vec!["mail.example.eu"]));
        let first_gateway = gateway.clone();
        let first_signer = signer.clone();
        let first_receipts = receipts.clone();
        let first_registry = registry.clone();
        let first_ctx = ctx.clone();
        let first_task = tokio::spawn(async move {
            send_outbound(
                first_gateway.as_ref(),
                first_ctx.as_ref(),
                first_signer.as_ref(),
                first_receipts.as_ref(),
                first_registry.as_ref(),
                email("same-key"),
            )
            .await
        });
        started.notified().await;

        let second = send_outbound(
            gateway.as_ref(),
            ctx.as_ref(),
            signer.as_ref(),
            receipts.as_ref(),
            registry.as_ref(),
            email("same-key"),
        )
        .await;
        assert!(matches!(second, Err(ReedeError::OutboundPending { .. })));
        release.notify_one();
        first_task.await.unwrap().unwrap();
        assert_eq!(*gateway.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn concurrent_distinct_sends_relinearize_receipt_head() {
        let gateway = Arc::new(RecordingGateway::default());
        let signer = Arc::new(InMemoryReceiptSigner::generate_random());
        let receipts = Arc::new(RacingReceiptStore {
            inner: Arc::new(InMemoryReceiptStore::new()),
            first_appends: Arc::new(Barrier::new(2)),
            append_attempts: AtomicUsize::new(0),
        });
        let registry = Arc::new(InMemorySendRegistry::new());
        let ctx = Arc::new(ctx(
            vec![TOOL_OUTBOUND_EMAIL, TOOL_OUTBOUND_SLACK],
            vec!["mail.example.eu", "hooks.slack.example.eu"],
        ));

        let first = {
            let gateway = gateway.clone();
            let signer = signer.clone();
            let receipts = receipts.clone();
            let registry = registry.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                send_outbound(
                    gateway.as_ref(),
                    ctx.as_ref(),
                    signer.as_ref(),
                    receipts.as_ref(),
                    registry.as_ref(),
                    email("race-a"),
                )
                .await
            })
        };
        let second = {
            let gateway = gateway.clone();
            let signer = signer.clone();
            let receipts = receipts.clone();
            let registry = registry.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                send_outbound(
                    gateway.as_ref(),
                    ctx.as_ref(),
                    signer.as_ref(),
                    receipts.as_ref(),
                    registry.as_ref(),
                    OutboundMessage {
                        channel: OutboundChannel::Slack,
                        destination: "hooks.slack.example.eu".to_string(),
                        recipient: "#alerts".to_string(),
                        summary: "deploy shipped".to_string(),
                        idempotency_key: "race-b".to_string(),
                        payload: json!({ "text": "shipped" }),
                    },
                )
                .await
            })
        };

        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
        let chain = receipts.chain("tenant-send").await.unwrap();
        assert_eq!(chain.len(), 2, "both distinct sends must finalize");
        assert_eq!(gateway.calls().len(), 2);
        verify_chain(&chain, None).expect("concurrent receipt retries preserve one chain");
    }

    #[tokio::test]
    async fn post_dispatch_receipt_failure_fences_retry() {
        let gateway = RecordingGateway::default();
        let receipts = InMemoryReceiptStore::new();
        let registry = InMemorySendRegistry::new();
        let ctx = ctx(vec![TOOL_OUTBOUND_EMAIL], vec!["mail.example.eu"]);
        let first = send_outbound(
            &gateway,
            &ctx,
            &FailingSigner,
            &receipts,
            &registry,
            email("unknown-after-dispatch"),
        )
        .await;
        assert!(matches!(
            first,
            Err(ReedeError::ReceiptSigningFailed { .. })
        ));
        let retry = send_outbound(
            &gateway,
            &ctx,
            &InMemoryReceiptSigner::generate_random(),
            &receipts,
            &registry,
            email("unknown-after-dispatch"),
        )
        .await;
        assert!(matches!(
            retry,
            Err(ReedeError::OutboundSideEffectUnknown { .. })
        ));
        assert_eq!(gateway.calls().len(), 1);
    }

    /// No-bypass guarantee: `send.rs` is the only reede module that names an
    /// `outbound/*` tool id, so nothing can reach an `outbound/*` grant without
    /// going through this seam.
    #[test]
    fn no_outbound_send_bypasses_the_seam() {
        use std::fs;
        use std::path::Path;

        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        for entry in fs::read_dir(&src_dir).expect("read reede/src") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            if name == "send.rs" {
                continue; // the seam itself defines the namespace
            }
            let body = fs::read_to_string(&path).unwrap_or_default();
            if body.contains("\"outbound/") {
                offenders.push(name);
            }
        }
        assert!(
            offenders.is_empty(),
            "these reede modules name an outbound/* tool id directly, \
             bypassing the send seam: {offenders:?}. Route the send through \
             reede::send::send_outbound instead."
        );
    }
}
