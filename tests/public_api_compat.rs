use chrono::Utc;
use reede::correction::{correction_signals, SectionChange, SectionChangeKind};
use reede::frogen::{dismissal_signal, DismissalReason};
use reede::gateway::ToolResponse;
use reede::govern::{GovernedWrite, NotifyOutcome};
use reede::receipt::ExecutionReceipt;
use reede::send::{OutboundChannel, OutboundSend, SendClaim};
use reede::signal::AttributionSource;
use uuid::Uuid;

struct CustomText(&'static str);

impl From<CustomText> for String {
    fn from(value: CustomText) -> Self {
        value.0.to_owned()
    }
}

fn receipt() -> ExecutionReceipt {
    ExecutionReceipt {
        task_id: Uuid::nil(),
        tenant_id: "tenant-compat".into(),
        sequence_no: 1,
        credits_spent: 0,
        tokens_used: 0,
        reservation_credits: 0,
        content_hash: "content-hash".into(),
        prev_hash: None,
        signature: "signature".into(),
        tsa_token: None,
        timestamp: Utc::now(),
        payload_summary: "compatibility fixture".into(),
        format: Some("reede-v1".into()),
        subject_id: None,
        signer_key_id: None,
    }
}

fn consume_governed_write(write: GovernedWrite) -> &'static str {
    write.tool
}

fn consume_outbound_send(send: OutboundSend) -> String {
    send.idempotency_key
}

#[test]
fn legacy_dismissal_signature_accepts_literals_owned_strings_and_custom_into() {
    let observed_at = Utc::now();
    let signal = dismissal_signal(
        "subject-literal",
        String::from("tenant-owned"),
        CustomText("agent-custom-into"),
        String::from("capability-owned"),
        "inquiry-compat",
        DismissalReason::Dismissed,
        observed_at,
        "run-literal",
    );

    assert_eq!(signal.subject_id, "subject-literal");
    assert_eq!(signal.tenant_id, "tenant-owned");
    assert_eq!(signal.agent_id, "agent-custom-into");
    assert_eq!(signal.capability, "capability-owned");
    assert_eq!(signal.run_id, "run-literal");
    assert_eq!(signal.observed_at, observed_at);
    assert_eq!(signal.raw["frogen_outcome"], "dismissed");
    assert_eq!(signal.raw["inquiry_id"], "inquiry-compat");
    assert_eq!(
        signal.idempotency_key,
        "frogen-dismissal:inquiry-compat:dismissed"
    );
}

#[test]
fn legacy_correction_signature_preserves_mapping_and_idempotency() {
    let changes = [SectionChange {
        key: "summary".into(),
        kind: SectionChangeKind::Modified,
        before: Some("before text".into()),
        after: Some("after text".into()),
        order_before: Some(0),
        order_after: Some(0),
    }];
    let signals = correction_signals(
        "tenant-literal",
        "subject-literal",
        "agent-literal",
        "copy",
        "1.2",
        "run-literal",
        "copy/summarize",
        &changes,
    );

    assert_eq!(signals.len(), 1);
    let signal = &signals[0];
    assert_eq!(signal.tenant_id, "tenant-literal");
    assert_eq!(signal.subject_id, "subject-literal");
    assert_eq!(signal.agent_id, "agent-literal");
    assert_eq!(signal.capability, "copy");
    assert_eq!(signal.source_version, "1.2");
    assert_eq!(signal.run_id, "run-literal");
    assert_eq!(signal.role.as_deref(), Some("copy/summarize"));
    assert_eq!(signal.attribution_source, AttributionSource::Explicit);
    assert_eq!(signal.raw["before"], "before text");
    assert_eq!(signal.raw["after"], "after text");
    assert_eq!(
        signal.idempotency_key,
        "subject-literal:copy:section:0:summary"
    );
}

#[test]
fn public_completed_variants_keep_their_original_owned_payload_types() {
    let response = ToolResponse {
        output: serde_json::Value::Null,
        duration_ms: 3,
        hosts_contacted: Vec::new(),
    };
    let notified = NotifyOutcome::Notified(GovernedWrite {
        tool: "outbound/respondent_notify",
        tool_response: response.clone(),
        receipt: receipt(),
    });
    match notified {
        NotifyOutcome::Notified(write) => {
            assert_eq!(consume_governed_write(write), "outbound/respondent_notify");
        }
        NotifyOutcome::BudgetRefused { .. } => panic!("expected a completed notify"),
    }

    let claim = SendClaim::Completed(OutboundSend {
        channel: OutboundChannel::RespondentNotify,
        idempotency_key: "send-compat-idempotency".into(),
        deduplicated: true,
        tool_response: response,
        receipt: receipt(),
    });
    match claim {
        SendClaim::Completed(send) => {
            assert!(send.deduplicated);
            assert_eq!(consume_outbound_send(send), "send-compat-idempotency");
        }
        _ => panic!("expected a completed send"),
    }
}

#[test]
#[allow(deprecated)]
fn neutral_names_exist_and_old_names_still_resolve() {
    assert_eq!(reede::inquiry::INQUIRY_SOURCE, reede::frogen::FROGEN_SOURCE);
    assert_eq!(reede::INQUIRY_SOURCE_VERSION, reede::FROGEN_SOURCE_VERSION);
    assert!(reede::is_inquiry_source("frogen") && reede::is_inquiry_source("inquiry"));
    assert!(!reede::is_inquiry_source("rating"));
    assert_eq!(
        reede::govern::TOOL_APPLY_LESSON_DELTA,
        "feedback/apply_lesson_delta"
    );
    assert_eq!(
        reede::govern::LEGACY_TOOL_APPLY_LESSON_DELTA,
        "weeger/apply_lesson_delta"
    );
    assert_eq!(
        reede::subject::header_value("sub_1"),
        "X-Reede-Subject: sub_1"
    );
    assert_eq!(
        reede::subject_from_header("X-Tectic-Subject: sub_1"),
        Some("sub_1")
    );
}
