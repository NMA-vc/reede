// The crate docs are the README, so docs and README cannot drift apart.
// Engineering contract for work on this crate: CLAUDE.md.
#![doc = include_str!("../README.md")]

pub mod anchor;
pub mod attention_budget;
pub mod attribution;
pub mod bands;
pub mod capability_fingerprint;
pub mod cli;
pub mod consumer;
pub mod correction;
pub mod egress;
pub mod egress_proxy;
pub mod error;
pub mod fork;
pub mod inquiry;
#[deprecated(note = "renamed to `inquiry`")]
pub use crate::inquiry as frogen;
pub mod gateway;
pub mod golden;
pub mod govern;
pub mod honesty;
pub mod hygiene;
#[cfg(feature = "ingest")]
pub mod ingest;
pub mod isolation;
pub mod lease;
pub mod ledger;
pub mod lesson_application;
pub mod memory;
pub mod policy;
pub mod producer;
pub mod promotion;
pub mod rating;
pub mod receipt;
pub mod reducer;
pub mod replay_input;
pub mod resource_id;
pub mod role;
pub mod send;
pub mod session;
pub mod signal;
pub mod spec;
pub mod subject;
pub mod surface;
pub mod task;
pub mod telemetry_probe;
pub mod token_budget;
pub mod verification;

pub use attention_budget::{
    AskDecision, AttentionBudget, AttentionBudgetPolicy, InMemoryAttentionBudget,
};
pub use attribution::{
    apply_attribution, vet_outcome, AttributionOutcome, AttributionRequest, NeverAttributes,
    RoleAttributor, RoleOutput,
};
pub use bands::{Band, BandClassifier, BandPlan, BandRecord, EscalateEverything, MemoryRound};
pub use capability_fingerprint::{
    canonicalize_json_schema, CapabilityApproval, CapabilityApprovalRegistry,
    CapabilityApprovalState, CapabilityChange, CapabilityChangeKind, CapabilityDescriptor,
    CapabilityReconciliation,
};
pub use consumer::{
    failure_evidence, AppliedLesson, ConsumerStore, FailureEvidence, InMemoryConsumerStore,
    LessonDelta, LessonProposer, LessonStatus,
};
pub use correction::{
    correction_signals, sectioned_diff, sectionize, CorrectionSignalContext, Section,
    SectionChange, SectionChangeKind,
};
pub use egress::{
    AllowlistEgress, DeniedEgress, EgressAttemptKind, EgressPolicy, FlagToHuman, LoggingFlagToHuman,
};
pub use egress_proxy::{EgressProxy, DEFAULT_DNS_UPSTREAM, DEFAULT_PROXY_PORT};
pub use error::ReedeError;
pub use fork::{Destination, MemoryRefusal, Routing, SignalFork};
pub use gateway::{
    Gateway, ModelMessage, ModelRequest, ModelResponse, TaskContext, ToolCall, ToolResponse,
    ToolSpec,
};
pub use golden::{
    evaluate_promotion, judge_case, similarity, CandidateRunner, CaseVerdict, DeterministicJudge,
    EvalHarness, EvalJudge, EvalReport, GoldenCase, GoldenSet, GoldenStore, InMemoryGoldenStore,
    PromoteVerdict,
};
pub use govern::{
    apply_lesson_delta, notify_respondent, respondent_notify_idempotency_key, GovernedWrite,
    NotifyOutcome, RespondentNotice, LEGACY_TOOL_APPLY_LESSON_DELTA, TOOL_APPLY_LESSON_DELTA,
    TOOL_NOTIFY_RESPONDENT,
};
pub use honesty::{
    apply_verdict, assess, golden_case_from_signal, MemoryVerdict, ReplayManifest, ReplayMode,
    MIN_IMPROVEMENT,
};
pub use hygiene::{
    apply_default_ttl, assert_permanent, effective_weight, is_retrievable, reinforce,
    HygienePolicy, ProvenanceEntry, RetractionCause, RetractionRecord,
};
pub use inquiry::{
    dismissal_signal, is_inquiry_source, may_notify_respondent, record_dismissal, DismissalContext,
    DismissalReason, InMemoryWriteBackStore, UntrustedResponseText, WriteBackLink, WriteBackStore,
    INQUIRY_SOURCE, INQUIRY_SOURCE_NEUTRAL, INQUIRY_SOURCE_VERSION,
};
#[allow(deprecated)]
pub use inquiry::{FROGEN_SOURCE, FROGEN_SOURCE_VERSION};
pub use isolation::{
    create_isolation_backend, GvisorBackend, IsolationBackend, PassthroughBackend, SandboxCommand,
    SandboxId,
};
pub use lease::{CredentialLease, InMemoryLeaseManager, LeaseId, LeaseManager};
pub use ledger::{InMemoryLedger, Ledger, ReservationId};
pub use memory::{
    cosine_similarity, rank_by_similarity, InMemoryMemoryStore, Memory, MemoryBuilder, MemoryKind,
    MemoryQuery, MemoryStore,
};
pub use policy::{derive_policy, grant_permits, DerivedPolicy, ResourceGrant};
pub use producer::{InMemoryWatermarkStore, SignalProducer, WatermarkStore};
pub use promotion::{
    correction_body, corroboration_count, decide, trust_tier, PromotionDecision, PromotionPolicy,
    PromotionRefusal, TrustTier,
};
pub use rating::{
    RatingProducer, RatingSubmission, RatingVote, RATING_SOURCE, RATING_SOURCE_VERSION,
};
pub use receipt::{
    emit_execution_receipt, emit_execution_receipt_timestamped, encode_fields_injective,
    recompute_content_hash, recompute_content_hash_reede_v1, recompute_content_hash_reede_v2,
    signer_key_id, verify_chain, verify_chain_from_genesis, AuthorizationReceipt, ExecutionReceipt,
    InMemoryReceiptSigner, InMemoryReceiptStore, NoTimestamper, ReceiptSigner, ReceiptStore,
    ReceiptTimestamper, REEDE_V1_FORMAT, REEDE_V2_FORMAT,
};
pub use reducer::{
    Classifier, InMemoryJudgementStore, Judgement, JudgementStore, KeywordClassifier,
    MappingReducer, MappingRule, ReductionScope,
};
pub use resource_id::derive_sandbox_id;
pub use role::{ProducerRoles, RoleKey, RoleRegistry, ROLE_KEY_SEPARATOR};
pub use send::{
    send_outbound, AuditedSendSeam, InMemorySendRegistry, OutboundChannel, OutboundMessage,
    OutboundSeam, OutboundSend, SendClaim, SendRegistry, TOOL_OUTBOUND_EMAIL,
    TOOL_OUTBOUND_MEDIA_INTAKE, TOOL_OUTBOUND_RESPONDENT_NOTIFY, TOOL_OUTBOUND_SLACK,
    TOOL_OUTBOUND_TEAMS, TOOL_OUTBOUND_THREADS, TOOL_OUTBOUND_WEBHOOK, TOOL_OUTBOUND_WHATSAPP,
};
pub use session::{Session, SessionManager, SessionState};
pub use signal::{
    InMemorySignalStore, LatencyClass, Signal, SignalKind, SignalStore, SIGNAL_ID_PREFIX,
};
pub use spec::{
    clone_spec, import_spec, parse_manifest_v1, AgentRubric, AgentSpec, GrantSection,
    InMemorySpecStore, RubricDimension, SpecStore,
};
pub use subject::{
    frontmatter_value, header_value, pr_body_marker, subject_from_header, url_param_value,
    ArtifactKind, InMemorySubjectStore, Subject, SubjectStore, SUBJECT_ID_PREFIX,
};
pub use surface::{
    CapabilityView, DimensionBaseline, DimensionScore, JudgementDrilldown, ProducerInfo,
    ReedeSurface, SubjectView, TimelineSignal,
};
pub use task::{
    execute_isolated_task, BudgetEnvelope, InMemoryTaskStore, Task, TaskState, TaskStore,
};
pub use telemetry_probe::{
    InMemoryTelemetrySource, ProbeReport, SufficiencyDecision, SufficiencyGate, SufficiencyPolicy,
    TelemetryObservation, TelemetrySource,
};
pub use token_budget::{TokenBudget, TokenBudgetSnapshot, TokenReservation};
