use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ReedeError {
    #[error("Budget exhausted: spent {spent_eur} EUR exceeds ceiling {ceiling_eur} EUR")]
    BudgetExhausted {
        spent_eur: String,
        ceiling_eur: String,
    },

    #[error(
        "Token budget exhausted: consumed/reserved {consumed_tokens} tokens exceeds ceiling {limit_tokens} (requested {requested_tokens})"
    )]
    TokenBudgetExhausted {
        consumed_tokens: u64,
        limit_tokens: u64,
        requested_tokens: u64,
    },

    #[error("Egress denied: destination '{destination}' is not on the allowlist")]
    EgressDenied { destination: String },

    #[error("Lease revoked for secret '{secret_ref}' on task {task_id}")]
    LeaseRevoked { task_id: String, secret_ref: String },

    #[error("Lease expired for secret '{secret_ref}' on task {task_id}")]
    LeaseExpired { task_id: String, secret_ref: String },

    #[error("Receipt signing failed: {reason}")]
    ReceiptSigningFailed { reason: String },

    #[error("Receipt chain head conflict: {reason}")]
    ReceiptHeadConflict { reason: String },

    #[error("Receipt verification failed: {reason}")]
    ReceiptVerificationFailed { reason: String },

    #[error("Task state violation: illegal transition from {from} to {to}")]
    TaskStateViolation { from: String, to: String },

    #[error("Spec validation failed: {reason}")]
    SpecValidationFailed { reason: String },

    #[error("Gateway unavailable: {reason}")]
    GatewayUnavailable { reason: String },

    #[error("Ledger operation failed: {reason}")]
    LedgerFailed { reason: String },

    #[error("Termination failed: {reason}")]
    TerminationFailed { reason: String },

    #[error("Isolation sandbox failed: {reason}")]
    IsolationFailed { reason: String },

    #[error("Task not found: {id}")]
    TaskNotFound { id: String },

    #[error("Gateway error: {reason}")]
    GatewayError { reason: String },

    #[error("Grant denied: resource '{resource}' action '{action}' is not in this run's resource grant set")]
    GrantDenied { resource: String, action: String },

    #[error("Capability '{capability}' requires explicit re-approval before it can be called")]
    CapabilityApprovalRequired { capability: String },

    #[error("Capability '{capability}' fingerprint does not match the approved surface")]
    CapabilityFingerprintMismatch { capability: String },

    #[error("Outbound send '{key}' is already pending")]
    OutboundPending { key: String },

    #[error("Outbound send '{key}' has an unknown side effect; refusing to redispatch")]
    OutboundSideEffectUnknown { key: String },
}
