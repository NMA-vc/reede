//! Storage-agnostic sealing: one span in, one signed reede-v2 receipt out, over any
//! [`ReceiptStore`]. `reede serve` calls it with the in-memory store behind its files; a host
//! with a durable store (tectic-core's SurrealDB one) calls it with that. Same bytes either way.
//!
//! The caller passes the value that is *stored* for the span; the receipt summary is computed
//! over exactly that value, so a host that redacts before persisting seals the redacted copy.
//! The trust tier is the `reported:` subject prefix, written here and nowhere else: no request
//! field is read.

use super::otlp::Span;
use super::span_summary;
use crate::receipt::{emit_execution_receipt, ReceiptSigner, ReceiptStore};
use serde_json::Value;
use uuid::Uuid;

/// Decode an OTLP/HTTP protobuf body (lets a host skip its own prost dependency).
pub fn decode_protobuf(bytes: &[u8]) -> Result<super::otlp::ExportTraceServiceRequest, String> {
    use prost::Message;
    super::otlp::ExportTraceServiceRequest::decode(bytes)
        .map_err(|e| format!("malformed OTLP protobuf: {e}"))
}

/// The `reported:<trace>/<span>` subject (lowercase hex ids) a sealed span's receipt carries.
pub fn subject_id(trace_hex: &str, span_hex: &str) -> String {
    format!("reported:{trace_hex}/{span_hex}")
}

/// Seal one span under `tenant` (the chain key). Returns the receipt's sequence number.
/// `span` must have passed [`Span::validate`].
pub async fn seal_span(
    signer: &dyn ReceiptSigner,
    store: &dyn ReceiptStore,
    tenant: &str,
    span: &Span,
    stored: &Value,
) -> Result<u64, String> {
    let task = Uuid::from_slice(&span.trace_id).map_err(|e| e.to_string())?;
    let subject = subject_id(&hex::encode(&span.trace_id), &hex::encode(&span.span_id));
    emit_execution_receipt(
        signer,
        store,
        task,
        tenant,
        span_summary(stored),
        0,
        span.tokens(),
        0,
        Some(subject),
    )
    .await
    .map(|r| r.sequence_no)
    .map_err(|e| e.to_string())
}

/// Seal `items` in order. Returns each span's sequence number. Stops at the first failure,
/// after which the spans before it are already sealed (a chain is append-only), so a caller
/// must not resubmit the whole batch.
pub async fn seal_batch(
    signer: &dyn ReceiptSigner,
    store: &dyn ReceiptStore,
    tenant: &str,
    items: &[(&Span, &Value)],
) -> Result<Vec<u64>, String> {
    let mut seqs = Vec::with_capacity(items.len());
    for (span, stored) in items {
        seqs.push(seal_span(signer, store, tenant, span, stored).await?);
    }
    Ok(seqs)
}
