# Reede Receipt Encoding & Verification Specification (O5)

Date: 2026-08-04
Status: SPECIFIED & DECIDED

## 1. Content-Hash Derivations Across Layers

The Reede sovereign runtime ecosystem contains three distinct payload encoding pathways for content-hash derivation:

### A. Reede Open-Core Injective Field Encoding (Open-Core & Python SDK)
- **Format**: For each field string, emit hex UTF-8 byte length, a colon separator `:`, and the field UTF-8 bytes (`<len_hex>:<field_bytes>`).
- **Signature Target**: `SHA-256(injective_bytes)` hex string (`content_hash.as_bytes()`).
- **Scope**: Used by `reede::receipt::encode_fields_injective` and `reede` Python SDK (`encode_fields_injective`).

### B. Host Timestamp Payload Encoding (host application runtime)
- **Format**: 8-byte big-endian u64 length header followed by field bytes (`Field::Str`, `Field::I64`, `Field::Bytes`).
- **Signature Target**: `SHA-256(payload_bytes)` hex string (`content_hash.as_bytes()`).
- **Scope**: Used by the host application's timestamp payload encoder and decision-receipt generator.

### C. Finalized Receipt Serialization Payload
- **Format**: `serde_json::to_string(&hashed_content)`.
- **Signature Target**: `SHA-256(json_string)` hex string.
- **Scope**: Used by the host application's receipt finalizer.

---

## 2. Offline Verifier Scope & Limitations (`reede-verify`)

The `reede-verify` binary performs **offline signature-over-hash verification**:

1. **Chain Linkage**: Verifies `prev_hash` pointer chaining across sequential links.
2. **Signature Verification**: Verifies Ed25519 signature over the ASCII hex string bytes of `r.content_hash.as_bytes()`.
3. **Timestamp Presence**: Reports whether an RFC 3161 TSA token string is attached (`TOKEN PRESENT (NOT VALIDATED)` vs `ABSENT`).

> [!IMPORTANT]
> **Verifier Scope Limit**: `reede-verify` confirms that an Ed25519 signature matches the `content_hash` string; it does **not** recompute the content-hash from raw application payload bytes. Payload-level field verification is performed by individual runtime producers (`reede` or the host application runtime).
