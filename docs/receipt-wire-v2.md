# reede-v2 Receipt Wire Format

Status: SPECIFIED (new file; the reede-v1 documents are unchanged)
Supersedes for emission: `receipt-encoding-spec-addendum-reede-v1-wire.md`, which stays
normative for legacy `format = "reede-v1"` receipts.

The code in `src/receipt.rs` is the source of truth. If this document and the code disagree,
the shared vector `tests/fixtures/reede-v2-vector.json` decides.

## 1. Where it applies

`reede-v2` is what `emit_execution_receipt_timestamped` writes (it sets
`format = REEDE_V2_FORMAT`). The verifier selects the hash rule from the receipt's own
`format` field (`recompute_content_hash`): `reede-v1` and `reede-v2` are recomputed, any
other value (or none) is reported as unverifiable, never as passing (`verify_receipt`).

## 2. Encoding

`encode_fields_injective(fields)`: for each field, emit the byte length of its UTF-8 form in
lowercase hex, a colon, then the bytes. Fields are concatenated with no other separator. The
length prefix, not the colon, makes it injective: field bytes may contain colons.

## 3. Fields, in order

`recompute_content_hash_reede_v2` hashes exactly these 11 strings:

| # | Field | Rendering |
|---|-------|-----------|
| 1 | `tenant_id` | as is |
| 2 | `task_id` | hyphenated lowercase UUID |
| 3 | `payload_summary` | as is |
| 4 | `credits_spent` | decimal |
| 5 | `tokens_used` | decimal |
| 6 | `reservation_credits` | decimal |
| 7 | `prev_hash` | hex of the previous receipt's `content_hash`; empty string if null |
| 8 | `sequence_no` | decimal |
| 9 | `timestamp` | RFC 3339, UTC, exactly 6 fractional digits, `Z` (`2023-11-14T22:13:20.123456Z`) |
| 10 | `subject_id` | as is; empty string if absent |
| 11 | `signer_key_id` | as is; empty string if absent |

Fields 1-7 are the reede-v1 fields in the same order (`recompute_content_hash_reede_v1`).
Fields 8-11 are new: under reede-v1 `sequence_no`, `timestamp` and `subject_id` were not covered
by hash or signature; under reede-v2 an edit to any of them changes the hash. The writer
truncates the timestamp to microseconds before storing so the stored value is what is hashed.

## 4. Hash and signature

- `content_hash` = lowercase hex SHA-256 of the encoded bytes.
- `signature` = Ed25519 (RFC 8032) over the 64 ASCII bytes of the hex `content_hash`, not the raw
  digest; 64 bytes, lowercase hex (`verify_receipt`).
- `signer_key_id` = first 16 hex characters of SHA-256 over the 32-byte public key
  (`signer_key_id()`). It names the key; the verifier still needs the trusted public key.

## 5. Chain rules

`verify_chain` (oldest first): one `tenant_id` throughout; `sequence_no` contiguous (+1 per
link); no repeated `content_hash`; every link's `prev_hash` equals the preceding link's
`content_hash`. The head's own `prev_hash` is not checked: a head that links to an earlier
receipt is a valid segment, reported as `SEGMENT` / `supplied_segment_only`.

`verify_chain_from_genesis` additionally requires the head at `sequence_no` 1. Because
`sequence_no` is signed in reede-v2, a truncated chain cannot be renumbered to start at 1.

The `verify` binary applies these rules in two modes:

- Plain mode (`verify_chain_report`): `verify_chain_from_genesis`, or `verify_chain` with
  `--segment`. A non-genesis head fails unless `--segment` is given.
- Strict mode (`--strict`, `--json`, or any `--expected-*` / `--require-genesis`, which imply
  it): `verify_export` in `src/verification.rs`. It checks each receipt with `verify_receipt`,
  tenant and predecessor links, and, when every receipt is reede-v2, also calls `verify_chain`
  (contiguous `sequence_no`, no repeated `content_hash`). A non-genesis head is accepted and
  reported `completeness: supplied_segment_only`. `--require-genesis` rejects a head with a
  `prev_hash`, and, for reede-v2, a head whose `sequence_no` is not 1. For reede-v1 receipts
  `sequence_no` is unsigned, so only the `prev_hash` rule applies and the report carries
  `sequence_authenticated: false`.

Completeness (nothing missing at the end, or the right history) needs a trusted
`--expected-head` and `--expected-count` from outside the file.

## 6. Shared vector

`tests/fixtures/reede-v2-vector.json`, generated independently of the Rust writer (Python
hashlib + cryptography). Seq 2 of a chain, so a segment.

```
pubkey_hex            = ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
expected_content_hash = e02622f7aaf8c45ee0225b6b8e32d6d8eca90f63a8841ba716e8e73c6e2e04d6
signer_key_id         = fe812c12f3ab4ce6
```

A reimplementation is correct iff it reproduces `expected_content_hash` from the 11 fields and
verifies `signature` against `pubkey_hex`.

## 7. Timestamps and verdicts

Unchanged from the reede-v1 addendum: authenticity is fail-closed, RFC 3161 qualification is
fail-open (`verify_receipt_two_tier`), and a signed receipt without a validated token is never
"fully qualified". A reede-v1 link additionally carries the caveat that its `sequence_no`,
`timestamp` and `subject_id` are not signed; the verifier still accepts it.
