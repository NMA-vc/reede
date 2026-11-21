# reede-v1 Receipt Wire Format -- Reimplementation Spec (O5 addendum)

Date: 2026-08-21
Status: SPECIFIED
Addendum to: `receipt-encoding-spec.md` (O5, 2026-08-04). That document stays as
shipped; this addendum adds the byte-level detail a third party needs to reimplement the offline
verifier without reading the Rust, and pins a shared test vector.

This document is normative for `format = "reede-v1"` receipts. If it and the Rust ever disagree,
the shared test vector (Section 5) decides.

## 1. What a verifier checks

A `reede-v1` receipt carries two independent evidentiary tiers (see
`decisions/H8-pending-timestamp-two-tier.md`):

1. **Authenticity (fail-closed).** Recompute `content_hash` from the receipt fields and compare;
   verify the Ed25519 signature over `content_hash`. Chain linkage via `prev_hash`.
2. **Timestamp qualification (fail-open).** Whether an RFC 3161 token is attached and validates.
   Absence never fails verification; it only means "signed, not timestamped".

A reimplementation that agrees with ours must reproduce Section 3's `content_hash` and accept the
same signatures; the two-tier verdict rules are Section 6.

## 2. Receipt fields (JSON)

Receipts are exchanged as JSON. Fields relevant to hashing and verification:

| Field                 | JSON type        | In content_hash? | Notes |
|-----------------------|------------------|:----------------:|-------|
| `tenant_id`           | string           | yes (1)          | |
| `task_id`             | string (UUID)    | yes (2)          | lowercase hyphenated UUID |
| `payload_summary`     | string           | yes (3)          | |
| `credits_spent`       | integer (i64)    | yes (4)          | base-10 text of the integer |
| `tokens_used`         | integer (u32)    | yes (5)          | base-10 text |
| `reservation_credits` | integer (i64)    | yes (6)          | base-10 text |
| `prev_hash`           | string or null   | yes (7)          | null encodes as the empty string |
| `content_hash`        | string (hex)     | no (it *is* the output) | 64 lowercase hex chars |
| `signature`           | string (hex)     | no               | 128 hex chars = 64-byte Ed25519 sig |
| `sequence_no`         | integer          | no               | chain position, not hashed |
| `timestamp`           | string (RFC 3339)| no               | wall-clock, not hashed |
| `tsa_token`           | string or null   | no               | base64 RFC 3161 token, or absent |
| `format`              | string           | no               | must equal `"reede-v1"` to be verifiable |
| `subject_id`          | string or null   | no               | optional metadata |

## 3. content_hash derivation (the injective encoding)

`content_hash = lowercase_hex( SHA-256( injective_encode(FIELDS) ) )`

`FIELDS` is exactly these seven byte strings, in this order:

```
1. tenant_id
2. task_id                 (UUID as lowercase hyphenated text)
3. payload_summary
4. credits_spent           (decimal text, e.g. "250"; negatives as "-5")
5. tokens_used             (decimal text)
6. reservation_credits     (decimal text)
7. prev_hash               (the string; if null, the empty string "")
```

`injective_encode(fields)` concatenates, for each field in order:

```
<len_hex> ":" <field_utf8_bytes>
```

<!-- guardrail-allow:UNPADDED_HEX len is a scalar byte length; the signed wire format requires unpadded lowercase hex, not digest byte encoding. -->
where `<len_hex>` is the byte length of the field's UTF-8 encoding written in **lowercase
hexadecimal with no leading zeros** (Rust `format!("{:x}", len)`), followed by a literal ASCII
colon `:`, followed by the raw field bytes. Length prefixing makes the concatenation injective, so
no two distinct field tuples collide.

Worked example (the golden fields):

```
fields = ["tenant-golden", "00000000-0000-0000-0000-000000000001",
          "battlecard:acme", "250", "1234", "500", ""]

encoded = "d:tenant-golden24:00000000-0000-0000-0000-000000000001f:battlecard:acme3:2504:12343:5000:"
          |  |               |  |                                  | |               | |    | |    | |
          |  tenant-golden   |  task_id (0x24 = 36 bytes)          | payload (0xf=15)| 250 | 1234| 500| "" (len 0)
          0xd = 13 bytes                                           colon separators throughout

SHA-256(encoded) = c61c46e4831cc1bef79ed703c3b88aa03d2ecbd244a7b544db92d492ebed5245
```

Note the colon is only a separator between the length header and the bytes; field bytes may
themselves contain colons (`battlecard:acme`, `1:2:3`), which is why the length prefix -- not the
colon -- is what makes the encoding unambiguous.

## 4. Signature

- Algorithm: Ed25519 (RFC 8032), deterministic signatures.
- Signed message: the ASCII bytes of the hex `content_hash` string (`content_hash.as_bytes()`),
  i.e. the 64 hex characters, NOT the 32 raw digest bytes.
- `signature` is the 64-byte Ed25519 signature, lowercase hex (128 chars).
- Public key: 32-byte Ed25519 verifying key, lowercase hex.

## 5. Shared test vector

Committed at `reede/tests/fixtures/reede-v1-vector.json`. A reimplementation is correct iff it
reproduces `expected_content_hash` from the receipt fields (Section 3) and verifies `signature`
against `pubkey_hex` (Section 4).

```
pubkey_hex            = ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
expected_content_hash = b718a347ef7b58725942a2b10c3363767112dac42d93fbef655c66a85efadc83

receipt fields used in the hash:
  tenant_id           = "tenant-shared-vector"
  task_id             = "11111111-2222-3333-4444-555555555555"
  payload_summary     = "battlecard:acme"
  credits_spent       = 250
  tokens_used         = 1234
  reservation_credits = 500
  prev_hash           = null  (encodes as "")

signature (over the ASCII bytes of expected_content_hash):
  f5976478c6ecd23a52adf62ab4e9dc15df69b49a7a1a8eb92caa236445afd397a388d4d25a6cb92f20587bed9ce155a49a7565abcc59e96617e17139b7e3d80d
```

`reede/tests/verify_two_tier.rs::shared_vector_third_party_recompute_and_binary_verify`
demonstrates the O5 gate: it recomputes the hash with an inline reimplementation (no call into
`reede`) and confirms the shipping binary verifies the signature -- the "someone who has not read
the Rust agrees on a shared vector" check.

## 6. Chain and two-tier verdict rules

- **Chain linkage.** For each receipt after the first, `prev_hash` MUST equal the preceding
  receipt's `content_hash`. The head receipt has `prev_hash = null`. (A null `prev_hash` after the
  head is tolerated only for pre-cutoff legacy receipts; post-cutoff it is a break.)
- **Verdict.**
  - Reject (exit non-zero) if any `reede-v1` `content_hash` recompute mismatches, any signature
    fails, or chain linkage breaks. This is Tier 1, fail-closed.
  - Otherwise report Tier 2: `FULLY QUALIFIED` iff every link carries an RFC 3161 token that
    validates against the trusted CA; else `SIGNED, NOT TIMESTAMPED`. A verifier given no public
    key, or an unrecomputable `format`, reports `NOT FULLY VERIFIED` (authenticity not established)
    rather than either qualified state.
- **RFC 3161 validation** (to reach `FULLY QUALIFIED`): the token is verified over the digest
  whose hex is `content_hash`, e.g. `openssl ts -verify -digest <content_hash> -in <token>
  -token_in -CAfile <ca.pem>` expecting `Verification: OK`.

## 7. Scope limits (unchanged from the base O5 doc)

The offline verifier is Apache-2.0 and free of host-application dependencies: only the `reede-v1` injective encoding,
SHA-256, Ed25519, and (for Tier 2) RFC 3161 via the system `openssl`. It does not recompute
content hashes for other `format` values (`encode_payload`-based host-application receipts); those are
reported as unverifiable, never silently passed.
