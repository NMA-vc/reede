# H8 -- Pending timestamps: an explicit two-tier verifier status

- **Status:** Accepted
- **Scope:** The offline receipt verifier (`src/receipt.rs`, `src/bin/verify.rs`)
  and how it presents a receipt whose trusted timestamp never landed.
- **Decision option chosen:** (b) an explicit two-tier status the verifier surfaces.
  Option (a), a backfill sweeper, is Phase 4 work and out of scope here.

## Context -- the inherited contradiction

The Reede engineering contract requires two things that pull against each other:

- Timestamping authority must be an EU QTSP with status granted (qualified evidence), AND
- Timestamping is fail-open: if the TSA is unreachable, mark the receipt pending and proceed.

Together they produce receipts with two different evidentiary strengths under one name. A
signature is fail-closed (no signature -> no proceed), so every stored receipt is authentic; but
a receipt may be authentic and *not* timestamped. Nothing in the MVP backfills a pending one
(that is Phase 4's Merkle-batch timestamping). If the verifier reports a pending receipt the same
way it reports a timestamped one, a customer is handed incomplete evidence that looks complete.

## Decision -- two explicit tiers, one combined verdict

Verification is modelled as two separable tiers, and the verifier reports both plus a combined
verdict that can never over-state the evidence:

**Tier 1 -- Authenticity (fail-closed).** Content-hash integrity (recompute the `reede-v1`
injective encoding and compare) and the Ed25519 signature over the `content_hash`. Chain linkage
(`prev_hash`) is the structural part of this tier. Any failure REJECTS the receipt: the binary
exits non-zero, the library returns `Err`. No verdict is produced for a receipt that fails here.

**Tier 2 -- Timestamp qualification (fail-open).** Whether a trusted RFC 3161 timestamp is
attached and validates:

| State         | Meaning                                                        | Fully qualified? |
|---------------|----------------------------------------------------------------|------------------|
| `Pending`     | No TSA token attached (fail-open path). Signed, not timestamped.| No               |
| `Present`     | Token attached but not validated by this checker (no CA material). | No            |
| `Timestamped` | Token attached and validated against a trusted CA.             | Yes              |

Tier 2 never rejects. A missing or unvalidated timestamp only downgrades the combined verdict.

### Surfaced states

- Library: `reede::receipt::verify_receipt_two_tier(receipt, key) -> Result<ReceiptVerdict, _>`.
  Tier 1 failure -> `Err`. On success, `ReceiptVerdict { authentic, timestamp }` with helpers
  `is_authentic()`, `is_pending_timestamp()`, `is_fully_qualified()`. The library performs no
  network I/O and does not validate an RFC 3161 token against a CA, so it emits only `Pending` or
  `Present`; only the binary (which shells `openssl ts -verify -CAfile ...`) can emit
  `Timestamped`. `is_fully_qualified()` is therefore false for anything the library alone can see
  -- exactly the H8 guarantee.
- Binary (`reede-verify`): a `VERDICT:` line. An authentic + RFC-3161-validated chain reads
  `FULLY QUALIFIED (authentic + RFC 3161 timestamped)`; an authentic but not-timestamped chain
  reads `SIGNED, NOT TIMESTAMPED (authentic; not fully qualified evidence)`; a chain whose
  authenticity could not be fully established (no `--pubkey`, or an unrecomputable format) reads
  `NOT FULLY VERIFIED (...)`.

## DONE-WHEN evidence

Both outputs verified, visibly different (real transcripts):

Pending (TSA unreachable / no token) -- `reede-verify --chain <pending> --pubkey <pk>`:

```
CHAIN:      VERIFIED (1 links)
SIGNATURES: VERIFIED (ed25519, 1 links)
HASH:       VERIFIED (1/1 links, reede-v1)
TIMESTAMP:  ABSENT (0/1 links)
VERDICT:    SIGNED, NOT TIMESTAMPED (authentic; not fully qualified evidence)
```

Timestamped (real RFC 3161 token, validated) -- `reede-verify --chain <ts> --pubkey <pk> --cafile <ca>`:

```
CHAIN:      VERIFIED (1 links)
SIGNATURES: VERIFIED (ed25519, 1 links)
HASH:       VERIFIED (1/1 links, reede-v1)
TIMESTAMP:  RFC 3161 SIGNATURE OK (1/1 links)
VERDICT:    FULLY QUALIFIED (authentic + RFC 3161 timestamped)
```

The timestamped transcript is exercised by
`reede/tests/verify_two_tier.rs::binary_timestamped_receipt_reports_fully_qualified`, which issues
a genuine local RFC 3161 token with `openssl ts` and validates it through the shipping binary
(the test skips only if the local openssl toolchain cannot issue a token; it never hangs). The
pending case is proven deterministically by the same file and by the library unit tests.

## Consequences and non-goals

- A pending receipt is now impossible to present as fully qualified through the offline verifier.
- `verify_chain`'s deliberate tolerance of a null `prev_hash` at the head, and pre-cutoff for
  legacy receipts, is unchanged (that migration accommodation is orthogonal to H8 and out of scope
  for S5). Tier-1 chain reordering/splicing of `Some(prev_hash)` links is still rejected.
- The real answer to H8 -- Merkle-batch timestamping against the selected EU QTSP so no receipt
  stays pending -- remains Phase 4. This decision is the MVP-scoped stopgap the spec calls for.
