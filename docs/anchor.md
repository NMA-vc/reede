# Anchors: Merkle roots, timestamp digest, proof file, `reede anchor verify`

An anchor timestamps many receipts with one RFC 3161 token. Everything here is checkable
offline with this crate and `openssl`; no Tectic code is involved.

## Merkle tree over receipts

Leaves are the receipts' `content_hash` strings, in `sequence_no` order.

- leaf = SHA-256(`0x00` || UTF-8 bytes of the `content_hash` hex string)
- node = SHA-256(`0x01` || left || right)
- Level by level, left to right; an odd last node is promoted unchanged (never duplicated).
- One leaf: the root is the leaf. No leaves: no root.
- An inclusion proof is the sibling hashes leaf to root (skipping promoted levels). The
  verifier re-derives each sibling's side from `index` and `leaf_count`.

Vectors (`receipt-i` = SHA-256 of the ASCII string "receipt-i", as hex, for i = 0, 1, 2):

| item | value |
|---|---|
| leaf of receipt-0 | `5bd146667a0858414c27892ff78455d2107d1432c505d8f26311acf51c85e735` |
| root of the 3 leaves | `d377bb2325e44396318a28cc6e82831aa1654b41334dd79b4a4cd8662e2ea94c` |

## Timestamp digest (what the token covers)

The token's message imprint (SHA-256) is **not** the bare root:

```
digest = SHA-256( "reede-anchor-v1" || 0x00 || chain_key || 0x00
                  || from_seq (8 bytes big-endian) || to_seq (8 bytes big-endian)
                  || leaf_count (8 bytes big-endian) || merkle_root (32 raw bytes) )
```

`chain_key` is UTF-8 and must not contain NUL. This binds the token to one chain and range.

Vector: `chain_key = "acme#byoa"`, `from_seq = 1`, `to_seq = 3`, `leaf_count = 3`, root as above:

`a1e7f856860824a193192cbbdadaf8edff2c19d91cd9f749ea71f6c98aadb794`

The verifier recomputes the digest from the proof's fields; the file carries no digest of its own.

## Proof file (`schema: "reede-byoa-proof-v1"`)

```
{ schema, chain: "reported"|"witnessed", chain_key, pubkey_hex,
  receipts: [ExecutionReceipt...]            // a contiguous chain slice
  anchors:  [{ from_seq, to_seq, leaf_count, merkle_root (hex),
               tsa_url, tsa_qualified, tsa_token (base64, optional),
               status: "pending"|"anchored"|"failed", anchored_at?,
               inclusion: [{ sequence_no, index, siblings: [hex...] }] }] }
```

The hosted endpoint also adds a top-level `body_status` list (`{ sequence_no, status:
"present"|"expired"|"missing", note? }`); `expired` means "body expired (retention), summary still
signed": the stored text was removed under `BYOA_BODY_RETENTION_DAYS`, the receipt and anchor are
unchanged, and this is not tampering. The verifier ignores the field.

Everything in the file is untrusted input. In particular `pubkey_hex` is only a hint, and
`tsa_qualified` is the operator's claim, shown as "claimed qualified" and never checked.

## `reede anchor verify --proof <file> [--pubkey <hex>] [--expected-chain-key <key>] [--cafile <ca.pem>]`

- `--pubkey` pins the signing key. Tectic's hosted service publishes its key and TSA CA at
  `/.well-known/reede-verification.json` (fetch over TLS; never take the key from the proof). Without it the proof's key is used and the output says
  `KEY: taken from proof, NOT pinned` and `AUTHENTIC: NOT ESTABLISHED`.
- `--expected-chain-key` refuses a proof for another chain.
- `--cafile` validates each token with `openssl ts -verify -digest <digest>`: signature, chain
  to that CA, and message imprint equal to the digest above. The token's genTime is printed.
- reede-v1 receipts do not cover `sequence_no` in their hash or signature, so an inclusion
  path cannot prove their position: they are reported as NOT proof of position, count as not
  anchored, and their caveat line is kept. The same holds for receipts whose hash cannot be
  recomputed.

### Exit codes

| code | meaning |
|---|---|
| 0 | chain, signatures (pinned key), inclusion and anchoring all verified, token validated against `--cafile` |
| 1 | tampered or malformed: bad chain, signature, inclusion, digest or token; wrong chain key; crafted numbers |
| 2 | incomplete but nothing wrong: `ANCHORING:` is PENDING, FAILED, NOT ANCHORED or TOKEN NOT VALIDATED; key not pinned; reede-v1 receipts |

Timestamping is fail-open: a pending anchor is not an error, but it is never exit 0 and is
printed as PENDING, never as anchored. The final `ANCHORING:` line shows the weakest state
across the receipts and the weakest authority label (`interim, not qualified` if any anchor
in use claims no qualification).
