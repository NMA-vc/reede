# Reede

Reede is a runtime for AI agents. It runs each agent action under temporary, explicit,
revocable authority, and leaves a signed account of the action that anyone can verify
later, offline, under a trusted producer key. A signature protects the account's
integrity; it does not prove execution truth if the signer is compromised.

Govern any agent: bring the one you have, point its OpenTelemetry exporter at Reede, and keep a receipt for everything it reported.

The product is the *leash*, not the deploy experience:

- **Leash.** What a run may do is derived from the agent's own manifest: a budget ceiling,
  an egress allowlist of hosts it may reach, and the tools it is granted. Every check fails
  closed. An empty allowlist allows nothing, and an empty grant list grants nothing.
- **Ledger.** Credits are reserved before work starts and settled afterwards, against a
  per-tenant balance. A run that would overspend is refused up front. A per-task token
  ceiling works the same way.
- **Lease.** Credentials are handed to a run as leases that expire on their own and can be
  revoked mid-run; a revoked or expired lease is refused on its next use.
- **Receipt.** Each governed action leaves an `ExecutionReceipt` in the `reede-v2` format.
  Its content hash covers the tenant, the task, a summary, the credits and tokens, the
  previous receipt's hash, the sequence number, the time, the subject and the signing key's
  id, so the receipts form a per-tenant hash chain whose order and dates cannot be edited.
  The hash is signed with Ed25519.
- **Verify.** An offline verifier, Apache-2.0 like the rest of the crate, recomputes every
  hash, checks the chain linkage and the signatures, and reports a two-tier verdict:
  authentic (fail-closed), then timestamped or not (fail-open, and visibly different).

Reede is open-core and Apache-2.0. It depends on no host-application crate, and CI enforces
that on the resolved dependency graph (`scripts/check-one-way-dependency.py`).

Reede is early (`0.8.0`, pre-1.0) and the API can still change between minor versions.

## Verified receipt in 5 minutes

Bring an agent you already have, with any framework that exports OpenTelemetry traces. Reede
seals every span into a signed, hash-chained receipt on your own machine, and a verifier checks
the result offline. You need Rust 1.89 or newer.

```sh
cargo install --path . --features ingest      # from a checkout of this repository
# once published: cargo install reede --features ingest

reede serve                                   # local OTLP/HTTP ingest on http://127.0.0.1:4318
```

Point your OpenTelemetry exporter at `http://127.0.0.1:4318` (a base URL; `/v1/traces` is
appended) and run your agent. Complete LangGraph and Mastra examples, each with a `run.sh`
that uses fake models and needs no API key, are in [examples/otel](examples/otel). Then:

```sh
reede ingest check --out reede-ingest --pubkey "$(cat reede-ingest/pubkey.hex)"
reede receipt verify --chain reede-ingest/chain.json --pubkey "$(cat reede-ingest/pubkey.hex)"
```

`ingest check` recomputes every span file's hash against its receipt and fails if a span file
was edited, a receipt was changed or removed, or the chain is cut short. `receipt verify` checks
the chain and signatures and prints a verdict such as `SIGNED, NOT TIMESTAMPED`. Details,
limits and the file layout are in [docs/ingest.md](docs/ingest.md).

**What this proves, and what it does not.** This is the *reported* tier. A reported receipt
proves what the agent reported and when this machine sealed it. It does not prove the report is
true, and whoever runs `reede serve` holds the signing key. Receipts are signed, not
timestamped: no trusted timestamp authority is involved, so the dates are the sealing machine's
claim. Pass `--pubkey` with a key you obtained out of band; without it the check only shows the
directory is self-consistent.

**Privacy.** Spans are stored in clear in `reede-ingest/spans/`. Some frameworks put full
prompts and completions in span attributes, and sharing span files for verification discloses
them. Keep the output directory private (it is created mode 0700) and share only what you intend
to disclose.

## Examples

Run these from the repository root. They use no network once the crates are downloaded, and
need no database, Docker or key you have to provide.

```sh
cargo test --locked                      # the crate's own tests
cargo run --locked --example manifest    # parse a manifest, derive its policy, see bad ones refused
cargo run --locked --example leash       # egress, grants, budget, tokens, leases: allowed and refused
cargo run --locked --example receipt     # emit a signed, chained receipt chain and export it
cargo run --locked --example verify      # verify that chain, then watch five tampered copies fail
```

Each example exits non-zero if any of its checks has an unexpected outcome, so they double
as smoke tests. Signing keys in the examples are generated in-process and never written.

| Example | Shows |
|---|---|
| `manifest` | `parse_manifest_v1` accepting a manifest and refusing a non-EU model provider, a zero budget and an unknown key; `derive_policy` producing the budget, approval threshold, egress allowlist and grants |
| `leash` | `AllowlistEgress`, `grant_permits`, `InMemoryLedger`, `TokenBudget` and `InMemoryLeaseManager`, each in both directions |
| `receipt` | three runs that reserve and settle credits and emit one receipt each; writes `chain.json` and `pubkey.hex` |
| `verify` | `verify_chain` and `verify_receipt_two_tier` on the genuine chain, then on copies with an edited field, an edited summary, a recomputed hash, the wrong key and a dropped receipt |

## Verify a receipt

Use the `verify` binary's strict JSON mode for automated acceptance. It requires a
trusted Ed25519 public key, rejects empty exports, unsupported formats, invalid
signatures and broken or missing predecessor links, and exits nonzero on failure:

```sh
cargo run --locked --example receipt -- /tmp/reede-example
cargo run --locked --bin verify -- \
  --chain /tmp/reede-example/chain.json \
  --pubkey "$(cat /tmp/reede-example/pubkey.hex)" --json
```

The example generates its own key for demonstration. In production, obtain the
producer's public key through a trusted channel; a key supplied alongside an
untrusted export does not establish who signed it.

A successful `reede-verification-v1` report sets `authentic` and `chain_verified`
to `true`. Without additional trusted boundaries, `completeness` is
`supplied_segment_only`: a correctly signed suffix can still omit earlier
receipts, and an otherwise valid export can omit later receipts. For complete
export acceptance, also pass `--require-genesis`, `--expected-head <hash>` and
`--expected-count <count>`, obtaining the expected head and count independently
from a trusted source. Pass `--expected-tenant <tenant>` when the caller expects
a particular tenant. Sequence numbers and outer timestamp metadata are not
signed `reede-v1` content; they are signed in `reede-v2`, the format the writer now emits.

The shared test vector verifies through the same strict path:

```sh
jq '[.receipt]' tests/fixtures/reede-v1-vector.json > /tmp/vector-chain.json
cargo run --locked --bin verify -- --chain /tmp/vector-chain.json \
  --pubkey "$(jq -r .pubkey_hex tests/fixtures/reede-v1-vector.json)" --json
```

Strict mode reports timestamp tokens as `present_not_validated` or `absent`; it
does not validate RFC 3161 tokens and rejects `--cafile`. Its `legally_qualified`
field is `null`: neither a valid receipt signature nor RFC 3161 conformance
establishes legal qualification.

The human-readable mode also checks that the chain is one tenant's, numbered contiguously
from `sequence_no` 1, with no repeated link. A file whose first receipt is not seq 1 fails
(`chain starts at seq 3, not 1`), so receipts deleted from the start of an export are caught.
To check a deliberate excerpt, pass `--segment`: the CHAIN line then reads `VERIFIED SEGMENT`
with the head's `sequence_no` and `prev_hash`, and the verdict says which receipt it continues
from. Receipts are written as `reede-v2`, which adds `sequence_no`, `timestamp` (RFC 3339,
UTC, 6 fractional digits), `subject_id` and `signer_key_id` to the signed content, so
re-dating or renumbering a receipt fails like any other edit. Chains written earlier as
`reede-v1` still verify by their own rule, and the verdict says those fields are not covered.

For separate timestamp inspection, the legacy human-readable mode accepts
`--cafile <ca.pem>` and invokes `openssl ts -verify`. Its historical
`FULLY QUALIFIED` label means that its signature/hash/timestamp checks passed;
it is **not** a determination of qualified trust-service status or legal effect.
Legacy mode can exit zero without signature verification when `--pubkey` is
omitted, and reports unsupported formats without recomputing their hashes. Use
strict `--json` or `--strict` mode for security decisions.

From Rust, the strict API is `reede::verification::verify_export` with a
`VerificationPolicy`. The SDKs' offline helpers invoke this same Rust core.

## The `reede` binary

`src/bin/reede.rs` is an early command-line front end. What it does today:
- `reede serve` and `reede ingest check` (built with `--features ingest`): see above and
  [docs/ingest.md](docs/ingest.md).

- `reede deploy --manifest <agent.toml>` validates a manifest with `parse_manifest_v1` and
  reports `VALIDATED`. It does not deploy or start an agent.
- `reede receipt verify --chain <receipts.json> --pubkey <hex>` runs the same offline
  verifier as `verify`. Pass `--json` for strict acceptance and a structured report.
  Without `--json`/`--strict`, it retains the legacy inspection behavior described above.
- `reede status` reports whether `runsc`, an egress proxy, `SURREAL_URL`,
  `AGENT_SIGNING_KEY` and `TSA_URL` are present on this host.
- `reede tasks [--limit N]`, `reede tasks <id>`, `reede kill <id> [--wait]` and
  `reede lease <id>` call the tenant-scoped lifecycle API when Reede is built with
  `--features cli`. Without that feature they report that the HTTP client is unavailable.
- `reede policy` and `reede logs` are not implemented. There is no `reede run` command.

## Status

Pre-1.0 (`0.8.0`). The API can still change between minor versions. Standalone CI,
dependency-boundary checks, MSRV, examples and verifier smoke tests run on every push.

Built and tested in this crate:

- manifest parsing and validation, and policy derivation;
- the egress allowlist decision, resource grants, the in-memory budget ledger, the token
  ceiling and credential leases;
- `reede-v2` receipt emission (hash, sign, chain), with a bounded retry on a chain-head
  conflict, and the offline verifier;
- an allowlist-gated egress proxy (HTTP `CONNECT` and DNS) with a hook for every denial;
- `reede serve` (feature `ingest`): a local OTLP/HTTP ingest that seals reported spans into
  `reede-v2` receipts, and `reede ingest check`;
- the feedback subsystem (signals, producers, reducers, promotion, memory hygiene, the
  golden set), which a host application consumes.

The production receipt writer belongs to the host application, not this crate: a host emits its
run receipts through `emit_execution_receipt_timestamped`, and its durable stores implement this
crate's store traits. `tests/fixtures/reede-v1-writer-receipt.json` is a synthetic receipt shaped
like that writer's output, signed with a public test key, and the verifier's own tests verify it.

Not wired yet. Do not rely on these:

- **Sandbox isolation.** `GvisorBackend` (Docker with `--runtime=runsc`) exists as code,
  but a host must still be provisioned with `runsc` and explicitly select
  `REEDE_ISOLATION_BACKEND=gvisor`. The factory defaults to the production profile
  and refuses missing or invalid backend configuration. Local passthrough requires
  both `REEDE_EXECUTION_PROFILE=development` and `REEDE_ISOLATION_BACKEND=passthrough`.
  Direct construction of `PassthroughBackend` remains an explicit library choice. Network-level
  egress enforcement depends on that sandbox, so without it the egress allowlist is a
  decision your code must honour, not a wall.
- **Trusted timestamps.** The `ReceiptTimestamper` hook exists, but no RFC 3161 timestamp
  authority is configured, so every receipt is signed but not timestamped. The authority
  must be an EU qualified trust service provider; which one is an open decision.
- **Human approval.** `derive_policy` computes an approval threshold
  (`hitl_above_credits`), but nothing in this crate enforces it.
- **SDK release candidates.** Python and JavaScript/TypeScript clients are in
  [sdk/](sdk/README.md). They implement the existing lifecycle and agent-host
  protocols and use the common Rust verifier for offline proof checks. Package
  publication, full release validation and runtime recovery work are separate.

## Layout

| Path | What |
|---|---|
| `src/` | the library; `src/bin/verify.rs` is the offline verifier, `src/bin/reede.rs` the CLI |
| `examples/` | the four runnable examples above, and `examples/otel` (LangGraph, Mastra) |
| `tests/` | integration tests and the `reede-v1` fixtures |
| `docs/` | [public specifications](docs/README.md) and the [ingest guide](docs/ingest.md) |
| `scripts/` | dependency-boundary checker, release-candidate builder and Python tests |
| `sdk/` | Python and JavaScript/TypeScript service clients and conformance tests |
| `.github/workflows/` | CI, and the tag-driven release workflow |
| `skills/claude-code/` | a Claude Code skill that derives a leash from an agent manifest |
| `CHANGELOG.md` | what has landed |

## Standalone checks

From the repository root, with the reviewed `Cargo.lock` tracked in Git:

```sh
python3 -m unittest discover -s scripts/tests -v
python3 scripts/check-one-way-dependency.py
cargo fmt -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo test --locked --all-features
```

The Python tests use synthetic metadata and never invoke Cargo. The checker
itself reads actual `cargo metadata --locked` graphs for default and all
features. It rejects missing graph data and any reached local package outside
this directory, including symlink escapes. A missing standalone lockfile is a
release blocker; do not copy the monorepo lock and call it validated.

The workflow in `.github/workflows/ci.yml` also runs all four examples and checks
that the shipping verifier accepts a signed chain and rejects a tampered one.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
