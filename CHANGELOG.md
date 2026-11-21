# Changelog

All notable changes to the `reede` crate.

## 0.8.0 - 2026-11-21

First public release candidate. The API changes without notice before 1.0.

### Added

- **Manifests and policy.** `parse_manifest_v1` (unknown keys refused, an EU model provider
  required, a positive budget ceiling) and `derive_policy`, which derives the budget ceiling, an
  approval threshold, the egress allowlist (MCP server hosts plus the manifest's own `egress`
  list) and resource grants. Per-capability rubrics.
- **The leash.** Every check fails closed.
  - `AllowlistEgress` (an empty list allows nothing; direct IPs and metadata endpoints are
    refused) and an allowlist-gated egress proxy for HTTP `CONNECT` and DNS, with connection and
    header bounds, deadlines, and a hook that fires on every denial.
  - Resource grants with fail-closed matching, checked by `Gateway::authorize_tool`.
  - The budget ledger: reserve, settle, release, and recovery of stranded reservations.
  - Per-task hard token ceilings (`TokenBudget`).
  - Credential leases that expire and can be revoked mid-run.
  - Capability fingerprints: a changed tool surface needs re-approval.
  - A model and tool `Gateway` trait for a host to route calls through, with structured-output
    requests.
  - A task state machine and `execute_isolated_task` over an `IsolationBackend`. Production
    refuses an absent or unknown backend; a gVisor (`runsc`) backend exists as opt-in code and is
    not provisioned. Local passthrough needs explicit development settings.
  - An audited outbound-send seam with idempotent claims.
- **Receipts.** `reede-v2` is the emission format: an injective encoding of 11 signed fields
  (including sequence number, timestamp, subject and signer key id), SHA-256, Ed25519 and a
  per-tenant hash chain. `reede-v1` receipts still verify by their own rule.
  `emit_execution_receipt` and `emit_execution_receipt_timestamped` are the single place a
  receipt is hashed, signed and chained, with a bounded retry on a chain-head conflict.
- **Verification.** The offline `verify` binary and `reede receipt verify`. Authenticity is
  fail-closed; timestamp qualification is fail-open and reported as a distinct verdict, so a
  signed but untimestamped receipt is never presented as fully qualified. Strict mode
  (`--json` or `--strict`) requires a trusted public key and supports `--require-genesis`,
  `--expected-head`, `--expected-count` and `--expected-tenant`; it also checks the sequence
  numbers of a `reede-v2` chain.
- **`reede serve` (feature `ingest`).** A local OTLP/HTTP trace ingest that seals every reported
  span into a signed, chained receipt, and `reede ingest check` to verify the sealed directory
  offline. This is the reported tier: it proves what the agent reported and when this machine
  sealed it, not that the report is true. Examples for LangGraph and Mastra are in
  `examples/otel`; the guide is `docs/ingest.md`.
- **Lifecycle CLI.** `reede kill`, `tasks` and `lease` (feature `cli`), `reede deploy`
  (manifest validation only) and `reede status`.
- **Feedback subsystem.** Subject identity, an append-only signal store, producer and reducer
  traits, rating and correction producers, a feedback surface, consumers with human-gated lesson
  deltas, per-role memory with promotion policy, hygiene and retraction, the honesty layer, depth
  bands, and the golden set as a regression gate.
- **Clients.** Python and JavaScript/TypeScript service clients in `sdk/`, with conformance
  tests and offline-verification helpers that call the Rust verifier.
- **Docs and examples.** Four runnable examples (`manifest`, `leash`, `receipt`, `verify`), the
  public specifications in `docs/`, a Claude Code skill (`reede-deploy`) that derives a leash
  from an agent manifest, and standalone CI plus a tag-driven release workflow.

### Not yet wired

- No RFC 3161 timestamp authority is configured, so receipts are signed but not timestamped.
- The default isolation backend is `PassthroughBackend` (no isolation); network-level egress
  enforcement depends on a provisioned sandbox.
- The approval threshold from `derive_policy` is computed, not enforced, in this crate.
- `reede policy` and `reede logs` are not implemented, and there is no `reede run`.
