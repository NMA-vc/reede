# reede serve: reported receipts for any OpenTelemetry agent

Keep your framework. Point your exporter at Reede. `reede serve` is a local OTLP/HTTP trace
ingest that seals every span it receives into a signed, hash-chained `reede-v2` receipt, which
`reede receipt verify` (or the standalone `verify` binary) checks offline.

This is the **reported** tier. A reported receipt proves what the agent reported and when this
machine sealed it. It does not prove the report is true, and it carries no trusted timestamp
(no TSA, `tsa_token` is null): a verifier reports it as signed, not timestamped. Whoever runs
the ingest holds the signing key and could seal anything.

## Build and run

The feature is off by default; the default build and the `verify` binary are unchanged.

```text
cargo install --path . --features ingest
reede serve [--listen 127.0.0.1:4318] [--out <dir>] [--tenant local] [--allow-remote]
reede ingest check --out <dir> [--pubkey <hex>]
```

- Binds loopback by default. A non-loopback `--listen` is refused unless `--allow-remote`;
  the server has no authentication and no TLS, so put it behind something that has both.
- `POST /v1/traces` with `application/x-protobuf` (what the Python OTel exporter sends) or
  `application/json` (OTLP JSON). Success is `200` with an empty `ExportTraceServiceResponse`
  (`{}` for JSON). `413` over 8 MiB, `415` for other content types or any `Content-Encoding`
  other than identity (turn exporter compression off), `400` for a malformed body or a span
  whose trace id is not 16 non-zero bytes or span id not 8. Spans of a rejected request are
  not sealed. One request per connection, 32 connections at once, 60 s to read a request, 16 KiB
  and 64 headers at most; a request with both `Content-Length` and `Transfer-Encoding`, a
  duplicate `Content-Length` or whitespace before a header colon is `400`. No gRPC.
- **Do not blindly retry a failed export.** Spans are sealed one by one; if a request fails
  part way (`500`), the spans before the failure are already sealed, and a retry seals them
  again as new receipts (duplicates, each a valid receipt). Once a request has been read in
  full, sealing is never cancelled by a timeout.

## What is sealed

One receipt per span, through the crate's `emit_execution_receipt` (no private hashing):

| Receipt field | Value |
|---|---|
| `tenant_id` | `--tenant` (default `local`) |
| `task_id` | the trace id, as a UUID (same 16 bytes) |
| `subject_id` | `reported:<trace_id_hex>/<span_id_hex>`; this is where the tier lives, the format stays `reede-v2` |
| `payload_summary` | SHA-256 hex of the canonical span serialization below |
| `tokens_used` | `gen_ai.usage.input_tokens` + `gen_ai.usage.output_tokens` when present (int or whole-number double), else 0 |
| `credits_spent`, `reservation_credits` | 0 |

### Canonical span serialization

The span file `spans/<seq>.json` is `{"resource": [...attributes], "scope": {name, version}|null,
"span": {...}}` in OTLP JSON shape: camelCase keys, ids as lowercase hex, 64-bit integers and
timestamps as decimal strings, every modelled field always present. The summary is the SHA-256
of that value as canonical JSON: UTF-8, object keys sorted, no whitespace. In Python:

```python
hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
```

(Verified against the LangGraph example's output.) Caveat: double values use Rust's shortest
representation; an exponent form may differ from Python's. Fields the ingest does not model
(dropped-attribute counts, span and link `flags`) are not sealed.
Non-finite doubles cannot be written as JSON numbers; they are stored as the strings `"NaN"`,
`"Infinity"` and `"-Infinity"` (as OTLP JSON does), so spans that differ only there have
different summaries.

## Privacy: spans contain what the agent reported, in clear

Some frameworks put full prompts and completions into span attributes (LangSmith's integration
does: `gen_ai.prompt` and `gen_ai.completion`). Those are sealed and stored unredacted in
`spans/<seq>.json`. The receipt only holds a hash, but verifying a span means handing over the
span file, and **sharing span files for verification discloses that content**. Share only the
spans you intend to disclose (a chain with the other receipts is still checkable
with `receipt verify`, but `ingest check` needs every span file). The output directory is
created mode 0700 and its files 0600; an existing directory keeps its own permissions.

## Files under `--out`

`chain.json` (the JSON array `reede verify --chain` reads; rewritten via temp file and rename
after each request), `spans/<seq>.json`, `pubkey.hex`, `signing.key` (hex Ed25519 seed, created
on first run with mode 0600, never printed; keep it private, never commit it). Appends are
serialized behind one lock so sequence numbers stay contiguous.

## Restart

On start the existing chain is verified (from genesis, this tenant, signatures against the key)
and appending continues from its head. If it fails verification, or `--tenant` differs, `serve`
refuses to start. It also refuses when `spans/` holds a span with a higher number than the
chain has receipts (a deleted or truncated `chain.json`, or a crash between writing a span and
its receipt): starting would restart at genesis and overwrite `spans/1.json`. Restore
`chain.json`, or inspect and move `spans/` aside. Nothing is repaired automatically.

## Checking

`reede ingest check --out <dir> [--pubkey <hex>]` verifies the chain from genesis against `pubkey.hex`, then for
every receipt recomputes the span-file hash and compares it with `payload_summary`, and checks
that `subject_id` and `task_id` match the ids inside the span file. It also fails on a span file
past the end of the chain, which is how a dropped head receipt shows (a chain alone cannot show
that). Editing a span file, a receipt field, or removing a receipt fails it; tests cover each.
Without `--pubkey`, the key in `pubkey.hex` next to the chain is trusted, which only shows the
directory is self-consistent: whoever holds a copy can re-sign everything under a new key. Pin
the key you were given with `--pubkey`, and pin the head hash or count you published with `reede receipt verify --strict --expected-head`
or `--expected-count` to detect truncation by someone who also deletes the span file.

Implementation note: sealing does its small file writes (fsynced temp file, then rename) on the
async runtime thread while holding the append lock; fine for local use, not tuned for
high-volume ingest.

## Examples

`examples/otel/langgraph` (LangSmith's OTel integration) and `examples/otel/mastra`
(`@mastra/otel-exporter`), each with a `run.sh`, run against fake models. Both emit `gen_ai.*`
attributes; only the model-call span carries token usage, so token counts are not duplicated
across a trace.
