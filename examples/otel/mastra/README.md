# Mastra -> reede serve

A Mastra agent on the AI SDK's mock model (no API key), exporting traces with
`@mastra/otel-exporter` (custom provider, `http/protobuf`) to `reede serve`.

```text
./run.sh        # REEDE_BIN=<path to a reede built with --features ingest>; Node 20+
```

Run on Node 25 with `@mastra/core` 1.85.0, `@mastra/observability` 1.24.2,
`@mastra/otel-exporter` 1.6.1, `ai` 6.0.332 (all pinned, with a lockfile).

## What it emits (observed)

One generate call produces 8 spans in one trace: `generic`, two `processor_run`, `model_chunk`,
`chat`, `agent_step`, `model_generation` and `invoke_agent`. Only the `chat` span carries
`gen_ai.usage.input_tokens` / `output_tokens`, so exactly one receipt has `tokens_used` 19.
Like the LangGraph example, the spans can carry prompts and outputs; keep the output
directory private.

The exporter config is the whole integration:

```js
new OtelExporter({ provider: { custom: { endpoint: 'http://127.0.0.1:4318', protocol: 'http/protobuf' } } })
```

`endpoint` is the collector base; Mastra appends `/v1/traces`. Call `mastra.shutdown()` before
exit so the batch exporter flushes.

## Real model

Give the Agent Mastra's OpenAI-compatible config pointed at `https://api.cortecs.ai/v1`
(see the comment in `agent.js`). Not run here.
