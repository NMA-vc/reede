# LangGraph -> reede serve

A two-node LangGraph agent on a fake chat model (no API key, no network model call), traced
through LangSmith's OpenTelemetry integration and sealed into reede receipts by `reede serve`.
Nothing is sent to LangSmith: `LANGSMITH_TRACING_MODE=otel` exports over OTLP only.

```text
./run.sh        # REEDE_BIN=<path to a reede built with --features ingest>
```

It starts `reede serve`, runs `agent.py`, then runs `reede ingest check` and
`reede receipt verify`. Versions are pinned in `requirements.txt` (langsmith 0.15.1,
langgraph 1.2.24, langchain-core 1.8.4; run with Python 3.12 and 3.14).

## What it emits (observed, not assumed)

One trace, five spans per run: the graph (`LangGraph`), each node (`draft`, `finalize`) and
each model call (`FakeChat`). LangSmith writes `gen_ai.*` attributes on all of them, but only
the model-call spans carry `gen_ai.usage.input_tokens` / `output_tokens`, so the receipts'
`tokens_used` is 19 on those two and 0 on the three chain spans. Spans also carry
`gen_ai.prompt` and `gen_ai.completion` (the full inputs and outputs as JSON), which means
they are sealed into `spans/<seq>.json`: keep the output directory as private as the data.

LangSmith has to be told where to export:

| Variable | Value |
|---|---|
| `LANGSMITH_TRACING` | `true` |
| `LANGSMITH_TRACING_MODE` | `otel` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://127.0.0.1:4318` (a base URL; `/v1/traces` is appended) |
| `OTEL_EXPORTER_OTLP_HEADERS` | any non-empty `k=v`, so no `x-api-key` header is built |

## Real model

Replace `FakeChat` with `langchain-openai`'s `ChatOpenAI(base_url="https://api.cortecs.ai/v1",
api_key=..., model=<a Cortecs model id>)`. Not run here. Use no OpenAI, Anthropic or Gemini
endpoint.
