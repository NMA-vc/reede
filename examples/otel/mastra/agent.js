// A Mastra agent on a mock model, exporting its traces over OTLP/HTTP protobuf to `reede serve`.
// No API key and no network model call: the model is the AI SDK's own mock.
//
// Real-model variant (not run here): give the Agent
//   model: { id: 'openai/<a Cortecs model id>', url: 'https://api.cortecs.ai/v1', apiKey: process.env.CORTECS_API_KEY }
// (Mastra's OpenAI-compatible config). Do not point it at an OpenAI, Anthropic or Gemini endpoint.
import { Mastra } from '@mastra/core/mastra';
import { Agent } from '@mastra/core/agent';
import { Observability } from '@mastra/observability';
import { OtelExporter } from '@mastra/otel-exporter';
import { MockLanguageModelV3 } from 'ai/test';

const model = new MockLanguageModelV3({
  doGenerate: async () => ({
    content: [{ type: 'text', text: 'a reported receipt proves what was reported' }],
    finishReason: { unified: 'stop', raw: 'stop' },
    usage: {
      inputTokens: { total: 12, noCache: 12 },
      outputTokens: { total: 7, text: 7 },
    },
    warnings: [],
  }),
});

const agent = new Agent({ id: 'demo', name: 'demo', instructions: 'Answer briefly.', model });

const endpoint = process.env.REEDE_OTLP_ENDPOINT ?? 'http://127.0.0.1:4318';
const mastra = new Mastra({
  agents: { agent },
  observability: new Observability({
    configs: {
      reede: {
        serviceName: 'reede-mastra-example',
        exporters: [new OtelExporter({ provider: { custom: { endpoint, protocol: 'http/protobuf' } } })],
      },
    },
  }),
});

const res = await mastra.getAgent('agent').generate('What does a reported receipt prove?');
console.log(res.text);
await mastra.shutdown?.(); // flushes the batch exporter
