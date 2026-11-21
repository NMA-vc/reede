// A Mastra agent that calls one tool, plus a two-step workflow, both on mock models and
// exporting over OTLP/HTTP protobuf to `reede serve`. No API key, no network model call.
// Run it with `AGENT=agent-tools.js ./run.sh`. `reede ingest runs` turns the spans into runs.
import { Mastra } from '@mastra/core/mastra';
import { Agent } from '@mastra/core/agent';
import { createTool } from '@mastra/core/tools';
import { createWorkflow, createStep } from '@mastra/core/workflows';
import { Observability } from '@mastra/observability';
import { OtelExporter } from '@mastra/otel-exporter';
import { MockLanguageModelV3 } from 'ai/test';
import { z } from 'zod';

let calls = 0;
const model = new MockLanguageModelV3({
  doGenerate: async () => {
    calls += 1;
    if (calls === 1) {
      return {
        content: [{ type: 'tool-call', toolCallId: 'call_1', toolName: 'lookup', input: JSON.stringify({ topic: 'receipts' }) }],
        finishReason: { unified: 'tool-calls', raw: 'tool-calls' },
        usage: { inputTokens: { total: 30, noCache: 30 }, outputTokens: { total: 10, text: 10 } },
        warnings: [],
      };
    }
    return {
      content: [{ type: 'text', text: 'a reported receipt proves what was reported' }],
      finishReason: { unified: 'stop', raw: 'stop' },
      usage: { inputTokens: { total: 50, noCache: 50 }, outputTokens: { total: 9, text: 9 } },
      warnings: [],
    };
  },
});

const lookup = createTool({
  id: 'lookup',
  description: 'Look a topic up.',
  inputSchema: z.object({ topic: z.string() }),
  outputSchema: z.object({ fact: z.string() }),
  execute: async ({ topic }) => ({ fact: `${topic}: sealed by the machine that received them` }),
});

const agent = new Agent({ id: 'demo', name: 'demo', instructions: 'Use lookup, then answer briefly.', model, tools: { lookup } });

const shout = createStep({
  id: 'shout',
  inputSchema: z.object({ text: z.string() }),
  outputSchema: z.object({ text: z.string() }),
  execute: async ({ inputData }) => ({ text: inputData.text.toUpperCase() }),
});
const exclaim = createStep({
  id: 'exclaim',
  inputSchema: z.object({ text: z.string() }),
  outputSchema: z.object({ text: z.string() }),
  execute: async ({ inputData }) => ({ text: `${inputData.text}!` }),
});
const workflow = createWorkflow({
  id: 'shouter',
  inputSchema: z.object({ text: z.string() }),
  outputSchema: z.object({ text: z.string() }),
})
  .then(shout)
  .then(exclaim)
  .commit();

const endpoint = process.env.REEDE_OTLP_ENDPOINT ?? 'http://127.0.0.1:4318';
const mastra = new Mastra({
  agents: { agent },
  workflows: { shouter: workflow },
  observability: new Observability({
    configs: {
      reede: {
        serviceName: 'reede-mastra-tools-example',
        exporters: [new OtelExporter({ provider: { custom: { endpoint, protocol: 'http/protobuf' } } })],
      },
    },
  }),
});

const res = await mastra.getAgent('agent').generate('What does a reported receipt prove?');
console.log(res.text);
const run = await mastra.getWorkflow('shouter').createRun();
console.log((await run.start({ inputData: { text: 'sealed' } })).result);
await mastra.shutdown?.();
