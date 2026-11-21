import { AgentHostClient, ReedeClient, verifyFile } from '../src/index.js';
const client = new ReedeClient('https://runtime.example', async () => 'token');
void client.listTasks({ limit: 5, signal: new AbortController().signal });
const host = new AgentHostClient('https://host.example', 'token');
void host.submit('agent', { topic: 'spring' }, { invocationId: 'stable' });
void host.decide('approval', 'approve', { editedOutput: 'reviewed' });
void host.pendingTools({ taskId: '00000000-0000-0000-0000-000000000001', limit: 20 });
void host.decideTool('tool-approval', 'reject');
void host.recover('00000000-0000-0000-0000-000000000001').then(report => { const id: string = report.task_id; void id; });
// @ts-expect-error tool proposals are immutable and do not accept edited output
void host.decideTool('tool-approval', 'approve', { editedOutput: 'replacement' });
// @ts-expect-error reviewer identity comes from the authenticated principal
void host.decideTool('tool-approval', 'approve', { decider: 'other-user' });
void verifyFile('chain.json', 'key', { expectedCount: 1, requireGenesis: true });
// @ts-expect-error authority cannot be overridden with a caller tenant argument
new ReedeClient('https://runtime.example', 'token', { tenantId: 'other' });
// @ts-expect-error only supported decisions are accepted
void host.decide('approval', 'maybe');
