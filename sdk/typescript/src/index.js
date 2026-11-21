import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { randomUUID } from "node:crypto";

const MAX_BYTES = 2 * 1024 * 1024;
const execute = promisify(execFile);

export class ReedeError extends Error {
  constructor(code, status, requestId) {
    super(`Reede request failed: ${code}${status ? ` (HTTP ${status})` : ""}`);
    this.name = "ReedeError";
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

function baseUrl(raw, allowLocalHttp) {
  try {
    const url = new URL(raw);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if ((url.protocol !== "https:" && !(allowLocalHttp && loopback && url.protocol === "http:")) || url.username || url.password || url.search || url.hash) throw new Error();
    return url.href.replace(/\/$/, "");
  } catch {
    throw new TypeError("base URL must be HTTPS without credentials, query or fragment; local HTTP requires explicit opt-in");
  }
}

function taskId(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) throw new TypeError("task ID must be a UUID");
  return value.toLowerCase();
}

function parseJson(text) {
  // Preserve large JSON integers as decimal strings instead of silently
  // rounding signed receipt/credit fields. Node 22+ supplies the source text.
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value === "number" && Number.isInteger(value) && !Number.isSafeInteger(value)) {
      if (!context?.source || !/^-?\d+$/.test(context.source)) throw new ReedeError("unsafe_numeric_response");
      return context.source;
    }
    return value;
  });
}

async function bodyJson(response) {
  const chunks = [];
  let size = 0;
  if (!response.body) throw new ReedeError("invalid_response", response.status);
  const reader = response.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) throw new ReedeError("response_too_large", response.status);
      chunks.push(value);
    }
    return parseJson(Buffer.concat(chunks).toString("utf8"));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function object(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ReedeError("invalid_response");
  return value;
}

function objects(value) {
  if (!Array.isArray(value)) throw new ReedeError("invalid_response");
  return value.map(object);
}

export class ReedeClient {
  #token;
  constructor(base, token, { timeoutMs = 30000, readRetries = 2, allowLocalHttp = false } = {}) {
    this.baseUrl = baseUrl(base, allowLocalHttp);
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || !Number.isInteger(readRetries) || readRetries < 0 || readRetries > 5) throw new TypeError("positive timeoutMs and 0..5 readRetries required");
    this.#token = token;
    this.timeoutMs = timeoutMs;
    this.readRetries = readRetries;
  }
  async _request(method, path, body, signal) {
    for (let attempt = 0; attempt <= this.readRetries; attempt++) {
      const token = typeof this.#token === "function" ? await this.#token() : this.#token;
      if (typeof token !== "string" || !/^[\x21-\x7e]+$/.test(token)) throw new ReedeError("invalid_token");
      const requestSignal = AbortSignal.any([AbortSignal.timeout(this.timeoutMs), ...(signal ? [signal] : [])]);
      let response;
      try {
        response = await fetch(this.baseUrl + path, {
          method, redirect: "manual", signal: requestSignal,
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json" },
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        if (response.ok) return await bodyJson(response);
      } catch (error) {
        if (error instanceof ReedeError) throw error;
        throw new ReedeError(signal?.aborted ? "cancelled" : requestSignal.aborted ? "timeout" : "transport_error");
      }
      const status = response.status;
      const requestId = response.headers.get("x-request-id") ?? undefined;
      const retryAfter = response.headers.get("retry-after");
      await response.body?.cancel();
      if (method === "GET" && [429, 502, 503, 504].includes(status) && attempt < this.readRetries) {
        const pause = retryAfter && /^\d+$/.test(retryAfter) ? Math.min(2000, Number(retryAfter) * 1000) : Math.min(2000, 100 * 2 ** attempt);
        try { await delay(pause, undefined, { signal }); } catch { throw new ReedeError("cancelled"); }
        continue;
      }
      const code = ({ 401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict", 429: "busy", 501: "unsupported" })[status] ?? (status >= 500 ? "server_error" : "refused");
      throw new ReedeError(code, status, requestId);
    }
    throw new ReedeError("retry_exhausted");
  }
  async listTasks({ limit = 50, signal } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw new TypeError("limit must be 1..500");
    return objects(await this._request("GET", `/api/v1/reede/tasks?limit=${limit}`, undefined, signal));
  }
  async getTask(id, { signal } = {}) { return object(await this._request("GET", `/api/v1/reede/tasks/${taskId(id)}`, undefined, signal)); }
  async cancelTask(id, { signal } = {}) { return object(await this._request("POST", `/api/v1/reede/tasks/${taskId(id)}/cancel`, undefined, signal)); }
  async listLeases(id, { signal } = {}) { return objects(await this._request("GET", `/api/v1/reede/tasks/${taskId(id)}/leases`, undefined, signal)); }
}

export class AgentHostClient extends ReedeClient {
  async _rpc(method, params, signal) {
    const id = randomUUID();
    const response = object(await this._request("POST", "/mcp", { jsonrpc: "2.0", id, method, params }, signal));
    if (response.id !== id || response.jsonrpc !== "2.0") throw new ReedeError("invalid_rpc_response");
    if (response.error) throw new ReedeError("rpc_error");
    if (!("result" in response)) throw new ReedeError("invalid_rpc_response");
    return response.result;
  }
  submit(agentId, input, { invocationId, signal } = {}) {
    return this._rpc("task.submit", { agent_id: agentId, input, ...(invocationId === undefined ? {} : { invocation_id: invocationId }) }, signal);
  }
  start(id, { signal } = {}) { return this._rpc("task.start", { task_id: taskId(id) }, signal); }
  status(id, { signal } = {}) { return this._rpc("task.status", { task_id: taskId(id) }, signal); }
  cancel(id, { signal } = {}) { return this._rpc("task.cancel", { task_id: taskId(id) }, signal); }
  recover(id, { signal } = {}) { return this._rpc("task.recover", { task_id: taskId(id) }, signal); }
  pending({ signal } = {}) { return this._rpc("task.pending", {}, signal); }
  pendingTools({ taskId: id, limit = 100, signal } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new TypeError("limit must be an integer from 1 to 100");
    return this._rpc("task.tool_pending", { limit, ...(id === undefined ? {} : { task_id: taskId(id) }) }, signal);
  }
  decideTool(approvalKey, decision, { signal } = {}) {
    if (!["approve", "reject"].includes(decision)) throw new TypeError("decision must be approve or reject");
    return this._rpc("task.tool_decide", { approval_key: approvalKey, decision }, signal);
  }
  decide(approvalKey, decision, { editedOutput, signal } = {}) {
    if (!["approve", "reject"].includes(decision)) throw new TypeError("decision must be approve or reject");
    return this._rpc("task.decide", { approval_key: approvalKey, decision, ...(editedOutput === undefined ? {} : { edited_output: editedOutput }) }, signal);
  }
}

export async function verifyFile(chain, publicKey, { verifier = "verify", expectedHead, expectedCount, expectedTenant, requireGenesis = false } = {}) {
  const args = ["--chain", chain, "--pubkey", publicKey, "--json"];
  for (const [flag, value] of [["--expected-head", expectedHead], ["--expected-count", expectedCount], ["--expected-tenant", expectedTenant]]) {
    if (value !== undefined) args.push(flag, String(value));
  }
  if (requireGenesis) args.push("--require-genesis");
  let result;
  try { result = await execute(verifier, args, { timeout: 30000, maxBuffer: 1024 * 1024, encoding: "utf8" }); }
  catch { throw new ReedeError("verification_failed"); }
  let report;
  try { report = JSON.parse(result.stdout); } catch { throw new ReedeError("invalid_verification_response"); }
  if (report.schema !== "reede-verification-v1" || report.authentic !== true) throw new ReedeError("verification_failed");
  return report;
}
