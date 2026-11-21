"""Reede's implemented lifecycle and agent-host protocols.

Tenant authority always comes from the bearer credential. No client tenant
override is accepted. Mutations are never retried automatically.
"""
from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import json
import math
import queue
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

JSON = dict[str, Any]
Token = str | Callable[[], str]
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_VERIFIER_BYTES = 1024 * 1024
_VERIFIER_SLOTS = threading.BoundedSemaphore(4)
_TRANSPORT_SLOTS = threading.BoundedSemaphore(4)


@dataclass
class ReedeError(Exception):
    """Safe structured failure; response bodies and credentials are excluded."""
    code: str
    status: int | None = None
    request_id: str | None = None

    def __str__(self) -> str:
        return f"Reede request failed: {self.code}" + (f" (HTTP {self.status})" if self.status else "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _base_url(raw: str, allow_local_http: bool) -> str:
    try:
        url = urllib.parse.urlsplit(raw)
        host = url.hostname or ""
        local = host == "localhost"
        try:
            local = local or ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
        _ = url.port
        if (url.scheme != "https" and not (allow_local_http and local and url.scheme == "http")) or not host or url.username is not None or url.password is not None or url.query or url.fragment:
            raise ValueError()
        return raw.rstrip("/")
    except ValueError:
        raise ValueError("base URL must be HTTPS without credentials, query or fragment; local HTTP requires explicit opt-in") from None


def _task_id(value: str) -> str:
    return str(uuid.UUID(value))


class ReedeClient:
    def __init__(self, base_url: str, token: Token, *, timeout: float = 30, read_retries: int = 2, allow_local_http: bool = False) -> None:
        self.base_url = _base_url(base_url, allow_local_http)
        if not math.isfinite(timeout) or timeout <= 0 or not 0 <= read_retries <= 5:
            raise ValueError("positive finite timeout and 0..5 read retries required")
        self._token = token
        self.timeout = timeout
        self.read_retries = read_retries
        self._opener = urllib.request.build_opener(_NoRedirect())

    def __repr__(self) -> str:
        return f"ReedeClient(base_url={self.base_url!r}, token=<redacted>)"

    def _request(self, method: str, path: str, body: JSON | None = None) -> Any:
        """Run one bounded HTTP operation under a total caller deadline.

        urllib exposes socket-operation timeouts but cannot interrupt a read
        whose peer keeps making progress. A fixed number of daemon workers
        bounds those operations; a worker that outlives its deadline retains
        its slot until urllib returns, so repeated slow peers cannot create an
        unbounded number of threads.
        """
        if not _TRANSPORT_SLOTS.acquire(blocking=False):
            raise ReedeError("transport_busy")
        deadline = time.monotonic() + self.timeout
        completed: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def run() -> None:
            try:
                try:
                    result = self._request_until(method, path, body, deadline)
                    completed.put((True, result))
                except BaseException as error:
                    completed.put((False, error))
            finally:
                _TRANSPORT_SLOTS.release()

        try:
            caller_context = contextvars.copy_context()
            worker = threading.Thread(target=caller_context.run, args=(run,), name="reede-http-request", daemon=True)
        except BaseException:
            _TRANSPORT_SLOTS.release()
            raise
        try:
            worker.start()
        except BaseException as error:
            # A failed start has no worker to release the slot. If start was
            # interrupted after the OS thread began, its own finally handles it.
            if worker.ident is None:
                _TRANSPORT_SLOTS.release()
            if isinstance(error, RuntimeError):
                raise ReedeError("transport_unavailable") from None
            raise
        try:
            ok, result = completed.get(timeout=max(0, deadline - time.monotonic()))
        except queue.Empty:
            raise ReedeError("transport_timeout") from None
        if time.monotonic() >= deadline:
            raise ReedeError("transport_timeout")
        if ok:
            return result
        if isinstance(result, ReedeError):
            raise result
        if isinstance(result, (urllib.error.URLError, TimeoutError, OSError)):
            raise ReedeError("transport_error") from None
        raise result

    def _request_until(self, method: str, path: str, body: JSON | None, deadline: float) -> Any:
        payload = json.dumps(body, allow_nan=False).encode() if body is not None else None
        for attempt in range(self.read_retries + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ReedeError("transport_timeout")
            token = self._token() if callable(self._token) else self._token
            if not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
                raise ReedeError("invalid_token")
            request = urllib.request.Request(self.base_url + path, data=payload, method=method, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"})
            try:
                # Token providers may block or do other request-local work.
                # Do not dispatch if that work consumed the caller's budget.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReedeError("transport_timeout")
                with self._opener.open(request, timeout=min(self.timeout, remaining)) as response:
                    data = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(data) > MAX_RESPONSE_BYTES:
                        raise ReedeError("response_too_large", response.status)
                    try:
                        return json.loads(data)
                    except (ValueError, UnicodeError):
                        raise ReedeError("invalid_response", response.status) from None
            except urllib.error.HTTPError as error:
                status = error.code
                request_id = error.headers.get("x-request-id")
                retry_after = error.headers.get("Retry-After", "")
                error.close()
                if method == "GET" and status in (429, 502, 503, 504) and attempt < self.read_retries:
                    delay = min(2.0, float(retry_after)) if retry_after.isdigit() else min(2.0, 0.1 * 2**attempt)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ReedeError("transport_timeout")
                    time.sleep(min(delay, remaining))
                    continue
                codes = {401: "unauthorized", 403: "forbidden", 404: "not_found", 409: "conflict", 429: "busy", 501: "unsupported"}
                raise ReedeError(codes.get(status, "server_error" if status >= 500 else "refused"), status, request_id) from None
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                # An ambiguous transport failure is not retried, even on writes
                # which the server might already have accepted.
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                if isinstance(reason, TimeoutError) or time.monotonic() >= deadline:
                    raise ReedeError("transport_timeout") from None
                raise ReedeError("transport_error") from None
        raise ReedeError("retry_exhausted")

    def list_tasks(self, *, limit: int = 50) -> list[JSON]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("limit must be 1..500")
        return self._request("GET", f"/api/v1/reede/tasks?limit={limit}")

    def get_task(self, task_id: str) -> JSON:
        return self._request("GET", f"/api/v1/reede/tasks/{_task_id(task_id)}")

    def cancel_task(self, task_id: str) -> JSON:
        return self._request("POST", f"/api/v1/reede/tasks/{_task_id(task_id)}/cancel")

    def list_leases(self, task_id: str) -> list[JSON]:
        return self._request("GET", f"/api/v1/reede/tasks/{_task_id(task_id)}/leases")


class AgentHostClient(ReedeClient):
    """Client for the agent host's existing JSON-RPC /mcp endpoint."""
    def _rpc(self, method: str, params: Mapping[str, Any]) -> Any:
        request_id = str(uuid.uuid4())
        response = self._request("POST", "/mcp", {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)})
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or response.get("id") != request_id:
            raise ReedeError("invalid_rpc_response")
        if "error" in response:
            raise ReedeError("rpc_error")
        if "result" not in response:
            raise ReedeError("invalid_rpc_response")
        return response["result"]

    def submit(self, agent_id: str, input: JSON, *, invocation_id: str | None = None) -> JSON:
        params: JSON = {"agent_id": agent_id, "input": input}
        if invocation_id is not None:
            params["invocation_id"] = invocation_id
        return self._rpc("task.submit", params)

    def start(self, task_id: str) -> JSON:
        return self._rpc("task.start", {"task_id": _task_id(task_id)})

    def status(self, task_id: str) -> JSON:
        return self._rpc("task.status", {"task_id": _task_id(task_id)})

    def cancel(self, task_id: str) -> JSON:
        return self._rpc("task.cancel", {"task_id": _task_id(task_id)})

    def recover(self, task_id: str) -> JSON:
        """Request fenced recovery; uncertain effects require reconciliation."""
        return self._rpc("task.recover", {"task_id": _task_id(task_id)})

    def pending(self) -> Any:
        return self._rpc("task.pending", {})

    def pending_tools(self, *, task_id: str | None = None, limit: int = 100) -> JSON:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        params: JSON = {"limit": limit}
        if task_id is not None:
            params["task_id"] = _task_id(task_id)
        return self._rpc("task.tool_pending", params)

    def decide_tool(self, approval_key: str, decision: str) -> JSON:
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be approve or reject")
        return self._rpc("task.tool_decide", {"approval_key": approval_key, "decision": decision})

    def decide(self, approval_key: str, decision: str, *, edited_output: str | None = None) -> JSON:
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be approve or reject")
        params: JSON = {"approval_key": approval_key, "decision": decision}
        if edited_output is not None:
            params["edited_output"] = edited_output
        return self._rpc("task.decide", params)


class AsyncReedeClient:
    """Async facade; a cancelled await does not retract an accepted server request.

    HTTP work runs in a worker thread with urllib socket-operation timeouts,
    not a total request deadline. Call cancel_task to cancel a remote run.
    """
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._client = ReedeClient(*args, **kwargs)

    async def list_tasks(self, *, limit: int = 50) -> list[JSON]:
        return await asyncio.to_thread(self._client.list_tasks, limit=limit)

    async def get_task(self, task_id: str) -> JSON:
        return await asyncio.to_thread(self._client.get_task, task_id)

    async def cancel_task(self, task_id: str) -> JSON:
        return await asyncio.to_thread(self._client.cancel_task, task_id)

    async def list_leases(self, task_id: str) -> list[JSON]:
        return await asyncio.to_thread(self._client.list_leases, task_id)



def _capture_verifier(args: list[str], *, timeout: float = 30) -> tuple[int, bytes]:
    """Bound retained output, process wait and outstanding pipe readers.

    A trusted verifier should not leave descendants holding stdout open. Even if
    a wrapper does so, its abandoned reader retains one of four slots until EOF;
    callers still time out instead of creating unlimited readers/subprocesses.
    """
    if not _VERIFIER_SLOTS.acquire(blocking=False):
        raise ReedeError("verifier_busy")
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except (OSError, ValueError, TypeError):
        _VERIFIER_SLOTS.release()
        raise ReedeError("verifier_unavailable") from None
    except BaseException:
        _VERIFIER_SLOTS.release()
        raise

    completed: queue.Queue[bytes | None] = queue.Queue(maxsize=1)
    finish_lock = threading.Lock()
    finished = {"reader": False, "parent": False}

    def finish(which: str) -> None:
        with finish_lock:
            finished[which] = True
            if all(finished.values()):
                _VERIFIER_SLOTS.release()

    def capture() -> None:
        try:
            assert process.stdout is not None
            # Retain at most one byte above the cap to distinguish overflow.
            completed.put(process.stdout.read(MAX_VERIFIER_BYTES + 1))
        except (OSError, ValueError):
            completed.put(None)
        finally:
            try:
                if process.stdout is not None:
                    process.stdout.close()
            finally:
                finish("reader")

    reader = threading.Thread(target=capture, name="reede-verifier-output", daemon=True)
    try:
        try:
            reader.start()
        except RuntimeError:
            raise ReedeError("verifier_unavailable") from None
        try:
            data = completed.get(timeout=max(0, deadline - time.monotonic()))
            if data is None:
                raise ReedeError("verifier_unavailable")
            if len(data) > MAX_VERIFIER_BYTES:
                raise ReedeError("verifier_output_too_large")
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
            return code, data
        except (queue.Empty, subprocess.TimeoutExpired):
            raise ReedeError("verifier_timeout") from None
    finally:
        try:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                # Do not turn a stuck local wrapper into an unbounded wait.
                pass
        finally:
            # A failed Thread.start has no reader to close/release its half.
            if reader.ident is None:
                if process.stdout is not None:
                    process.stdout.close()
                finish("reader")
            if process.poll() is not None:
                finish("parent")


def verify_file(chain: str | Path, public_key: str, *, verifier: str = "verify", expected_head: str | None = None, expected_count: int | None = None, expected_tenant: str | None = None, require_genesis: bool = False) -> JSON:
    """Use Reede's shared Rust verification core offline, without a shell.

    Install the matching Reede verifier separately; an absolute trusted binary
    path is recommended. No network, account or TSA service is needed.
    """
    args = [verifier, "--chain", str(chain), "--pubkey", public_key, "--json"]
    for flag, value in [("--expected-head", expected_head), ("--expected-count", expected_count), ("--expected-tenant", expected_tenant)]:
        if value is not None:
            args.extend([flag, str(value)])
    if require_genesis:
        args.append("--require-genesis")
    try:
        code, output = _capture_verifier(args)
        report = json.loads(output)
    except (OSError, ValueError):
        raise ReedeError("verifier_unavailable") from None
    if code != 0 or not isinstance(report, dict) or report.get("schema") != "reede-verification-v1" or report.get("authentic") is not True:
        raise ReedeError("verification_failed")
    return report
