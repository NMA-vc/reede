import contextvars
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from reede_client import AgentHostClient, ReedeClient, ReedeError, _TRANSPORT_SLOTS, verify_file

TASK = "00000000-0000-0000-0000-000000000001"


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.responses = []
        requests, responses = self.requests, self.responses

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.answer()

            def do_POST(self):
                self.answer()

            def answer(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                parsed = json.loads(body) if body else None
                requests.append((self.command, self.path, self.headers.get("Authorization"), parsed))
                code, payload = responses.pop(0) if responses else (200, [])
                if payload == "rpc":
                    payload = {"jsonrpc": "2.0", "id": parsed["id"], "result": {"task_id": TASK}}
                self.send_response(code)
                self.send_header("Retry-After", "0")
                self.send_header("Location", "/credential-sink")
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.client = ReedeClient(self.url, "secret-token", allow_local_http=True)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_routes_and_authorization_without_tenant_override(self):
        self.responses.extend([(200, []), (200, {"id": TASK}), (200, []), (202, {"id": TASK})])
        self.client.list_tasks(limit=3)
        self.client.get_task(TASK)
        self.client.list_leases(TASK)
        self.client.cancel_task(TASK)
        self.assertEqual([r[1] for r in self.requests], ["/api/v1/reede/tasks?limit=3", f"/api/v1/reede/tasks/{TASK}", f"/api/v1/reede/tasks/{TASK}/leases", f"/api/v1/reede/tasks/{TASK}/cancel"])
        self.assertTrue(all(r[2] == "Bearer secret-token" for r in self.requests))
        self.assertNotIn("secret-token", repr(self.client))

    def test_reads_retry_but_writes_and_redirects_do_not(self):
        self.responses.extend([(503, {"private": "secret-token"}), (200, [])])
        self.client.list_tasks()
        self.assertEqual(len(self.requests), 2)
        self.responses.append((503, {"private": "secret-token"}))
        with self.assertRaises(ReedeError) as error:
            self.client.cancel_task(TASK)
        self.assertEqual(len(self.requests), 3)
        self.assertNotIn("secret-token", str(error.exception))
        self.responses.append((302, {}))
        with self.assertRaises(ReedeError):
            self.client.get_task(TASK)
        self.assertEqual(len(self.requests), 4)

    def test_rpc_operations_match_implemented_contract(self):
        host = AgentHostClient(self.url, "secret-token", allow_local_http=True)
        self.responses.extend([(200, "rpc")] * 8)
        host.submit("agent", {"topic": "spring"}, invocation_id="stable")
        host.start(TASK)
        host.status(TASK)
        host.decide("approval-key", "approve", edited_output="reviewed")
        host.cancel(TASK)
        host.pending_tools(task_id=TASK, limit=20)
        host.decide_tool("tool-key", "approve")
        host.recover(TASK)
        self.assertEqual([r[3]["method"] for r in self.requests], ["task.submit", "task.start", "task.status", "task.decide", "task.cancel", "task.tool_pending", "task.tool_decide", "task.recover"])
        self.assertEqual(self.requests[0][3]["params"]["invocation_id"], "stable")
        self.assertEqual(self.requests[3][3]["params"]["edited_output"], "reviewed")
        self.assertEqual(self.requests[5][3]["params"], {"task_id": TASK, "limit": 20})
        self.assertEqual(self.requests[6][3]["params"], {"approval_key": "tool-key", "decision": "approve"})
        self.assertEqual(self.requests[7][3]["params"], {"task_id": TASK})

    def test_configuration_rejects_unsafe_destinations_and_path_injection(self):
        for url in [self.url, "https://token@example.com", "https://example.com?tenant=x", "https://example.com#x", "http://example.com"]:
            with self.assertRaises(ValueError):
                ReedeClient(url, "token")
        with self.assertRaises(ValueError):
            self.client.get_task("../../secrets")
        self.assertEqual(self.requests, [])


class TransportDeadlineTests(unittest.TestCase):
    def test_token_callback_inherits_caller_contextvars(self):
        request_token = contextvars.ContextVar("reede_request_token", default="missing")
        caller_value = request_token.set("request-local-token")
        authorization = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _limit):
                return b"[]"

        class Opener:
            def open(self, request, **_kwargs):
                authorization.append(request.get_header("Authorization"))
                return Response()

        try:
            client = ReedeClient("https://example.com", request_token.get, timeout=1)
            client._opener = Opener()
            client.list_tasks()
        finally:
            request_token.reset(caller_value)

        self.assertEqual(authorization, ["Bearer request-local-token"])

    def test_slow_token_callback_cannot_dispatch_after_deadline(self):
        release = threading.Event()
        entered = threading.Event()
        dispatches = []

        def token():
            entered.set()
            release.wait(2)
            return "token"

        class Opener:
            def open(self, *_args, **_kwargs):
                dispatches.append(True)
                raise AssertionError("expired request was dispatched")

        client = ReedeClient("https://example.com", token, timeout=0.05)
        client._opener = Opener()
        with self.assertRaises(ReedeError) as caught:
            client.list_tasks()
        self.assertEqual(caught.exception.code, "transport_timeout")
        self.assertTrue(entered.is_set())

        release.set()
        acquired = 0
        deadline = time.monotonic() + 2
        try:
            while acquired < 4 and time.monotonic() < deadline:
                if _TRANSPORT_SLOTS.acquire(blocking=False):
                    acquired += 1
                else:
                    time.sleep(0.01)
            self.assertEqual(acquired, 4, "expired token worker should release its slot")
            self.assertEqual(dispatches, [])
        finally:
            for _ in range(acquired):
                _TRANSPORT_SLOTS.release()

    def test_total_deadline_and_bounded_worker_cleanup(self):
        release = threading.Event()
        entered = threading.Semaphore(0)

        class DripLikeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self, _limit):
                # Simulate a peer that makes progress more often than the
                # socket timeout but takes longer than the whole-call deadline.
                for _ in range(50):
                    if release.wait(0.01):
                        return b"[]"
                return b"[]"

        class DripLikeOpener:
            def open(self, *_args, **_kwargs):
                entered.release()
                return DripLikeResponse()

        clients = [ReedeClient("https://example.com", "token", timeout=0.05) for _ in range(4)]
        for client in clients:
            client._opener = DripLikeOpener()
            with self.assertRaises(ReedeError) as caught:
                client.get_task(TASK)
            self.assertEqual(caught.exception.code, "transport_timeout")
            self.assertTrue(entered.acquire(timeout=1))

        try:
            with self.assertRaises(ReedeError) as caught:
                clients[0].get_task(TASK)
            self.assertEqual(caught.exception.code, "transport_busy")
        finally:
            release.set()

        acquired = 0
        deadline = time.monotonic() + 2
        try:
            while acquired < 4 and time.monotonic() < deadline:
                if _TRANSPORT_SLOTS.acquire(blocking=False):
                    acquired += 1
                else:
                    time.sleep(0.01)
            self.assertEqual(acquired, 4, "all timed-out workers should release their bounded slots")
        finally:
            for _ in range(acquired):
                _TRANSPORT_SLOTS.release()


class OfflineVerificationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("REEDE_VERIFY_BIN"), "set REEDE_VERIFY_BIN to run shared Rust conformance")
    def test_shared_vectors_and_tamper_against_shipping_core(self):
        fixtures = Path(__file__).resolve().parents[3] / "tests/fixtures"
        verifier = os.environ["REEDE_VERIFY_BIN"]
        with tempfile.TemporaryDirectory() as tmp:
            chain = Path(tmp) / "chain.json"

            def write(receipt):
                chain.write_text(json.dumps([receipt]))

            # reede-v2 (what Reede emits): the vector is the chain's seq-2 link, so it is a
            # trusted-head segment, not a whole history.
            v2 = json.loads((fixtures / "reede-v2-vector.json").read_text())
            r2, pub2 = v2["receipt"], v2["pubkey_hex"]
            self.assertEqual(r2["format"], "reede-v2")
            write(r2)
            report = verify_file(chain, pub2, verifier=verifier, expected_head=r2["content_hash"], expected_count=1)
            self.assertEqual(report["completeness"], "supplied_segment_only")
            with self.assertRaises(ReedeError):
                verify_file(chain, pub2, verifier=verifier, expected_head=r2["content_hash"], expected_count=1, require_genesis=True)
            # Every signed v2 field is tamper-evident, including the outer sequence_no and timestamp.
            for field, value in [("credits_spent", r2["credits_spent"] + 1), ("sequence_no", 3), ("timestamp", "2023-11-14T22:13:21.123456Z")]:
                write({**r2, field: value})
                with self.assertRaises(ReedeError, msg=field):
                    verify_file(chain, pub2, verifier=verifier)
                # The SDK error is opaque by design; ask the verifier itself for the reason.
                out = subprocess.run([verifier, "--chain", str(chain), "--pubkey", pub2, "--json"], capture_output=True, text=True)
                self.assertEqual(out.returncode, 1, field)
                self.assertIn("content_hash mismatch", json.loads(out.stdout)["error"], field)

            # reede-v1 (legacy): still recomputed and accepted; its genesis vector verifies whole.
            v1 = json.loads((fixtures / "reede-v1-vector.json").read_text())
            r1 = v1["receipt"]
            self.assertEqual(r1["format"], "reede-v1")
            write(r1)
            report = verify_file(chain, v1["pubkey_hex"], verifier=verifier, expected_head=r1["content_hash"], expected_count=1, require_genesis=True)
            self.assertEqual(report["completeness"], "verified_against_trusted_boundary")
            write({**r1, "credits_spent": r1["credits_spent"] + 1})
            with self.assertRaises(ReedeError):
                verify_file(chain, v1["pubkey_hex"], verifier=verifier)


if __name__ == "__main__":
    unittest.main()
