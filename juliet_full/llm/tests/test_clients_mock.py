"""Chat client and run_llm.py against a local mock OpenAI-compatible server (no network, no cost).

Covers: request body (temperature 0, thinking disabled for Qwen), retry with backoff on 503,
no retry on 400, fatal stop on 402, run abort when reasoning tokens appear, invalid model output
-> pred null / status invalid in the prediction file.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LLM_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LLM_DIR))

import run_llm  # noqa: E402
from llmlane import clients  # noqa: E402


def chat_payload(content: str, usage_extra: dict | None = None, message_extra: dict | None = None) -> dict:
    usage = {"prompt_tokens": 500, "completion_tokens": 16, "total_tokens": 516, **(usage_extra or {})}
    return {"id": "x", "model": "qwen3.5-4b", "usage": usage,
            "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": content,
                                                              **(message_extra or {})}}]}


class MockServer:
    """script: list of (status, payload) served in order; the last entry repeats.
    responder: optional callable(body) -> (status, payload) used instead of the script."""

    def __init__(self, script=None, responder=None):
        self.script, self.responder, self.bodies = list(script or []), responder, []
        self.lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._send(200, {"object": "list", "data": [{"id": "qwen3.5-4b"}]})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with outer.lock:
                    outer.bodies.append(body)
                    if outer.responder:
                        status, payload = outer.responder(body)
                    else:
                        status, payload = outer.script.pop(0) if len(outer.script) > 1 else outer.script[0]
                self._send(status, payload)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/v1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


FAST = clients.RetryPolicy(max_attempts=3, base_seconds=0.01, cap_seconds=0.05, timeout_seconds=5)
MESSAGES = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]


class ChatClientMockTest(unittest.TestCase):
    def test_body_and_ok(self):
        server = MockServer([(200, chat_payload('{"label": "vulnerable", "confidence": 0.9}'))])
        try:
            result = clients.qwen_client(server.url, policy=FAST).complete(MESSAGES, 64)
        finally:
            server.close()
        body = server.bodies[0]
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.content, '{"label": "vulnerable", "confidence": 0.9}')
        self.assertEqual((body["temperature"], body["max_tokens"], body["model"]), (0, 64, "qwen3.5-4b"))
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
        self.assertEqual(body["response_format"], {"type": "json_object"})

    def test_retry_then_ok(self):
        server = MockServer([(503, {"error": "busy"}), (200, chat_payload("{}"))])
        try:
            result = clients.qwen_client(server.url, policy=FAST).complete(MESSAGES, 64)
        finally:
            server.close()
        self.assertEqual((result.status, len(result.attempts)), ("ok", 2))

    def test_400_not_retried(self):
        server = MockServer([(400, {"error": "bad request"})])
        try:
            result = clients.qwen_client(server.url, policy=FAST).complete(MESSAGES, 64)
        finally:
            server.close()
        self.assertEqual((result.status, result.error, len(result.attempts)), ("error", "http_400", 1))

    def test_402_is_fatal(self):
        server = MockServer([(402, {"error": "Insufficient Balance"})])
        try:
            with self.assertRaises(clients.FatalApiError):
                clients.qwen_client(server.url, policy=FAST).complete(MESSAGES, 64)
        finally:
            server.close()

    def test_reasoning_tokens_abort(self):
        payload = chat_payload("{}", {"completion_tokens_details": {"reasoning_tokens": 12}})
        server = MockServer([(200, payload)])
        try:
            with self.assertRaises(clients.FatalApiError) as ctx:
                clients.qwen_client(server.url, policy=FAST).complete(MESSAGES, 64)
        finally:
            server.close()
        self.assertEqual(ctx.exception.result.usage["completion_tokens_details"]["reasoning_tokens"], 12)

    def test_reasoning_content_abort_and_zero_count_ok(self):
        server = MockServer([(200, chat_payload("{}", message_extra={"reasoning_content": "let me think"}))])
        try:
            with self.assertRaises(clients.FatalApiError):
                clients.qwen_client(server.url, policy=FAST).complete(MESSAGES, 64)
        finally:
            server.close()
        server = MockServer([(200, chat_payload("{}", {"completion_tokens_details": {"reasoning_tokens": 0}}))])
        try:
            self.assertEqual(clients.qwen_client(server.url, policy=FAST).complete(MESSAGES, 64).status, "ok")
        finally:
            server.close()


UNITS = [
    {"unit_id": f"CWE401_Memory_Leak__int_malloc_{v}__{lab}", "group_id": f"CWE401_Memory_Leak__int_malloc_{v}",
     "family": "int_malloc", "variant": v, "flow_category": "02-22", "mechanism": "c_alloc", "language": "c",
     "set": "dev", "fold": None, "label": lab, "truth": int(lab == "bad"), "good_kind": None,
     "model_text": f"int main(void)\n{{\n    int *p = malloc(4); /* {v}{lab[0]} */\n    return 0;\n}}\n",
     "line_map": []}
    for v in ("04", "10") for lab in ("bad", "good")
]


class RunLlmMockTest(unittest.TestCase):
    def test_qwen_run_writes_contract_files(self):
        answers = {"04b": '{"label": "vulnerable", "confidence": 0.8}',
                   "04g": '{"label": "not_vulnerable", "confidence": 0.7}',
                   "10b": "I think it leaks.",
                   "10g": '{"label": "not_vulnerable"}'}

        def responder(body):
            code = body["messages"][1]["content"]
            key = next(k for k in answers if f"/* {k} */" in code)
            return 200, chat_payload(answers[key])

        server = MockServer(responder=responder)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            units = tmp / "units.jsonl"
            units.write_text("".join(json.dumps(u) + "\n" for u in UNITS))
            try:
                code = run_llm.main(["--model", "qwen", "--strategy", "L1", "--units", str(units), "--set", "dev",
                                     "--keep-l2-examples", "--concurrency", "2", "--warmup-wait", "0",
                                     "--base-url", server.url, "--run-id", "mock", "--out-root", str(tmp / "res"),
                                     "--raw-root", str(tmp / "raw"), "--ledger", str(tmp / "ledger.jsonl")])
            finally:
                server.close()
            self.assertEqual(code, 0)
            out = tmp / "res" / "qwen3_5_4b" / "layer1"
            rows = {json.loads(line)["unit_id"].split("malloc_")[1]: json.loads(line)
                    for line in (out / "mock.jsonl").read_text().splitlines()}
            meta = json.loads((out / "mock.meta.json").read_text())
        self.assertEqual(len(rows), 4)
        self.assertEqual((rows["04__bad"]["pred"], rows["04__bad"]["score"], rows["04__bad"]["status"]), (1, 0.8, "ok"))
        self.assertEqual(rows["04__good"]["pred"], 0)
        self.assertAlmostEqual(rows["04__good"]["score"], 0.3)
        self.assertEqual((rows["10__bad"]["pred"], rows["10__bad"]["status"]), (None, "invalid"))
        # label without confidence: verdict kept, no score
        self.assertEqual((rows["10__good"]["pred"], rows["10__good"]["score"], rows["10__good"]["status"]),
                         (0, None, "ok"))
        for row in rows.values():
            self.assertEqual(set(row) >= {"unit_id", "method", "strategy", "model", "layer", "pred", "score",
                                          "latency_s", "status", "extra"}, True)
            self.assertEqual((row["method"], row["strategy"], row["layer"]), ("qwen3_5_4b", "L1", "layer1"))
        self.assertEqual(meta["n_units"], 4)
        self.assertEqual(len(meta["prompt_hash"]), 64)
        self.assertEqual(meta["concurrency"], 2)

    def test_reasoning_tokens_abort_whole_run(self):
        server = MockServer([(200, chat_payload('{"label": "vulnerable", "confidence": 0.9}',
                                                {"completion_tokens_details": {"reasoning_tokens": 3}}))])
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            units = tmp / "units.jsonl"
            units.write_text("".join(json.dumps(u) + "\n" for u in UNITS))
            try:
                code = run_llm.main(["--model", "qwen", "--strategy", "L1", "--units", str(units), "--set", "dev",
                                     "--keep-l2-examples", "--concurrency", "2", "--warmup-wait", "0",
                                     "--base-url", server.url, "--run-id", "abort", "--out-root", str(tmp / "res"),
                                     "--raw-root", str(tmp / "raw"), "--ledger", str(tmp / "ledger.jsonl")])
            finally:
                server.close()
            out = tmp / "res" / "qwen3_5_4b" / "layer1"
            rows = [json.loads(line) for line in (out / "abort.jsonl").read_text().splitlines()]
            meta = json.loads((out / "abort.meta.json").read_text())
        self.assertEqual(code, 3)
        self.assertIn("reasoning", meta["aborted"])
        self.assertEqual(len(server.bodies), 1)  # warm-up request aborts before the burst
        self.assertEqual({r["status"] for r in rows}, {"error"})
        self.assertEqual({r["pred"] for r in rows}, {None})


if __name__ == "__main__":
    unittest.main()
