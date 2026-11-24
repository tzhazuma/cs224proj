"""Tests for vulnllmr_prompt (template copy, CWE hint, parser) and run_vulnllmr (fake vLLM server, resume).

    .venv/bin/python -m pytest -q tests/        (or: python3 -m unittest discover -s tests)
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import run_vulnllmr  # noqa: E402
import vulnllmr_prompt as prompt  # noqa: E402

AUTHORS_REPO = Path("/tmp/vulnllmr_repo")  # git clone of ucsb-mlsec/VulnLLM-R @ 5357371a (optional)
TEST_401 = Path.home() / ".cache" / "vllmr" / "test-401.json"
# sha256 of vulscan/utils/sys_prompts.py:78-111 reasoning_user_prompt at 5357371a
TEMPLATE_SHA256 = "20bd58e69cf4ae56459e03b5a42cc8043db9680ab94994114d2331aeeb124e61"


class TemplateTest(unittest.TestCase):
    def test_template_hash(self):
        self.assertEqual(hashlib.sha256(prompt.REASONING_USER_PROMPT.encode()).hexdigest(), TEMPLATE_SHA256)

    @unittest.skipUnless((AUTHORS_REPO / "vulscan/utils/sys_prompts.py").exists(), "authors' repo not cloned")
    def test_identical_to_authors_literals(self):
        ns: dict = {}
        exec(compile((AUTHORS_REPO / "vulscan/utils/sys_prompts.py").read_text(), "sys_prompts", "exec"), ns)
        self.assertEqual(ns["reasoning_user_prompt"], prompt.REASONING_USER_PROMPT)
        self.assertEqual(ns["qwen_sys_prompt"], prompt.QWEN_SYS_PROMPT)
        self.assertEqual(ns["policy"], prompt.POLICY_HEADER)

    @unittest.skipUnless(TEST_401.exists(), "test-401.json not present")
    def test_cwe_list_matches_their_juliet_401_rows(self):
        rows = json.loads(TEST_401.read_text())
        self.assertEqual({tuple(r["CWE_ID"] + r["RELATED_CWE"]) for r in rows},
                         {tuple(prompt.CWE_ID + prompt.RELATED_CWE)})

    def test_policy_block(self):
        info = prompt.cwe_info("CWE401_Memory_Leak__char_calloc_01__bad", "policy")
        lines = info.split("\n")
        self.assertEqual(lines[0], prompt.POLICY_HEADER)
        self.assertEqual(sorted(line.split(":")[0] for line in lines[1:]),
                         ["- CWE-1333", "- CWE-401", "- CWE-404", "- CWE-703"])
        self.assertEqual(prompt.cwe_order("u1"), prompt.cwe_order("u1"))  # deterministic per unit
        orders = {tuple(prompt.cwe_order(f"u{i}")) for i in range(50)}
        self.assertGreater(len(orders), 5)  # actually shuffled across units

    def test_render_none_and_policy(self):
        none = prompt.render_user("int main(){}", "u", "none")
        self.assertIn("```\nint main(){}\n```\n\n\n\n\n\nYou should STRICTLY", none)
        pol = prompt.render_user("int main(){}", "u", "policy")
        self.assertIn("```\n\n\n" + prompt.POLICY_HEADER + "\n- CWE-", pol)
        self.assertTrue(pol.endswith("#judge: no\n#type: N/A\n"))


class ParserTest(unittest.TestCase):
    def check(self, output, finish, pred, judge, vtype, strict):
        v = prompt.verdict(output, finish)
        self.assertEqual((v["pred"], v["judge"], v["pred_type"], v["pred_strict"]), (pred, judge, vtype, strict))

    def test_yes_401(self):
        self.check("<think>\nmalloc never freed.\n</think>\n## Final Answer\n#judge: yes\n#type: CWE-401",
                   "stop", 1, "yes", "CWE-401", 1)

    def test_yes_other_cwe_is_lenient_positive_strict_negative(self):
        self.check("<think>x</think>\n## Final Answer\n#judge: yes\n#type: CWE-404\n", "stop", 1, "yes", "CWE-404", 0)

    def test_no(self):
        self.check("<think>all paths free data</think>\n## Final Answer\n#judge: no\n#type: N/A", "stop",
                   0, "no", "N/A", 0)

    def test_last_final_answer_wins(self):
        out = ("<think>The format is ## Final Answer\n#judge: yes\n#type: CWE-401 ... but data is freed.</think>\n"
               "## Final Answer\n#judge: no\n#type: N/A")
        self.check(out, "stop", 0, "no", "N/A", 0)

    def test_fallback_without_hash_marks(self):
        self.check("## Final Answer\nJudge: Yes\nType: CWE-401", "stop", 1, "yes", "CWE-401", 1)

    def test_two_cwes_not_strict(self):
        self.check("## Final Answer\n#judge: yes\n#type: CWE-401, CWE-404", "stop", 1, "yes", "CWE-401, CWE-404", 0)

    def test_missing_judge_invalid(self):
        self.check("<think>I think the code leaks memory because", "stop", None, "Invalid format", "N/A", None)

    def test_ambiguous_invalid(self):
        self.check("## Final Answer\n#judge: yes/no\n#type: N/A", "stop", None, "Invalid format", "N/A", None)

    def test_truncated_is_invalid_even_if_parseable(self):
        self.check("## Final Answer\n#judge: yes\n#type: CWE-401 and then it keeps", "length",
                   None, "yes", "CWE-401 AND THEN IT KEEPS", None)


class FakeServer(BaseHTTPRequestHandler):
    calls: list[dict] = []
    fail_first: set[str] = set()

    def log_message(self, *args):  # silence
        pass

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/v1/models":
            self._send(200, {"data": [{"id": "vulnllm-r-7b", "root": "/fake", "max_model_len": 12288}]})
        else:
            self._send(200, {}) if self.path != "/metrics" else self._metrics()

    def _metrics(self):
        data = b'vllm:num_requests_running{model_name="vulnllm-r-7b"} 0.0\n'
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        user = body["messages"][1]["content"]
        FakeServer.calls.append(body)
        key = "bad" if "BAD_UNIT" in user else "good"
        if key in FakeServer.fail_first:
            FakeServer.fail_first.discard(key)
            self._send(503, {"error": "busy"})
            return
        text = ("<think>leak</think>\n## Final Answer\n#judge: yes\n#type: CWE-401" if key == "bad"
                else "<think>freed</think>\n## Final Answer\n#judge: no\n#type: N/A")
        self._send(200, {"model": body["model"], "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 500, "completion_tokens": 40}})


class RunnerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        units = [{"unit_id": f"G{i}__{lab}", "group_id": f"G{i}", "set": "dev", "language": "c",
                  "model_text": f"// {'BAD_UNIT' if lab == 'bad' else 'GOOD_UNIT'} {i}"}
                 for i in range(3) for lab in ("bad", "good")]
        self.units = self.tmp / "layer1.jsonl"
        self.units.write_text("".join(json.dumps(u) + "\n" for u in units))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeServer)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}/v1"
        FakeServer.calls = []

    def tearDown(self):
        self.server.shutdown()

    def run_cli(self, *extra):
        return run_vulnllmr.main(["--layer", "layer1", "--set", "dev", "--units-file", str(self.units),
                                  "--base-url", self.base, "--out-root", str(self.tmp / "results"),
                                  "--raw-root", str(self.tmp / "raw"), "--concurrency", "4", *extra])

    def test_bulk_run_retry_and_resume(self):
        FakeServer.fail_first = {"bad"}
        rc = self.run_cli("--limit", "4")
        self.assertEqual(rc, 0)
        pred = self.tmp / "results" / "vulnllm_r_7b" / "layer1" / "dev_policy_r1.jsonl"
        rows = [json.loads(line) for line in pred.read_text().splitlines()]
        self.assertEqual([r["unit_id"] for r in rows], ["G0__bad", "G0__good", "G1__bad", "G1__good"])
        self.assertEqual([r["pred"] for r in rows], [1, 0, 1, 0])
        self.assertTrue(all(r["status"] == "ok" and r["method"] == "vulnllm_r_7b" for r in rows))
        self.assertEqual(sum(r["extra"]["attempts"] for r in rows), 5)  # one 503 retried
        self.assertLessEqual(len(rows[0]["extra"]["output_tail"]), 300)
        sent = FakeServer.calls[0]
        self.assertEqual((sent["temperature"], sent["max_tokens"], sent["seed"], sent["repetition_penalty"]),
                         (0.0, 8192, 42, 1.0))
        self.assertEqual(sent["messages"][0]["content"], prompt.QWEN_SYS_PROMPT)
        meta = json.loads(pred.with_suffix(".meta.json").read_text())
        self.assertEqual(meta["prompt_sha256"], prompt.prompt_sha256("policy"))
        self.assertEqual(meta["usage_totals"]["completion_tokens"], 160)
        self.assertEqual(meta["yes_type_counts"], {"CWE-401": 2})
        # resume: full set, only the 2 missing units are requested
        n_calls = len(FakeServer.calls)
        self.assertEqual(self.run_cli(), 0)
        self.assertEqual(len(FakeServer.calls) - n_calls, 2)
        rows = [json.loads(line) for line in pred.read_text().splitlines()]
        self.assertEqual(len(rows), 6)

    def test_nohint_run_id_and_prompt(self):
        FakeServer.fail_first = set()
        self.assertEqual(self.run_cli("--cwe-hint", "none", "--limit", "2"), 0)
        pred = self.tmp / "results" / "vulnllm_r_7b" / "layer1" / "dev_nohint_r1.jsonl"
        self.assertTrue(pred.exists())
        self.assertNotIn(prompt.POLICY_HEADER, FakeServer.calls[0]["messages"][1]["content"])

    def test_resume_refuses_changed_config(self):
        FakeServer.fail_first = set()
        self.assertEqual(self.run_cli("--limit", "1"), 0)
        with self.assertRaises(SystemExit):
            self.run_cli("--limit", "1", "--max-tokens", "100")


if __name__ == "__main__":
    unittest.main()
