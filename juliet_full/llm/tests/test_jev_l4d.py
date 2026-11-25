"""run_jev_l4d.py offline (no network, no cost): request building, pruning use, unit derivation, guards.

Covers: the /systemone body for one L4-D question (state and question text unchanged, neutral criteria), the pruned
question sets (= l4d_ft/prune.py prune), the 40-unit pilot sample, gold answers through unit_verdicts reproduce the
layer1-dev truth (oracle), the ledger row of a call, the model-version guard, the budget refusal and the FROZEN
refusal of eval runs.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from unittest import mock

LLM_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LLM_DIR))

import run_jev_l4d as jl  # noqa: E402
from llmlane import clients  # noqa: E402
from llmlane.ledger import Budget, Ledger  # noqa: E402

Q = {"qid": "layer1/u__bad/heap/s00", "unit_id": "u__bad", "qtype": "heap", "site_ids": ["s00"],
     "state": " 1| int main() {}", "question": "Does the call at line 1 allocate heap memory?"}


class FakeClient:
    """JevClient stand-in: returns noul 0.8 with the given model version(s)."""

    model = "jev-latest"

    def __init__(self, versions=("jev-1.14.0",)):
        self.versions = list(versions)
        self.calls = []

    def ask(self, state, question, name="leak", stop=None):
        self.calls.append((state, question, name))
        model = self.versions[min(len(self.calls), len(self.versions)) - 1]
        return clients.CallResult(status="ok", score=0.8, usage={"input_tokens": 400, "output_tokens": 21},
                                  model=model, latency_s=0.5, attempts=[{"attempt": 1}], http_status=200,
                                  raw={"answer": {"noul": 0.8}}, started_utc=1.0, ended_utc=2.0)


class RequestTests(unittest.TestCase):
    def test_request_body(self):
        body = jl.request_body(Q)
        self.assertEqual(body["model"], "jev-latest")
        self.assertEqual(body["state"], Q["state"])
        self.assertEqual(list(body["questions"]), ["answer"])
        spec = body["questions"]["answer"]
        self.assertEqual(spec, {"type": "noul", "instructions": Q["question"],
                                "criteria": {"true": "The answer to the question is Yes.",
                                             "false": "The answer to the question is No."}})

    def test_jev_client_sends_request_body(self):
        sent = {}

        def fake_http(method, url, key, body, timeout, headers=None):
            sent.update(url=url, body=body)
            return 200, {"model": "jev-1.14.0", "usage": {"input_tokens": 300},
                         "answers": {"answer": {"noul": 0.25}}}, {}

        with mock.patch.object(clients, "read_env_key", return_value="k"), \
                mock.patch.object(clients, "http_json", side_effect=fake_http):
            client = clients.JevClient()
            result = client.ask(Q["state"], jl.question_spec(Q), name=jl.QUESTION_NAME)
        self.assertTrue(sent["url"].endswith("/systemone"))
        self.assertEqual(sent["body"], jl.request_body(Q))
        self.assertEqual((result.status, result.score, result.model), ("ok", 0.25, "jev-1.14.0"))
        row = jl.answer_row(dict(Q, qtype="heap"), result, 0.0)
        for key in ("qid", "unit_id", "qtype", "p_yes", "logit_diff", "model", "fold"):
            self.assertIn(key, row)
        self.assertIsNone(row["logit_diff"])


class PruneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dev = jl.pruned_questions("layer1", "dev")

    def test_pruned_questions_are_prune_of_file(self):
        full = [q for q in jl.read_jsonl(jl.L4D_DIR / "build" / "questions_layer1.jsonl") if q["set"] == "dev"]
        self.assertEqual([q["qid"] for q in self.dev], [q["qid"] for q in jl.prune(full)])
        self.assertTrue(all(q["set"] == "dev" for q in self.dev))
        self.assertLess(len(self.dev), len(full))

    def test_pilot_units(self):
        units = jl.pilot_units(self.dev)
        self.assertEqual(len(units), jl.PILOT_N)
        self.assertEqual(units, jl.pilot_units(self.dev))
        self.assertTrue(set(units) <= {q["unit_id"] for q in self.dev})

    def test_gold_answers_reproduce_dev_truth(self):
        dev_units = sorted({q["unit_id"] for q in jl.read_jsonl(jl.L4D_DIR / "build" / "questions_layer1.jsonl")
                            if q["set"] == "dev"})
        truth_of = {u["unit_id"]: u["truth"] for u in jl.read_jsonl(jl.JF / "data/build/layer1.jsonl")}
        by_unit = defaultdict(list)
        for q in self.dev:
            by_unit[q["unit_id"]].append(q)
        p_of = {q["qid"]: float(q["gold"] or 0) for q in self.dev}
        pred = jl.unit_verdicts(dev_units, by_unit, p_of, 0.5)
        self.assertGreaterEqual(jl.macro_f1(pred, [truth_of[u] for u in dev_units]), 0.99)

    def test_unit_without_kept_question_is_zero(self):
        self.assertEqual(jl.unit_verdicts(["nobody"], {}, {}, 0.5), [0])


class AskerTests(unittest.TestCase):
    def make(self, tmp, versions=("jev-1.14.0",), expected=None, cap=1.0):
        ledger = Ledger(Path(tmp, "ledger.jsonl"))
        return jl.Asker(FakeClient(versions), Budget("jev", cap, 0.0, global_cap=3.2), ledger, "t_r1", "layer1",
                        "dev", Path(tmp, "raw.jsonl"), expected), ledger

    def test_call_and_ledger_row(self):
        with tempfile.TemporaryDirectory() as tmp:
            asker, ledger = self.make(tmp)
            bundle = asker.call(Q)
            asker.commit(bundle)
            self.assertEqual(asker.client.calls[0], (Q["state"], jl.question_spec(Q), "answer"))
            self.assertEqual(bundle["row"]["p_yes"], 0.8)
            rec = ledger.records()[0]
            self.assertEqual((rec["provider"], rec["purpose"], rec["strategy"], rec["run_id"], rec["set"],
                              rec["layer"], rec["unit_id"]), ("jev", "jev_l4d", "L4D", "t_r1", "dev", "layer1",
                                                              "u__bad"))
            self.assertAlmostEqual(rec["cost"], 400 * 0.042 / 1e6)
            self.assertAlmostEqual(jl.lane_spent(ledger), 400 * 0.042 / 1e6)

    def test_model_version_change_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            asker, _ = self.make(tmp, versions=("jev-1.14.0", "jev-1.15.0"))
            self.assertIsNotNone(asker.call(Q)["row"])
            self.assertIsNone(asker.call(Q)["row"])
            self.assertIn("model version changed", asker.abort_reason)
            self.assertIsNone(asker.call(Q))

    def test_budget_refusal_aborts(self):
        with tempfile.TemporaryDirectory() as tmp:
            asker, _ = self.make(tmp, cap=1e-9)
            self.assertIsNone(asker.call(Q))
            self.assertIn("run cap", asker.abort_reason)
            self.assertEqual(asker.client.calls, [])

    def test_make_budget_lane_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp, "ledger.jsonl"))
            ledger.append({"kind": "call", "provider": "jev", "purpose": "jev_l4d", "cost": 0.99})
            ledger.append({"kind": "call", "provider": "jev", "cost": 1.0})
            budget = jl.make_budget(ledger, 0.5)
            self.assertAlmostEqual(budget.run_cap, 0.01)
            self.assertEqual(budget.global_cap, 3.2)
            self.assertAlmostEqual(budget.ledger_spent, 1.99)
            ledger.append({"kind": "call", "provider": "jev", "purpose": "jev_l4d", "cost": 0.02})
            with self.assertRaises(jl.BudgetExceeded):
                jl.make_budget(ledger, 0.5)


class FrozenGuardTests(unittest.TestCase):
    def test_eval_refused_without_frozen(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(jl, "FROZEN", Path(tmp, "FROZEN")), \
                mock.patch.object(clients, "JevClient", side_effect=AssertionError("no client may be built")):
            with self.assertRaises(AssertionError) as ctx:
                jl.main(["answer", "--layer", "layer3", "--set", "eval", "--run-id", "x", "--max-cost", "0.01"])
            self.assertIn("refused", str(ctx.exception))

    def test_eval_refused_on_changed_criteria(self):
        with tempfile.TemporaryDirectory() as tmp:
            frozen = Path(tmp, "FROZEN")
            frozen.write_text(json.dumps({"hashes": jl.current_hashes(), "criteria": {"true": "x", "false": "y"},
                                          "question_name": "answer", "request_template": {}}))
            with mock.patch.object(jl, "FROZEN", frozen), self.assertRaises(AssertionError) as ctx:
                jl.load_frozen_checked()
            self.assertIn("criteria", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
