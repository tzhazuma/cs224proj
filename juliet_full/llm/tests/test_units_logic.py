"""Unit tests: verdict parsing, ledger/budget math, peak gate (simulated clocks), prompts, L4 facts.

Run: python3 -m unittest discover -s tests -v   (from juliet_full/llm)
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llmlane import l4  # noqa: E402
from llmlane.ledger import Budget, BudgetExceeded, Ledger  # noqa: E402
from llmlane.parse import parse_verdict  # noqa: E402
from llmlane.pricing import (  # noqa: E402
    PeakGate, PeakHours, deepseek_cost_cny, is_deepseek_peak, jev_cost_usd, next_offpeak,
)
from llmlane.prompts import PromptAuditError, PromptSet, render_evidence  # noqa: E402

PST = timezone(timedelta(hours=-8))


def bj(text: str) -> datetime:
    """Beijing wall time -> aware datetime."""
    return datetime.fromisoformat(text).replace(tzinfo=timezone(timedelta(hours=8)))


class ParseVerdictTest(unittest.TestCase):
    def test_plain_json(self):
        v = parse_verdict('{"label": "vulnerable", "confidence": 0.9}')
        self.assertEqual((v.status, v.pred, v.score, v.confidence), ("ok", 1, 0.9, 0.9))

    def test_not_vulnerable_score_is_one_minus_confidence(self):
        v = parse_verdict('{"label":"not_vulnerable","confidence":0.8}')
        self.assertEqual(v.pred, 0)
        self.assertAlmostEqual(v.score, 0.2)

    def test_fenced_and_prose(self):
        self.assertEqual(parse_verdict('```json\n{"label": "vulnerable", "confidence": 1}\n```').pred, 1)
        self.assertEqual(parse_verdict('Verdict: {"label": "not_vulnerable", "confidence": 0.6} done').pred, 0)

    def test_invalid_outputs(self):
        for text in ["", None, "vulnerable", '{"label": "maybe", "confidence": 0.5}', '{"label": 1}',
                     '{"label": "vulnerable", "confidence": 0.9']:
            v = parse_verdict(text)
            self.assertEqual((v.status, v.pred, v.score), ("invalid", None, None), text)

    def test_bad_confidence_keeps_label(self):
        for conf in ['1.7', '"high"', 'null', 'true']:
            v = parse_verdict('{"label": "vulnerable", "confidence": %s}' % conf)
            self.assertEqual((v.status, v.pred, v.score), ("ok", 1, None), conf)
        self.assertEqual(parse_verdict('{"label": "vulnerable", "confidence": "0.7"}').score, 0.7)


class CostAndLedgerTest(unittest.TestCase):
    def test_deepseek_cost_offpeak_and_peak(self):
        usage = {"prompt_tokens": 1220, "prompt_cache_hit_tokens": 768, "prompt_cache_miss_tokens": 452,
                 "completion_tokens": 17}
        off = (768 * 0.02 + 452 * 1.0 + 17 * 4.0) / 1e6
        self.assertAlmostEqual(deepseek_cost_cny(usage, peak=False), off)
        self.assertAlmostEqual(deepseek_cost_cny(usage, peak=True), 2 * off)

    def test_missing_cache_split_counts_as_miss(self):
        self.assertAlmostEqual(deepseek_cost_cny({"prompt_tokens": 500, "completion_tokens": 16}, False),
                               (500 + 64) / 1e6)
        self.assertEqual(deepseek_cost_cny(None, False), 0.0)

    def test_jev_cost(self):
        self.assertAlmostEqual(jev_cost_usd({"input_tokens": 1_000_000, "output_tokens": 9}), 0.042)

    def test_ledger_append_and_spent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "ledger.jsonl")
            ledger.append({"kind": "call", "provider": "deepseek", "cost": 0.25})
            ledger.append({"kind": "call", "provider": "deepseek", "cost": 0.5})
            ledger.append({"kind": "balance", "provider": "deepseek", "cost": 99})
            ledger.append({"kind": "call", "provider": "jev", "cost": 0.01})
            self.assertAlmostEqual(ledger.spent("deepseek"), 0.75)
            self.assertAlmostEqual(ledger.spent("jev"), 0.01)
            self.assertEqual(len((Path(tmp) / "ledger.jsonl").read_text().splitlines()), 4)

    def test_ledger_concurrent_appends(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "l.jsonl")
            threads = [threading.Thread(target=lambda: [ledger.append({"kind": "call", "provider": "deepseek",
                                                                       "cost": 0.001}) for _ in range(50)])
                       for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertAlmostEqual(ledger.spent("deepseek"), 0.4)

    def test_budget_run_cap(self):
        budget = Budget("deepseek", run_cap=0.01, ledger_spent=0.0)
        budget.reserve(0.004)
        budget.settle(0.004, 0.003)
        budget.reserve(0.006)
        with self.assertRaises(BudgetExceeded):
            budget.reserve(0.002)  # 0.003 spent + 0.006 reserved + 0.002 > 0.01
        budget.settle(0.006, 0.001)
        budget.reserve(0.002)
        self.assertAlmostEqual(budget.run_spent, 0.004)

    def test_budget_global_hard_stop(self):
        budget = Budget("deepseek", run_cap=5.0, ledger_spent=9.499)
        self.assertEqual(budget.global_cap, 9.5)
        with self.assertRaises(BudgetExceeded):
            budget.reserve(0.002)
        jev = Budget("jev", run_cap=1.0, ledger_spent=3.9999)
        self.assertEqual((jev.global_cap, jev.currency), (4.0, "USD"))
        with self.assertRaises(BudgetExceeded):
            jev.reserve(0.001)


class PeakGateTest(unittest.TestCase):
    def test_peak_windows_beijing(self):
        self.assertTrue(is_deepseek_peak(bj("2026-11-24T09:00:00")))   # Tue
        self.assertTrue(is_deepseek_peak(bj("2026-11-24T11:59:59")))
        self.assertFalse(is_deepseek_peak(bj("2026-11-24T12:00:00")))
        self.assertFalse(is_deepseek_peak(bj("2026-11-24T13:59:00")))
        self.assertTrue(is_deepseek_peak(bj("2026-11-24T14:00:00")))
        self.assertTrue(is_deepseek_peak(bj("2026-11-24T17:59:00")))
        self.assertFalse(is_deepseek_peak(bj("2026-11-24T18:00:00")))
        self.assertFalse(is_deepseek_peak(bj("2026-11-24T08:59:59")))
        self.assertFalse(is_deepseek_peak(bj("2026-11-28T10:00:00")))  # Sat
        self.assertFalse(is_deepseek_peak(bj("2026-11-29T15:00:00")))  # Sun

    def test_dell_clock_conversion(self):
        # Mon 2026-11-23 17:30 PST = Tue 09:30 Beijing (peak); 16:30 PST = 08:30 Beijing (off-peak)
        self.assertTrue(is_deepseek_peak(datetime(2026, 11, 23, 17, 30, tzinfo=PST)))
        self.assertFalse(is_deepseek_peak(datetime(2026, 11, 23, 16, 30, tzinfo=PST)))
        # Fri 2026-11-27 08:00 PST = Sat 00:00 Beijing: weekend
        self.assertFalse(is_deepseek_peak(datetime(2026, 11, 27, 8, 0, tzinfo=PST)))
        with self.assertRaises(ValueError):
            is_deepseek_peak(datetime(2026, 11, 23, 12, 0))

    def test_next_offpeak(self):
        self.assertEqual(next_offpeak(bj("2026-11-24T10:15:00")), bj("2026-11-24T12:00:00"))
        self.assertEqual(next_offpeak(bj("2026-11-24T15:00:00")), bj("2026-11-24T18:00:00"))
        moment = bj("2026-11-24T02:00:00")
        self.assertEqual(next_offpeak(moment), moment)

    def test_refuse_start_in_peak(self):
        gate = PeakGate(now=lambda: bj("2026-11-24T09:30:00"), sleep=lambda s: None, log=lambda m: None)
        with self.assertRaises(PeakHours):
            gate.check_start()
        PeakGate(now=lambda: bj("2026-11-24T08:30:00"), log=lambda m: None).check_start()

    def test_pause_mid_run_until_offpeak(self):
        clock = {"t": bj("2026-11-24T11:58:00")}

        def sleep(seconds):
            clock["t"] += timedelta(seconds=seconds)

        gate = PeakGate(now=lambda: clock["t"], sleep=sleep, poll_seconds=30, log=lambda m: None)
        waited = gate.wait_offpeak()
        self.assertGreaterEqual(clock["t"], bj("2026-11-24T12:00:00"))
        self.assertAlmostEqual(waited, 120, delta=1)
        self.assertEqual(len(gate.pause_events), 1)
        self.assertEqual(gate.wait_offpeak(), 0.0)

    def test_pause_honours_stop(self):
        stop = threading.Event()
        clock = {"t": bj("2026-11-24T14:00:00"), "n": 0}

        def sleep(seconds):
            clock["t"] += timedelta(seconds=seconds)
            clock["n"] += 1
            if clock["n"] == 3:
                stop.set()

        gate = PeakGate(now=lambda: clock["t"], sleep=sleep, poll_seconds=30, log=lambda m: None)
        gate.wait_offpeak(stop)
        self.assertEqual(clock["n"], 3)


UNIT = {"unit_id": "G__bad", "group_id": "G", "language": "c", "label": "bad",
        "model_text": "int main(void)\n{\n    char *p = malloc(4);\n    return 0;\n}",
        "line_map": [["x.c", 10, 3]]}


class PromptTest(unittest.TestCase):
    def test_l1_messages_shape(self):
        prompts = PromptSet("L1")
        messages, _ = prompts.messages(UNIT)
        self.assertEqual([m["role"] for m in messages], ["system", "user"])
        self.assertIn('"confidence"', messages[0]["content"])
        self.assertTrue(messages[1]["content"].rstrip().endswith("Return only the JSON object."))
        self.assertIn("```c\nint main(void)", messages[1]["content"])
        self.assertEqual(len(prompts.prompt_hash), 64)

    def test_l3_evidence_rendering(self):
        text, info = render_evidence({"unit_id": "G__bad", "status": "ok", "warnings": [
            {"checker": "unix.Malloc", "message": "Potential leak of memory pointed to by 'p'",
             "file": "/abs/x.c", "line": 10}]}, UNIT)
        self.assertIn("line 3: Potential leak", text)
        self.assertEqual(info["n_warnings"], 1)
        static_row = {"unit_id": "G__bad", "warnings": [
            {"checker": "unix.Malloc", "message": "Potential leak", "source_file": "x.c", "source_line": 10,
             "model_text_line": 3, "statement_text": "return 0;"},
            {"checker": "unix.Malloc", "message": "Other", "source_file": "y.c", "source_line": 7,
             "model_text_line": None, "statement_text": None}]}
        text, info = render_evidence(static_row, UNIT)
        self.assertIn("- line 3: Potential leak [unix.Malloc]", text)
        self.assertIn("- Other [unix.Malloc]", text)
        self.assertEqual((info["n_warnings"], info["unmapped_lines"]), (2, 1))
        self.assertEqual(render_evidence({"unit_id": "G__bad", "warnings": []}, UNIT)[0],
                         "The analyzer reported no warnings.")
        self.assertIn("did not complete", render_evidence({"status": "error"}, UNIT)[0])
        messages, info = PromptSet("L3").messages(UNIT, None)
        self.assertIn("no result", messages[1]["content"])

    def test_audit_blocks_label_tokens(self):
        leaky = dict(UNIT, model_text="void bad_sink(char *p) { }")
        with self.assertRaises(PromptAuditError):
            PromptSet("L1").messages(leaky)
        with self.assertRaises(PromptAuditError):
            PromptSet("L3").messages(UNIT, {"status": "ok", "warnings": [{"message": "in goodG2B"}]})

    def test_jev_state_has_no_json_format(self):
        state, _ = PromptSet("L1", "jev").jev_state(UNIT)
        self.assertNotIn("JSON", state)
        self.assertIn("char *p = malloc(4);", state)
        with self.assertRaises(ValueError):
            PromptSet("L4", "jev")


class L4Test(unittest.TestCase):
    def test_parse_facts(self):
        out = "```\nalloc(a1, data, sym_0).\nfree(*data, sym_1).\npass(sym_1, data, data, sym_0)\n" \
              "call(main, sym_0()).\ndead(sym_0, data, free).\nfoo(x).\nalloc(a2, x).\n```"
        parsed = l4.parse_facts(out)
        self.assertEqual(parsed.facts["alloc"], [("a1", "data", "sym_0")])
        self.assertEqual(parsed.facts["free"], [("data", "sym_1")])
        self.assertEqual(parsed.facts["call"], [("main", "sym_0")])
        self.assertEqual(len(parsed.bad_lines), 2)
        self.assertFalse(parsed.strict_ok)
        self.assertTrue(l4.parse_facts("none").strict_ok)

    def _derive(self, text):
        result = l4.run_souffle(l4.parse_facts(text))
        self.assertEqual(result.status, "ok", result.error)
        return result.leaks

    def test_souffle_rules(self):
        self.assertEqual(self._derive("alloc(a1, data, f).\ncall(main, f)."), [("a1", "never_freed")])
        self.assertEqual(self._derive("alloc(a1, data, f).\ncall(main, f).\nfree(data, f)."), [])
        # interprocedural free through a parameter, and through a copy
        self.assertEqual(self._derive("alloc(a1, d, f).\ncall(main, f).\npass(g, p, d, f).\nfree(p, g)."), [])
        self.assertEqual(self._derive("alloc(a1, d, f).\ncall(main, f).\nassign(c, d, f).\nfree(c, f)."), [])
        # free in a dead branch does not count
        self.assertEqual(self._derive("alloc(a1, d, f).\ncall(main, f).\nfree(d, f).\ndead(f, d, free)."),
                         [("a1", "never_freed")])
        # allocation in a function that main never calls is ignored
        self.assertEqual(self._derive("alloc(a1, d, h).\ncall(main, f)."), [])
        # returned pointer freed by caller; global freed elsewhere
        self.assertEqual(self._derive("alloc(a1, r, src).\nret(src, r).\ncall(main, f).\ncall(f, src).\n"
                                      "retval(d, src, f).\nfree(d, f)."), [])
        self.assertEqual(self._derive("global(G).\nalloc(a1, G, f).\ncall(main, f).\ncall(main, k).\n"
                                      "free(G, k)."), [])
        self.assertEqual(self._derive("alloc(a1, d, f).\ncall(main, f).\nrealloc_fail(a1, f).\nfree(d, f)."),
                         [("a1", "realloc_fail")])
        self.assertEqual(self._derive("none"), [])


if __name__ == "__main__":
    unittest.main()
