"""Self-test with synthetic controls for all three modes.

These programs are not Juliet units and their results are never mixed into the
experiment.  They prove the direction of each mechanism: the realloc wrapper
must turn a latent realloc leak into an observed one, the global-root switch
must expose a global-only leak, and neither mechanism may fire on the correct
implementation.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from . import config
from .build import injection_object
from .execute import run_binary
from .parse import classify, summarize_run
from .units import sha256_file

CONTROLS = {
    "plain_leak": {
        "source": """#include <stdlib.h>
int main(void) { char *p = malloc(64); p[0] = 1; return 0; }
""",
        "expect": {"default": "leak", "nogobal": "leak", "realloc_fail": "not_applicable"},
    },
    "plain_clean": {
        "source": """#include <stdlib.h>
int main(void) { char *p = malloc(64); p[0] = 1; free(p); return 0; }
""",
        "expect": {"default": "clean", "nogobal": "clean", "realloc_fail": "not_applicable"},
    },
    "latent_realloc_bad": {
        "source": """#include <stdlib.h>
int main(void) {
    char *p = malloc(64);
    p[0] = 1;
    p = realloc(p, 4096);
    if (p != NULL) { p[0] = 2; free(p); }
    return 0;
}
""",
        "expect": {"default": "clean", "nogobal": "clean", "realloc_fail": "leak"},
    },
    "latent_realloc_good": {
        "source": """#include <stdlib.h>
int main(void) {
    char *p = malloc(64);
    p[0] = 1;
    char *tmp = realloc(p, 4096);
    if (tmp != NULL) { p = tmp; p[0] = 2; }
    free(p);
    return 0;
}
""",
        "expect": {"default": "clean", "nogobal": "clean", "realloc_fail": "clean"},
    },
    "global_leak": {
        "source": """#include <stdlib.h>
static char *g;
int main(void) { g = malloc(64); g[0] = 1; return 0; }
""",
        "expect": {"default": "clean", "nogobal": "leak", "realloc_fail": "not_applicable"},
    },
    "global_clean": {
        "source": """#include <stdlib.h>
static char *g;
int main(void) { g = malloc(64); g[0] = 1; free(g); return 0; }
""",
        "expect": {"default": "clean", "nogobal": "clean", "realloc_fail": "not_applicable"},
    },
}


class FakeUnit:
    def __init__(self, source: Path, group_id: str = "control"):
        self.sources = (source,)
        self.source_names = frozenset({source.name})
        self.source_paths = frozenset({str(source.resolve())})
        self.group_id = group_id


def _compile(source: Path, exe: Path, wrap: bool, work: Path) -> dict:
    cmd = ["gcc", "-std=gnu11", "-O0", "-g", "-fsanitize=address",
           "-fno-omit-frame-pointer", "-w", str(source), "-o", str(exe)]
    if wrap:
        injection = injection_object(work)
        cmd.extend([str(injection), "-Wl,--wrap=realloc"])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=config.COMPILE_TIMEOUT)
    return {"ok": proc.returncode == 0, "stderr": proc.stderr[-2000:], "command": cmd}


def run_selftest() -> dict:
    results = []
    with tempfile.TemporaryDirectory(prefix="dynenh_selftest_") as tmp:
        work = Path(tmp)
        for name, control in CONTROLS.items():
            case = work / name
            case.mkdir()
            source = case / "control.c"
            source.write_text(control["source"], encoding="utf-8")
            plain = _compile(source, case / "plain", wrap=False, work=work)
            wrap = _compile(source, case / "wrap", wrap=True, work=work)
            unit = FakeUnit(source)
            observed = {}
            for mode, exe in (
                ("default", case / "plain"),
                ("nogobal", case / "plain"),
                ("realloc_fail", case / "wrap"),
            ):
                if not (plain["ok"] and (wrap["ok"] if mode == "realloc_fail" else True)):
                    observed[mode] = {"decision": "compile_error", "attributed": False}
                    continue
                run = run_binary(exe, mode, case / f"run_{mode}")
                summary = summarize_run(run.stderr, unit)
                observed[mode] = {
                    "decision": "leak" if summary["leak_attributed"] else "clean",
                    "raw_leak": summary["leak_raw"],
                    "attributed": summary["leak_attributed"],
                    "injected": summary["injection"]["injected"],
                    "failure_class": classify(summary, run.timed_out, run.returncode),
                    "wall_ms": run.wall_ms,
                }
            checks = {}
            for mode, expected in control["expect"].items():
                if expected == "not_applicable":
                    checks[mode] = not observed[mode].get("injected")
                else:
                    checks[mode] = observed[mode]["decision"] == expected
            results.append(
                {
                    "control": name,
                    "compiled": plain["ok"] and wrap["ok"],
                    "observed": observed,
                    "expected": control["expect"],
                    "checks": checks,
                    "pass": bool(plain["ok"] and wrap["ok"] and all(checks.values())),
                }
            )
    passed = sum(1 for item in results if item["pass"])
    report = {
        "schema": "dynamic-enhanced-selftest-v1",
        "controls": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
        "status": "PASS" if passed == len(results) else "FAIL",
    }
    out = config.ROOT / "selftest"
    out.mkdir(exist_ok=True)
    path = out / "selftest.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    report["path"] = str(path.relative_to(config.PROJECT))
    report["sha256"] = sha256_file(path)
    return report
