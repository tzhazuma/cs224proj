from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

from .discover import discover_juliet, load_manifest
from .pipeline import RunOptions, evaluate_case, run_evaluation
from .toolchain import make_toolchain, check_tools


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _manifest_rows(cases: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(case, ensure_ascii=False) for case in cases) + "\n"


def _fixtures(root: Path) -> list[dict[str, Any]]:
    _write(
        root / "leak.c",
        "#include <stdlib.h>\n"
        "int main(void) { char *p = (char *)malloc(128); if (!p) return 2; "
        "p[0] = 'x'; return 0; }\n",
    )
    _write(
        root / "clean.c",
        "#include <stdlib.h>\n"
        "int main(void) { char *p = (char *)malloc(128); if (!p) return 2; "
        "p[0] = 'x'; free(p); return 0; }\n",
    )
    _write(
        root / "conditional.c",
        "#include <stdlib.h>\n"
        "int main(int argc, char **argv) { (void)argv; "
        "if (argc > 1) { char *p = (char *)malloc(64); if (!p) return 2; p[0] = 'x'; } "
        "return 0; }\n",
    )
    _write(
        root / "compile_error.c",
        "int main(void) { this is not valid C; return 0; }\n",
    )
    _write(
        root / "hang.c",
        "int main(void) { for (;;) { } return 0; }\n",
    )
    _write(
        root / "crash.c",
        "int main(void) { int *p = 0; *p = 1; return 0; }\n",
    )
    _write(
        root / "leak.cpp",
        "int main() { int *p = new int[4]; p[0] = 1; return 0; }\n",
    )
    _write(
        root / "juliet/testcasesupport/std_testcase.h",
        "#ifndef STD_TESTCASE_H\n#define STD_TESTCASE_H\n#endif\n",
    )
    _write(
        root / "juliet/testcases/CWE401_Memory_Leak/s01/CWE401_Memory_Leak__selftest_01.c",
        "#include <stdlib.h>\n"
        "#ifndef OMITBAD\n"
        "void bad(void) { char *p = (char *)malloc(64); if (!p) return; p[0] = 'x'; }\n"
        "#endif\n"
        "#ifndef OMITGOOD\n"
        "void good(void) { char *p = (char *)malloc(64); if (!p) return; free(p); }\n"
        "#endif\n"
        "#ifdef INCLUDEMAIN\n"
        "int main(void) {\n"
        "#ifndef OMITGOOD\n"
        "  good();\n"
        "#endif\n"
        "#ifndef OMITBAD\n"
        "  bad();\n"
        "#endif\n"
        "  return 0;\n"
        "}\n"
        "#endif\n",
    )
    rows = [
        {"case_id": "fixture-leak", "source": "leak.c", "expected_label": 1, "timeout_s": 10},
        {"case_id": "fixture-clean", "source": "clean.c", "expected_label": 0, "timeout_s": 10},
        {
            "case_id": "fixture-conditional-clean",
            "source": "conditional.c",
            "expected_label": 0,
            "timeout_s": 10,
        },
        {
            "case_id": "fixture-conditional-leak",
            "source": "conditional.c",
            "expected_label": 1,
            "argv": ["leak"],
            "timeout_s": 10,
        },
        {"case_id": "fixture-compile-error", "source": "compile_error.c", "expected_label": 1},
        {"case_id": "fixture-hang", "source": "hang.c", "expected_label": 1, "timeout_s": 1.5},
        {"case_id": "fixture-crash", "source": "crash.c", "expected_label": 0},
        {"case_id": "fixture-cpp-leak", "source": "leak.cpp", "language": "cpp", "expected_label": 1},
    ]
    return rows


def _find(results: list[dict[str, Any]], case_id: str) -> dict[str, Any]:
    for result in results:
        if result["case_id"] == case_id:
            return result
    raise AssertionError(f"missing result for {case_id}")


def _check(condition: bool, message: str, failures: list[str]) -> None:
    if condition:
        print(f"PASS {message}")
    else:
        print(f"FAIL {message}")
        failures.append(message)


def run_selftest(
    *,
    cc: Optional[str] = None,
    cxx: Optional[str] = None,
    valgrind_bin: Optional[str] = None,
    keep: bool = False,
    jobs: int = 2,
) -> int:
    temp_root = Path(tempfile.mkdtemp(prefix="dynleak-selftest-"))
    print(f"selftest workdir: {temp_root}")
    failures: list[str] = []
    try:
        rows = _fixtures(temp_root)
        manifest_path = temp_root / "cases.jsonl"
        manifest_path.write_text(_manifest_rows(rows), encoding="utf-8")
        cases = load_manifest(manifest_path)
        tc = make_toolchain(cc, cxx, valgrind_bin)
        print(f"toolchain: cc={tc.cc} cxx={tc.cxx} valgrind={tc.valgrind_bin}")

        asan_run = temp_root / "run_asan"
        options = RunOptions(
            detectors=["asan"],
            jobs=jobs,
            compile_timeout_s=30.0,
            valgrind_timeout_factor=2.0,
            rel_root=temp_root,
        )
        asan_result = run_evaluation(
            cases,
            asan_run,
            "selftest-asan",
            tc,
            options,
            input_metadata={"kind": "selftest", "fixtures": len(cases)},
        )
        asan_rows = asan_result["results"]
        _check(len(asan_rows) == len(cases), "all ASan cases produced a result", failures)
        expected = {
            "fixture-leak": ("leak", 1),
            "fixture-clean": ("clean", 0),
            "fixture-conditional-clean": ("clean", 0),
            "fixture-conditional-leak": ("leak", 1),
            "fixture-cpp-leak": ("leak", 1),
            "fixture-hang": ("timeout", None),
            "fixture-crash": ("inconclusive", None),
            "fixture-compile-error": ("build_failed", None),
        }
        for case_id, (outcome, label) in expected.items():
            row = _find(asan_rows, case_id)
            _check(
                row["outcome"] == outcome,
                f"{case_id}: outcome={outcome} (got {row['outcome']})",
                failures,
            )
            _check(
                row["detected_label"] == label,
                f"{case_id}: detected_label={label} (got {row['detected_label']})",
                failures,
            )
        compile_row = _find(asan_rows, "fixture-compile-error")
        _check(
            str(compile_row.get("failure_class") or "").startswith("compile."),
            "compile failure is classified as compile.*",
            failures,
        )
        crash_row = _find(asan_rows, "fixture-crash")
        _check(
            crash_row.get("failure_class") == "runtime.signal:SIGABRT"
            or str(crash_row.get("failure_class") or "").startswith("runtime."),
            "crash receives a runtime failure class",
            failures,
        )
        _check((asan_run / "results.jsonl").is_file(), "results.jsonl written", failures)
        _check((asan_run / "metrics.json").is_file(), "metrics.json written", failures)
        _check((asan_run / "metrics.md").is_file(), "metrics.md written", failures)
        lines = [line for line in (asan_run / "results.jsonl").read_text(encoding="utf-8").splitlines() if line]
        _check(len(lines) == len(cases), "results.jsonl has one row per case", failures)
        metrics = asan_result["metrics"]
        _check(metrics["counts"]["n_cases"] == len(cases), "metrics case count matches", failures)

        juliet_root = temp_root / "juliet" / "testcases" / "CWE401_Memory_Leak"
        juliet_cases = discover_juliet(juliet_root)
        _check(len(juliet_cases) == 2, "Juliet-like discovery yields bad+good variants", failures)
        labels = {case.variant: case.expected_label for case in juliet_cases}
        _check(labels.get("bad") == 1 and labels.get("good") == 0, "Juliet variant labels", failures)
        juliet_run = temp_root / "run_juliet"
        juliet_results = []
        for case in juliet_cases:
            juliet_results.append(
                evaluate_case(
                    case,
                    tc,
                    juliet_run,
                    [],
                    RunOptions(detectors=["asan"], jobs=1, rel_root=temp_root),
                    True,
                    False,
                )
            )
        juliet_outcomes = {row["variant"]: row["outcome"] for row in juliet_results}
        _check(
            juliet_outcomes.get("bad") == "leak" and juliet_outcomes.get("good") == "clean",
            "Juliet preprocessor variants are detected by execution",
            failures,
        )

        if tc.valgrind_bin:
            vg_run = temp_root / "run_valgrind"
            vg_cases = [case for case in cases if case.case_id in {"fixture-leak", "fixture-clean"}]
            vg_result = run_evaluation(
                vg_cases,
                vg_run,
                "selftest-valgrind",
                tc,
                RunOptions(
                    detectors=["valgrind"],
                    jobs=1,
                    compile_timeout_s=30.0,
                    valgrind_timeout_factor=2.0,
                    rel_root=temp_root,
                ),
                input_metadata={"kind": "selftest_valgrind"},
            )
            vg_rows = {row["case_id"]: row for row in vg_result["results"]}
            _check(vg_rows["fixture-leak"]["outcome"] == "leak", "Valgrind detects leak", failures)
            _check(vg_rows["fixture-clean"]["outcome"] == "clean", "Valgrind clean case", failures)
            _check(
                vg_rows["fixture-leak"]["detectors"]["valgrind"]["evidence"]["definite_records"] >= 1,
                "Valgrind XML has definite-leak evidence",
                failures,
            )
        else:
            print("SKIP Valgrind end-to-end selftest (binary not available)")

        if failures:
            print(f"SELFTEST FAILED ({len(failures)} failures)")
            return 1
        print("SELFTEST PASSED")
        return 0
    finally:
        if keep:
            print(f"kept selftest workdir: {temp_root}")
        else:
            shutil.rmtree(temp_root, ignore_errors=True)
