"""Configuration for the line/branch coverage audit of the frozen Juliet test 140.

The coverage build uses GCC's gcov instrumentation on top of the *same*
ASan/LSan flags as ``dynamic_enhanced``.  Keeping the compiler and the
sanitizer policy identical to the archived run is deliberate: it makes the
coverage execution and the archived leak verdicts directly comparable, and it
avoids the clang/compiler-rt interaction in which ``--wrap=realloc`` plus
LeakSanitizer deadlocks at exit (observed while selecting the toolchain).

Nothing in this package reads a model, an API key or the network.
"""

from __future__ import annotations

from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent                       # dynamic_coverage/
PROJECT = ROOT.parent                       # cs224proj/
DYNE_ROOT = PROJECT / "dynamic_enhanced"    # read-only reuse of units/probe/parse
JULIET = PROJECT / "juliet"
SUBSET = JULIET / "subset_units.jsonl"
JULIET_FREEZE = JULIET / "FREEZE.json"
RAW = JULIET / "raw"
SUPPORT = RAW / "testcasesupport"

RUNS = ROOT / "runs"
DEFAULT_RUN_ID = "test140_coverage_v1"

# The archived run whose verdicts are linked to the coverage evidence.
ARCHIVED_RUN = PROJECT / "dynamic_enhanced/runs/test140_enhanced_v3"
ARCHIVED_UNITS = ARCHIVED_RUN / "results_units.jsonl"
ARCHIVED_RAW = ARCHIVED_RUN / "results_raw.jsonl"
ARCHIVED_METRICS = ARCHIVED_RUN / "metrics.json"

MODES = ("default", "realloc_fail", "nogobal")
MODE_PRIORITY = ("default", "realloc_fail", "nogobal")

MODE_DESCRIPTION = {
    "default": (
        "Original ASan/LSan path: standard root set, stacks and registers are "
        "not roots.  This is the archived dynamic baseline."
    ),
    "realloc_fail": (
        "Enhanced fault path: linked with --wrap=realloc; the first realloc() "
        "that receives a non-NULL pointer is forced to return NULL, reaching "
        "the allocation-failure branch."
    ),
    "nogobal": (
        "Enhanced root-set path: same binary as default but LSan runs with "
        "use_globals=0, so a block held only by a global pointer is reported."
    ),
}

ASAN_OPTIONS = "detect_leaks=1:abort_on_error=0:exitcode=23"
LSAN_OPTIONS_BASE = "exitcode=23:use_stacks=0:use_registers=0"
LSAN_OPTIONS_NOGLOBAL = LSAN_OPTIONS_BASE + ":use_globals=0"

COMPILE_TIMEOUT = 180
RUN_TIMEOUT = 30
SUPPORT_SOURCES = ("io.c", "std_thread.c")

# Coverage tiers are exact, not thresholded:
#   branch_complete  every executable line hit and every recorded branch taken
#   line_complete    every executable line hit, at least one branch not taken
#   partial          some executable line in the unit's own files never ran
#   not_executed     no executable line in the unit's own files ran
#   no_coverage      gcov produced no line record for the unit's own files
#   coverage_error   gcov failed or .gcda was not written
TIERS = ("branch_complete", "line_complete", "partial", "not_executed", "no_coverage", "coverage_error")
