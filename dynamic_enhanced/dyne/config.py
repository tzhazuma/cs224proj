# Configuration for the enhanced dynamic analysis of Juliet CWE-401.
#
# Everything in this file is evaluation-side. The code under test is the raw
# frozen Juliet source; no model-facing artefact and no label is used when
# compiling or running a unit.

from __future__ import annotations

from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent                      # dynamic_enhanced/
PROJECT = ROOT.parent                      # cs224proj/
JULIET = PROJECT / "juliet"
SUBSET = JULIET / "subset_units.jsonl"
JULIET_FREEZE = JULIET / "FREEZE.json"
RAW = JULIET / "raw"
SUPPORT = RAW / "testcasesupport"
CWE_DIR = RAW / "testcases" / "CWE401_Memory_Leak"
RUNS = ROOT / "runs"
ASSETS = PACKAGE / "assets"

DEFAULT_RUN_ID = "test140_enhanced_v1"

# The two root-set policies differ only in whether global variables are roots.
# Stacks and registers stay disabled in both so a dangling pointer left in a
# stack slot cannot hide a leak (same policy as juliet_repair).
ASAN_OPTIONS = "detect_leaks=1:abort_on_error=0:exitcode=23"
LSAN_OPTIONS_BASE = "exitcode=23:use_stacks=0:use_registers=0"
LSAN_OPTIONS_NOGLOBAL = LSAN_OPTIONS_BASE + ":use_globals=0"

MODES = ("default", "realloc_fail", "nogobal")

MODE_DESCRIPTION = {
    "default": (
        "ASan/LSan with the standard root set (globals, TLS, libc); stacks and "
        "registers are not roots. Reproduces the archived ASan verdict."
    ),
    "realloc_fail": (
        "Same root set, but the binary is linked with --wrap=realloc and the "
        "first realloc() call that receives a non-NULL pointer is forced to "
        "return NULL. This reaches the error path that the default run never "
        "executes for the malloc_realloc_* family."
    ),
    "nogobal": (
        "Same binary as default, but LSan runs with use_globals=0 so a block "
        "whose only remaining pointer lives in a global variable is reported "
        "instead of being classified as still reachable."
    ),
}

COMPILE_TIMEOUT = 180
RUN_TIMEOUT = 30
SUPPORT_SOURCES = ("io.c", "std_thread.c")
