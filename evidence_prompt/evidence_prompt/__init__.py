"""Evidence-grounded SecVulEval detection prompt.

This package is deliberately separate from ``runner/secvul_runner``: it reuses
the audited HTTP client, cache, dataset loader, and statistics, but defines its
own prompt contract (evidence lines, vulnerability mechanism, counterfactual
repair check) and its own run artifacts.
"""

from __future__ import annotations

__version__ = "1.0.0"

EVIDENCE_STRATEGY = "evidence"
PROMPT_VERSION = "secvul-evidence-prompt-2026-11-12.1"
