"""Second-pass verification of positive evidence-prompt predictions.

The package consumes a frozen first-pass run (``evidence_prompt``), keeps the
negative predictions untouched, and asks a fresh model call to refute each
positive claim.  It writes only under ``evidence_verify/``.
"""

__version__ = "0.1.0"

VERIFIER_PROMPT_VERSION = "secvul-verify-prompt-2026-11-13.1"
VERIFIER_STRATEGY = "verify_positive_claim"
ANALYSIS_STATUS = "exploratory_post_hoc_test_seen"
