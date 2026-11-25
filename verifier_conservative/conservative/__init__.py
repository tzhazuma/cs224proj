"""Conservative three-way verification of positive vulnerability claims.

This package is a successor experiment to ``evidence_verify``.  It keeps the
first-pass predictions untouched except for positives that the verifier can
defeat with a concrete, line-grounded guard or counterexample.  The three-way
assessment is ``supported`` / ``unsupported`` / ``insufficient``; only
``unsupported`` with a valid guard or counterexample is allowed to retract.
Verifier schema failures and API errors keep the first-pass prediction.
"""

__version__ = "1.0.0"

PROMPT_VERSION = "secvul-verify-conservative-prompt-2026-11-22.2"
STRATEGY = "verify_positive_claim_three_way"
TASK = "verification_conservative"
PACKAGE = "verifier_conservative"
ANALYSIS_STATUS = "exploratory_post_hoc_test_seen"
ANALYSIS_STATUS_MEANING = (
    "Exploratory and post hoc: the frozen 160-function test split was already used to "
    "evaluate the first pass and the original verifier, so these results do not "
    "independently confirm any detection claim."
)
