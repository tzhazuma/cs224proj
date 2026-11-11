"""Dynamic CWE-401 (memory leak) evaluation harness.

This package only implements the traditional dynamic arm of the benchmark:
compile real C/C++ programs, execute them under LeakSanitizer and/or Valgrind,
parse the tool evidence, and emit a unified JSONL plus metrics.

Labels are never inferred from function names.  Ground-truth labels come from
the input manifest or from Juliet's preprocessor-controlled build variants;
the prediction comes exclusively from runtime detector evidence.
"""

__version__ = "1.0.0"
SCHEMA_VERSION = "dynamic-cwe401/1.0"
