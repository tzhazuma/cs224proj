"""LLM lane of juliet_full: API/vLLM clients, prompts, cost ledger, peak gate, L4 facts."""

from pathlib import Path

LLM_DIR = Path(__file__).resolve().parent.parent
JULIET_FULL_DIR = LLM_DIR.parent
PROJECT_ROOT = JULIET_FULL_DIR.parent
PROMPT_DIR = LLM_DIR / "prompts"
ENV_PATH = PROJECT_ROOT / ".env"
