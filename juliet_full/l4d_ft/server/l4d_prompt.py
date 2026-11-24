"""Prompt rendering of one L4-D fact question (shared by dell rendering, training, prediction and the :8004 endpoint).

text = Qwen chat template (add_generation_prompt=True, enable_thinking=False) applied to
  system = SYSTEM
  user   = USER_TEMPLATE.format(state=<question row "state">, question=<question row "question">)
The state (numbered model_text, exec_* questions already masked by l4d-data) and the question text come verbatim
from l4d/build/questions_<layer>.jsonl. TEMPLATE_SHA256 covers SYSTEM + USER_TEMPLATE; the chat template is hashed
separately (chat_template_sha256).
No torch import: dell renders with the decision_ft CPU venv (transformers + tokenizers only).
"""

from __future__ import annotations

import hashlib
import json

SYSTEM = ("You are a precise C/C++ program analyst. You are shown a numbered code unit and one question about it. "
          "Answer Yes or No.")
USER_TEMPLATE = "Code:\n```\n{state}\n```\n\nQuestion: {question}\nAnswer Yes or No."
TEMPLATE_SHA256 = hashlib.sha256(json.dumps({"system": SYSTEM, "user": USER_TEMPLATE}, sort_keys=True)
                                 .encode("utf-8")).hexdigest()


def render(tokenizer, state: str, question: str) -> str:
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": USER_TEMPLATE.format(state=state, question=question)}]
    return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
