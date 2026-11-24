"""VulnLLM-R-7B prompt rendering and verdict parsing, copied from the authors' code (see README.md section 2).

Sources (github.com/ucsb-mlsec/VulnLLM-R @ 5357371a2271df1048666220415a3bc937af5f9d):
  QWEN_SYS_PROMPT          vulscan/utils/sys_prompts.py:23
  POLICY_HEADER            vulscan/utils/sys_prompts.py:40
  REASONING_USER_PROMPT    vulscan/utils/sys_prompts.py:78-111 (byte-identical copy; checked by tests/test_vulnllmr.py)
  REASONING                vulscan/test/test_utils/utils.py:399-400 (the `"QwQ" or ...` branch is always taken)
  policy bullet format     vulscan/test/test_utils/utils.py:388-393
  CWE descriptions         vulscan/utils/get_cwe_info.py:10-18 over datasets/cwe-details.csv (LFS oid 70d35cc5...)
  CWE list                 CWE_ID + RELATED_CWE of every row of datasets/test/function_level/c/CWE-401.json
  extract_answer           vulscan/test/test_utils/generation_utils.py:133-157
  check_single_cwe / match vulscan/test/test_utils/generation_utils.py:108-112, 473-483
"""
from __future__ import annotations

import hashlib
import json
import random
import re
from typing import Any

QWEN_SYS_PROMPT = ("You are a helpful and harmless assistant. You are Qwen developed by Alibaba. "
                   "You should think step-by-step.")

POLICY_HEADER = "You should only focus on checking and reasoning if the code contains one of the following CWEs:"

REASONING = "You should STRICTLY structure your response as follows:"

reasoning_user_prompt = """\
You are an advanced vulnerability detection model. \
Your task is to check if a specific vulnerability exists in a given piece of code. \
You need to output whether the code is vulnerable and the type of vulnerability present with cwe id (CWE-xx). \
\n
## You are given the following code snippet:
```
{CODE}
```
\n
{CWE_INFO}
\n
{REASONING} 
\n
## Final Answer
#judge: <yes/no>
#type: <vulnerability type>

## Additional Constraint:
- If `#judge: yes`, then `#type:` **must contain exactly one CWE**.
- If `#judge: yes`, the model must output **only the most probable CWE** related to the given code snippet.
{ADDITIONAL_CONSTRAINT}

## Example
- If the code is vulnerable to a CWE-79, you should finally output:
## Final Answer
#judge: yes
#type: CWE-79

- If the code does not contain vulnerabilities related to the given CWE, you should finally output:
## Final Answer
#judge: no
#type: N/A
"""
REASONING_USER_PROMPT = reasoning_user_prompt

# CWE_ID + RELATED_CWE of the authors' Juliet CWE-401 test rows (identical on all 41 rows of
# ~/.cache/vllmr/test-401.json, sha256 12955dc6...abc = LFS oid of datasets/test/function_level/c/CWE-401.json).
CWE_ID = ["CWE-401"]
RELATED_CWE = ["CWE-1333", "CWE-703", "CWE-404"]

# get_cwe_info(n) = Name + ". " + (Extended Description if present else Description), datasets/cwe-details.csv.
CWE_DESCRIPTIONS = {
    "CWE-401": "Missing Release of Memory after Effective Lifetime. This is often triggered by improper handling of "
               "malformed data or unexpectedly interrupted sessions. In some languages, developers are responsible "
               "for tracking memory allocation and releasing the memory. If there are no more pointers or references "
               "to the memory, then it can no longer be tracked and identified for release.",
    "CWE-1333": "Inefficient Regular Expression Complexity. Some regular expression engines have a feature called "
                "backtracking. If the token cannot match, the engine backtracks to a position that may result in a "
                "different token that can match. Backtracking becomes a weakness if all of these conditions are met: "
                "The number of possible backtracking attempts are exponential relative to the length of the input. "
                "The input can fail to match the regular expression. The input can be long enough. Attackers can "
                "create crafted inputs that intentionally cause the regular expression to use excessive backtracking "
                "in a way that causes the CPU consumption to spike.",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions. The product does not properly anticipate or "
               "handle exceptional conditions that rarely occur during normal operation of the product.",
    "CWE-404": "Improper Resource Shutdown or Release. When a resource is created or allocated, the developer is "
               "responsible for properly releasing the resource as well as accounting for all potential paths of "
               "expiration or invalidation, such as a set period of time or revocation.",
}

CWE_HINTS = ("policy", "none")
CWE_ORDER_SEED = 20261123  # fixed per-unit shuffle seed (parent decision): sha256(f"{unit_id}|{CWE_ORDER_SEED}")
TARGET_CWE = "CWE-401"


def cwe_order(unit_id: str) -> list[str]:
    """CWE_ID + RELATED_CWE shuffled as with --random_cwe (random.sample), seeded per unit."""
    digest = hashlib.sha256(f"{unit_id}|{CWE_ORDER_SEED}".encode()).digest()
    rng = random.Random(int.from_bytes(digest[:8], "big"))
    cwes = CWE_ID + RELATED_CWE
    return rng.sample(cwes, len(cwes))


def cwe_info(unit_id: str, cwe_hint: str) -> str:
    """The {CWE_INFO} slot: '' without --use_policy, else POLICY_HEADER + one '\\n- CWE-x: desc' line per CWE."""
    if cwe_hint == "none":
        return ""
    if cwe_hint != "policy":
        raise ValueError(f"unknown cwe_hint {cwe_hint!r}")
    policy = POLICY_HEADER
    for cwe_id in cwe_order(unit_id):
        policy += f"\n- {cwe_id}: {CWE_DESCRIPTIONS[cwe_id]}"
    return policy


def render_user(code: str, unit_id: str, cwe_hint: str) -> str:
    return REASONING_USER_PROMPT.format(CODE=code, CWE_INFO=cwe_info(unit_id, cwe_hint), REASONING=REASONING,
                                        ADDITIONAL_CONSTRAINT="")


def messages(code: str, unit_id: str, cwe_hint: str) -> list[dict[str, str]]:
    return [{"role": "system", "content": QWEN_SYS_PROMPT},
            {"role": "user", "content": render_user(code, unit_id, cwe_hint)}]


def prompt_spec(cwe_hint: str) -> dict[str, Any]:
    """Everything that defines the prompt apart from the code and the per-unit CWE order."""
    return {"system": QWEN_SYS_PROMPT, "user_template": REASONING_USER_PROMPT, "reasoning": REASONING,
            "additional_constraint": "", "cwe_hint": cwe_hint,
            "policy_header": POLICY_HEADER if cwe_hint == "policy" else None,
            "cwe_list": CWE_ID + RELATED_CWE if cwe_hint == "policy" else None,
            "cwe_descriptions": CWE_DESCRIPTIONS if cwe_hint == "policy" else None,
            "cwe_order": f"random.Random(int(sha256(unit_id|{CWE_ORDER_SEED})[:8])).sample" if cwe_hint == "policy"
            else None}


def prompt_sha256(cwe_hint: str) -> str:
    blob = json.dumps(prompt_spec(cwe_hint), sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


def extract_answer(output: str) -> tuple[str, str]:
    """Port of the authors' extract_answer: ('yes'|'no'|'Invalid format', upper-cased type or 'N/A')."""
    output = output.split("## Final Answer")[-1]
    output = output.lower()
    pred_score = ""
    pred_vul_type = ""
    try:
        pred_score = output.split("#judge: ")[1].split("#type: ")[0].strip()
        pred_vul_type = output.split("#type: ")[1].split("\n")[0].strip()
    except IndexError:
        if "judge:" in output and "type:" in output:
            pred_score = output.split("judge:")[1].split("\n")[0].strip()
            pred_vul_type = output.split("type:")[1].split("\n")[0].strip()
        else:
            pred_score = "Invalid format"
    if "yes" in pred_score and "no" not in pred_score:
        pred_score = "yes"
    elif "no" in pred_score and "yes" not in pred_score:
        pred_score = "no"
    else:
        pred_score = "Invalid format"
    pred_vul_type = "N/A" if not pred_vul_type else pred_vul_type.upper()
    return pred_score, pred_vul_type


def type_is_target(pred_vul_type: str) -> bool:
    """Authors' TP condition on a vulnerable sample: exactly one CWE id and substring match with CWE-401."""
    if len(re.findall(r"CWE-\d+", pred_vul_type)) != 1:
        return False
    return TARGET_CWE in pred_vul_type or pred_vul_type in TARGET_CWE


def verdict(output: str, finish_reason: str | None) -> dict[str, Any]:
    """pred 1 iff '#judge: yes' (any type); None if unparseable or truncated at max_tokens (finish_reason 'length')."""
    judge, vul_type = extract_answer(output)
    truncated = finish_reason == "length"
    if truncated or judge == "Invalid format":
        pred = None
    else:
        pred = 1 if judge == "yes" else 0
    pred_strict = None if pred is None else int(pred == 1 and type_is_target(vul_type))
    cwes = re.findall(r"CWE-\d+", vul_type)
    return {"pred": pred, "judge": judge, "pred_type": vul_type, "pred_type_cwes": cwes,
            "pred_strict": pred_strict, "truncated": truncated}
