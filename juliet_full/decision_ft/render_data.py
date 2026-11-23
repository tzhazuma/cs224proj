"""Render the decision_ft inputs (README "Data") on dell.

For strategy L1 / L3 and fold k in {0,1,2} writes data/<strategy>/fold<k>/{train,dev,pred}.jsonl:
  train = eval units with fold != k, dev = all dev units, pred = eval units with fold == k.
Each row: unit metadata, `text` = Qwen chat template applied to
  system = llm/prompts/task.txt, user = PromptSet(strategy).user_body(unit, evidence) + "\\n\\n" + QUESTION
with add_generation_prompt=True, enable_thinking=False, and `n_tokens` of that text.
data/manifest.json records the input hashes (units, evidence, prompt files, chat template) and counts.

Run: PYTHONPYCACHEPREFIX=/tmp/dft-pycache .venv/bin/python render_data.py --strategy L1 [--strategy L3]
     [--dev-only]   (pipeline tests before the data freeze: only data/<strategy>/dev_only/dev.jsonl)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
JULIET_FULL = HERE.parent
sys.path.insert(0, str(JULIET_FULL / "llm"))
from llmlane.prompts import PromptAuditError, PromptSet, audit, read_prompt, render_evidence, sha256_text  # noqa: E402
from juliet_llm.cleaning import PROMPT_FORBIDDEN_PATTERNS, scan  # noqa: E402  (path set by llmlane.prompts)
from llmlane.units import file_sha256, load_evidence  # noqa: E402

UNITS_PATH = JULIET_FULL / "data" / "build" / "layer1.jsonl"
SHA256SUMS_PATH = JULIET_FULL / "data" / "build" / "SHA256SUMS"
EVIDENCE_PATH = JULIET_FULL / "static" / "results" / "clang_sa" / "layer1" / "evidence.jsonl"
MODEL_DIR = Path("/home/barton/tools/cs224/models/Qwen3.5-4B")
OUT_DIR = HERE / "data"
QUESTION = "Does the executed code unit leak heap memory? Answer Yes or No."
META_KEYS = ("unit_id", "group_id", "family", "variant", "flow_category", "mechanism", "language",
             "set", "fold", "label", "truth", "good_kind")


def frozen_units_sha() -> str:
    for line in SHA256SUMS_PATH.read_text().splitlines():
        digest, name = line.split()
        if name == UNITS_PATH.name:
            return digest
    raise SystemExit("layer1.jsonl missing from SHA256SUMS")


def render(strategy: str, units: list[dict], evidence: dict | None, tokenizer) -> list[dict]:
    prompts = PromptSet(strategy)
    system = read_prompt("task.txt")
    rows = []
    for unit in units:
        record = evidence.get(unit["unit_id"]) if evidence is not None else None
        body, info = prompts.user_body(unit, record)
        user = body + "\n\n" + QUESTION
        if evidence is None:
            audit(system + "\n" + user, unit["unit_id"], unit["group_id"])
        else:
            # Clang SA itself says "Potential memory leak" (28 units); that is evidence, not a label token,
            # so the evidence block is audited without the memory_leak pattern, everything else with it.
            evidence_text, _ = render_evidence(record, unit)
            audit(system + "\n" + user.replace(evidence_text, ""), unit["unit_id"], unit["group_id"])
            hits = {k: v for k, v in scan(evidence_text, PROMPT_FORBIDDEN_PATTERNS).items() if v}
            if hits or unit["unit_id"] in evidence_text or unit["group_id"] in evidence_text:
                raise PromptAuditError(f"forbidden tokens in evidence of {unit['unit_id']}: {hits}")
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True,
                                             enable_thinking=False)
        n_tokens = len(tokenizer(text, add_special_tokens=False)["input_ids"])
        rows.append({**{k: unit[k] for k in META_KEYS}, "strategy": strategy, "text": text,
                     "n_tokens": n_tokens, "evidence_info": info or None})
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def check_groups(rows: list[dict]) -> None:
    by_group: dict[str, list[int]] = {}
    for row in rows:
        by_group.setdefault(row["group_id"], []).append(row["truth"])
    bad = [g for g, t in by_group.items() if sorted(t) != [0, 1]]
    if bad:
        raise SystemExit(f"groups without exactly one bad + one good unit: {bad[:5]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strategy", action="append", choices=("L1", "L3"), required=True)
    parser.add_argument("--dev-only", action="store_true")
    args = parser.parse_args()

    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    yes, no = (tokenizer.encode(w, add_special_tokens=False) for w in ("Yes", "No"))
    if len(yes) != 1 or len(no) != 1:
        raise SystemExit(f"Yes/No are not single tokens: {yes} {no}")

    units_sha = file_sha256(UNITS_PATH)
    frozen = SHA256SUMS_PATH.exists()
    if not args.dev_only:
        if not frozen or units_sha != frozen_units_sha():
            raise SystemExit("layer1.jsonl is not frozen or does not match SHA256SUMS")
    units = [json.loads(line) for line in UNITS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    if args.dev_only:
        units = [u for u in units if u["set"] == "dev"]

    manifest_path = OUT_DIR / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    for strategy in args.strategy:
        evidence = None
        if strategy == "L3":
            evidence = load_evidence(EVIDENCE_PATH)
            missing = {u["unit_id"] for u in units} - set(evidence)
            if missing:
                raise SystemExit(f"L3: {len(missing)} units have no Clang SA evidence record")
        rows = render(strategy, units, evidence, tokenizer)
        check_groups(rows)
        prompts = PromptSet(strategy)
        user_file = "user_L3.txt" if strategy == "L3" else "user_L1.txt"
        entry = {
            "units_file": str(UNITS_PATH), "units_sha256": units_sha, "units_frozen": frozen,
            "evidence_file": str(EVIDENCE_PATH) if evidence is not None else None,
            "evidence_sha256": file_sha256(EVIDENCE_PATH) if evidence is not None else None,
            "prompt_files": {"task.txt": prompts.files["task.txt"], user_file: prompts.files[user_file]},
            "question": QUESTION, "question_sha256": sha256_text(QUESTION),
            "chat_template_sha256": sha256_text(tokenizer.chat_template),
            "chat_template_kwargs": {"add_generation_prompt": True, "enable_thinking": False},
            "tokenizer_dir": str(MODEL_DIR), "yes_token_id": yes[0], "no_token_id": no[0],
            "dev_only": args.dev_only, "files": {},
        }
        jobs = {"dev_only": None} if args.dev_only else {f"fold{k}": k for k in (0, 1, 2)}
        for job, fold in jobs.items():
            splits = {"dev": [r for r in rows if r["set"] == "dev"]}
            if fold is not None:
                splits["train"] = [r for r in rows if r["set"] == "eval" and r["fold"] != fold]
                splits["pred"] = [r for r in rows if r["set"] == "eval" and r["fold"] == fold]
            for split, split_rows in splits.items():
                path = OUT_DIR / strategy / job / f"{split}.jsonl"
                write_jsonl(path, split_rows)
                lengths = [r["n_tokens"] for r in split_rows]
                entry["files"][f"{strategy}/{job}/{split}.jsonl"] = {
                    "n_units": len(split_rows), "n_groups": len({r["group_id"] for r in split_rows}),
                    "tokens_mean": round(sum(lengths) / len(lengths), 1), "tokens_max": max(lengths),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        manifest[strategy] = entry
        print(strategy, json.dumps(entry["files"], indent=1))
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
