"""LineVul zero-shot inference (public Big-Vul checkpoint MickyMike/LineVul, no fine-tuning).

Follows the LineVul repo (awsm-research/LineVul, linevul_model.py / linevul_main.py):
- encoder: RoBERTa (CodeBERT architecture), tokenizer microsoft/codebert-base;
- input: tokenizer.tokenize(code)[:510] wrapped as <s> ... </s> (block_size 512, attention mask = ids != pad);
- head: RobertaClassificationHead on the <s> vector: dropout, dense 768->768, tanh, dropout, out_proj 768->2;
- prob = softmax(logits); pred = 1 (vulnerable) when prob[1] > 0.5.
The HF checkpoint stores the repo's `Model` wrapper with a plain RobertaModel as `encoder.*` (its pooler
is unused: the head reads the <s> vector of the last hidden states) and the head as `classifier.*`. Padding to 512 is skipped (batch size 1); with the pad attention mask this is the
same computation.

One unit at a time (concurrency 1); latency_s is the per-unit wall time on the host that runs the
script (tokenize + forward). Writes <out_root>/<method>/<layer>/<run_id>.jsonl and .meta.json
(contract juliet_full/README.md section 4).
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import socket
import time
from pathlib import Path

import torch
import transformers
from torch import nn
from transformers import RobertaConfig, RobertaModel, RobertaTokenizer

BLOCK_SIZE = 512


class RobertaClassificationHead(nn.Module):
    """Same layout as LineVul's head (linevul_model.py)."""

    def __init__(self, config: RobertaConfig):
        super().__init__()
        self.dense = nn.Linear(config.hidden_size, config.hidden_size)
        self.dropout = nn.Dropout(config.hidden_dropout_prob)
        self.out_proj = nn.Linear(config.hidden_size, 2)

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        x = features[:, 0, :]
        x = self.dropout(x)
        x = torch.tanh(self.dense(x))
        x = self.dropout(x)
        return self.out_proj(x)


class LineVul(nn.Module):
    def __init__(self, checkpoint_dir: Path):
        super().__init__()
        config = RobertaConfig.from_pretrained(checkpoint_dir)
        self.roberta = RobertaModel(config, add_pooling_layer=True)
        self.classifier = RobertaClassificationHead(config)
        state = torch.load(checkpoint_dir / "pytorch_model.bin", map_location="cpu", weights_only=True)
        enc = {k[len("encoder."):]: v for k, v in state.items() if k.startswith("encoder.")}
        head = {k[len("classifier."):]: v for k, v in state.items() if k.startswith("classifier.")}
        enc.pop("embeddings.position_ids", None)
        self.roberta.load_state_dict(enc, strict=True)
        self.classifier.load_state_dict(head, strict=True)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        hidden = self.roberta(input_ids, attention_mask=input_ids.ne(1))[0]
        return torch.softmax(self.classifier(hidden), dim=-1)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--units", type=Path, required=True, help="jsonl with unit_id, model_text, set")
    ap.add_argument("--set", default="all", help="dev | eval | all")
    ap.add_argument("--layer", default="layer1")
    ap.add_argument("--method", required=True, choices=["linevul_cpu", "linevul_gpu"])
    ap.add_argument("--checkpoint", type=Path, required=True, help="MickyMike/LineVul dir")
    ap.add_argument("--tokenizer", type=Path, required=True, help="microsoft/codebert-base dir")
    ap.add_argument("--out-root", type=Path, required=True)
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--subset", default=None, help="group subset name in data/build/subsets.json, e.g. latency300")
    ap.add_argument("--threads", type=int, default=None, help="torch CPU threads (default: torch default)")
    args = ap.parse_args()

    device = torch.device("cuda" if args.method == "linevul_gpu" else "cpu")
    if device.type == "cuda" and not torch.cuda.is_available():
        raise SystemExit("linevul_gpu needs CUDA")
    if args.threads:
        torch.set_num_threads(args.threads)

    units = [json.loads(line) for line in args.units.open()]
    if args.set != "all":
        units = [u for u in units if u.get("set") == args.set]
    if args.subset:
        subsets = Path(__file__).resolve().parents[1] / "data/build/subsets.json"
        groups = set(json.loads(subsets.read_text())[args.subset])
        units = [u for u in units if u["group_id"] in groups]
    if args.limit:
        units = units[: args.limit]
    run_id = args.run_id or f"{args.set}_{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}"
    out_dir = args.out_root / args.method / args.layer
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{run_id}.jsonl"

    meta = {"method": args.method, "layer": args.layer, "run_id": run_id, "units_file": str(args.units),
            "units_sha256": sha256(args.units), "set": args.set, "subset": args.subset, "n_units": len(units),
            "checkpoint": "MickyMike/LineVul", "checkpoint_sha256": sha256(args.checkpoint / "pytorch_model.bin"),
            "tokenizer": "microsoft/codebert-base", "block_size": BLOCK_SIZE, "threshold": 0.5,
            "torch": torch.__version__, "transformers": transformers.__version__, "python": platform.python_version(),
            "device": str(device), "gpu": torch.cuda.get_device_name(0) if device.type == "cuda" else None,
            "torch_threads": torch.get_num_threads(), "host": socket.gethostname(), "concurrency": 1,
            "latency_note": "per-unit wall time (tokenize+forward) on the host running the script; batch size 1",
            "start_utc": utcnow(), "loadavg_start": os.getloadavg()}

    tokenizer = RobertaTokenizer.from_pretrained(args.tokenizer)
    t0 = time.perf_counter()
    model = LineVul(args.checkpoint).to(device).eval()
    meta["load_s"] = round(time.perf_counter() - t0, 3)

    def run_one(code: str) -> tuple[float, int]:
        tokens = tokenizer.tokenize(code)
        ids = tokenizer.convert_tokens_to_ids([tokenizer.cls_token] + tokens[: BLOCK_SIZE - 2] + [tokenizer.sep_token])
        prob = model(torch.tensor([ids], device=device))[0, 1].item()
        return prob, len(tokens) + 2

    with torch.inference_mode():
        for _ in range(3):  # warm-up, not recorded
            run_one("int main(void) { return 0; }")
        n_trunc = 0
        with out_path.open("w") as out:
            for u in units:
                start = time.perf_counter()
                status, pred, score, n_tok = "ok", None, None, None
                try:
                    score, n_tok = run_one(u["model_text"])  # .item() synchronises the GPU
                    pred = int(score > 0.5)
                except Exception as exc:  # recorded per unit, counted as wrong by the scorer
                    status = "error"
                    print(f"{u['unit_id']}: {exc!r}")
                latency = time.perf_counter() - start
                truncated = n_tok is not None and n_tok > BLOCK_SIZE
                n_trunc += truncated
                out.write(json.dumps({"unit_id": u["unit_id"], "method": args.method, "strategy": None,
                                      "model": "MickyMike/LineVul", "layer": args.layer, "pred": pred,
                                      "score": score, "latency_s": round(latency, 5), "status": status,
                                      "extra": {"n_tokens": n_tok, "truncated": truncated}}) + "\n")
    meta.update({"end_utc": utcnow(), "loadavg_end": os.getloadavg(), "n_truncated": n_trunc})
    (out_dir / f"{run_id}.meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(f"wrote {out_path} ({len(units)} units, {n_trunc} truncated)")


if __name__ == "__main__":
    main()
