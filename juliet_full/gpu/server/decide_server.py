"""Forward-only HTTP read-out for Intern-Decision-4B (zero-shot decision model).

POST /decide  {"state": <str|obj>, "question": <str>, "options": [<str>...] | {<value>: <description>},
               optional "type": "choice" (default) | "noul", optional "name": field name (default "answer")}
           -> {"probs": {<value>: p}, "probs_raw": {...}, "decision": <value>, "input_tokens": n,
               "forward_ms": f, "latency_ms_server": t, "model": "Intern-Decision-4B", "temperature": T}
  type "noul" is the model card's binary question: values no, yes; `options` is optional and may describe
  them with no/yes or false/true keys (Jev noul criteria pass through unchanged).
GET  /health  -> {"status": "ok"} once the model is loaded and warmed up.

The prompt compiler, candidate-symbol read-out and calibration are the model card's own
`inference.py` (shipped next to the weights): JSON skeleton with a <decision> placeholder,
logits read at the position before the placeholder, softmax restricted to the option symbols,
then calibrated_p = softmax(log(p) / T) with T = 1.99241824. `probs_raw` is the T = 1 distribution.
Requests are served one at a time (a lock around the GPU forward).
"""
from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import Any, Literal

import torch
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

FIELD_NAME = "answer"


class DecideRequest(BaseModel):
    state: Any
    question: str
    options: list[str] | dict[str, str] | None = None
    type: Literal["choice", "noul"] = "choice"
    name: str = FIELD_NAME


def build_app(checkpoint: Path) -> FastAPI:
    sys.path.insert(0, str(checkpoint))
    import inference  # the model card's inference module

    engine = inference.DecisionEngine(checkpoint=str(checkpoint), temperature=1.0, device="cuda")
    calibration_temperature = inference.DEFAULT_TEMPERATURE
    lock = threading.Lock()

    def decide(req: DecideRequest) -> dict[str, Any]:
        start = time.perf_counter()
        if req.type == "noul":
            if isinstance(req.options, list):
                raise HTTPException(400, "noul options must be an object of no/yes (false/true) descriptions")
            question = {"type": "noul", "instructions": req.question}
            if req.options:
                question["criteria"] = dict(req.options)
        else:
            criteria = dict(req.options) if isinstance(req.options, dict) else {o: o for o in req.options or []}
            if len(criteria) < 2:
                raise HTTPException(400, "need at least two distinct options")
            question = {"type": "choice", "instructions": req.question, "criteria": criteria}
        if not req.name:
            raise HTTPException(400, "name must be nonempty")
        request = {"state": req.state, "questions": {req.name: question}}
        try:
            with lock:
                result = engine.predict(request)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        raw = result["answers"][req.name]["probabilities"]
        probs = inference.scale_probabilities(raw, calibration_temperature)
        return {"probs": probs, "probs_raw": raw, "decision": inference.argmax(probs),
                "input_tokens": result["usage"]["input_tokens"],
                "forward_ms": result["timing"]["inference_ms"],
                "latency_ms_server": round((time.perf_counter() - start) * 1000, 2),
                "model": result["model"], "temperature": calibration_temperature}

    warm = DecideRequest(state="warm-up", question="Is this a warm-up request?", options=["no", "yes"])
    for _ in range(3):
        decide(warm)

    app = FastAPI()

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "model": inference.MODEL_NAME,
                "gpu_mem_allocated_gb": round(torch.cuda.memory_allocated() / 2**30, 2)}

    app.post("/decide")(decide)
    return app


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", type=Path, required=True)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8002)
    args = ap.parse_args()
    uvicorn.run(build_app(args.checkpoint.resolve()), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
