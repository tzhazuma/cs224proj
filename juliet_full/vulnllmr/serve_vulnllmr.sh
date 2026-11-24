#!/usr/bin/env bash
# vLLM OpenAI server for VulnLLM-R-7B on 184-toast, port 8005.  Copy to ~/disk4/cs224/vulnllmr/ and run there:
#   serve_vulnllmr.sh start <gpus>   e.g. start 1  (one RTX 3090)  or  start 0,1  (data parallel, 2 engines, 1 port)
#   serve_vulnllmr.sh stop | health | status
# Model ~/disk4/cs224/models/VulnLLM-R-7B (Virtue-AI-HUB/VulnLLM-R-7B @ 8cd13d7a, bf16 Qwen2ForCausalLM, 15.2 GB).
# Memory on one 24 GiB 3090 with nothing else on it: --gpu-memory-utilization 0.90 = 21.6 GiB; weights 14.2 GiB,
# activations/CUDA graphs ~1.5 GiB, KV cache ~5.5 GiB at 56 KiB/token (28 layers x 2 x 4 KV heads x 128 x bf16)
# = ~100k tokens, i.e. ~50 sequences of 2k tokens; --max-num-seqs 64.
# --max-model-len 12288 >= longest prompt (~1.2k tokens, estimate_offline.py) + the authors' max_tokens 8192.
# --generation-config vllm: ignore the checkpoint's generation_config.json defaults (temperature 0.7, top_k 20,
# top_p 0.8, repetition_penalty 1.05); run_vulnllmr.py sends the authors' parameters on every request anyway.
# Refuses to start if a requested GPU already has > 1 GiB in use or port 8005 is taken.
set -euo pipefail
source "$HOME/disk4/cs224/gpu/server/env.sh"

PORT=8005
NAME=vulnllmr
BASE=$CS224/vulnllmr
mkdir -p "$BASE/logs" "$BASE/run"
PIDFILE=$BASE/run/$NAME.pid
LOG=$BASE/logs/$NAME.log
MODEL_DIR=$MODELS/VulnLLM-R-7B
GPU_UTIL=${VULNLLMR_GPU_UTIL:-0.90}
MAX_MODEL_LEN=${VULNLLMR_MAX_MODEL_LEN:-12288}
ACTION=${1:?usage: serve_vulnllmr.sh start <gpu[,gpu]> | stop | health | status}

running() { [[ -f $PIDFILE ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case $ACTION in
  start)
    GPUS=${2:?usage: serve_vulnllmr.sh start <gpu index, e.g. 1, or 0,1>}
    [[ $GPUS =~ ^[01](,[01])?$ ]] || { echo "bad GPU list '$GPUS' (use 0, 1 or 0,1)" >&2; exit 2; }
    if running; then echo "$NAME already running (pid $(cat "$PIDFILE"))"; exit 0; fi
    if ss -ltn "sport = :$PORT" | grep -q LISTEN; then echo "port $PORT already in use" >&2; exit 1; fi
    IFS=, read -ra GPU_LIST <<< "$GPUS"
    for g in "${GPU_LIST[@]}"; do
      used=$(nvidia-smi --query-gpu=memory.used --format=csv,noheader,nounits -i "$g")
      if (( used > 1024 )); then echo "GPU $g has ${used} MiB in use; refusing (needs an empty 3090)" >&2; exit 1; fi
    done
    [[ -f $MODEL_DIR/model-00004-of-00004.safetensors ]] || { echo "model missing: $MODEL_DIR" >&2; exit 1; }
    PAR=()
    if (( ${#GPU_LIST[@]} == 2 )); then PAR=(--data-parallel-size 2); fi
    CMD=(env CUDA_VISIBLE_DEVICES=$GPUS "$VENV/bin/vllm" serve "$MODEL_DIR"
         --served-model-name vulnllm-r-7b --host 0.0.0.0 --port $PORT
         --dtype bfloat16 --max-model-len "$MAX_MODEL_LEN" --gpu-memory-utilization "$GPU_UTIL"
         --max-num-seqs 64 --enable-prefix-caching --generation-config vllm "${PAR[@]}")
    echo "=== start $(date -u +%FT%TZ) ${CMD[*]}" >> "$LOG"
    nohup setsid "${CMD[@]}" >> "$LOG" 2>&1 < /dev/null &
    echo $! > "$PIDFILE"
    echo "$NAME started (pid $(cat "$PIDFILE")) on GPU $GPUS, port $PORT, log $LOG"
    echo "wait for: $0 health   (model load + CUDA graph capture takes ~1-3 min)"
    ;;
  stop)
    if ! running; then echo "$NAME not running"; rm -f "$PIDFILE"; exit 0; fi
    PID=$(cat "$PIDFILE")
    kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID"
    for _ in $(seq 60); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$PID" 2>/dev/null; then kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID"; fi
    rm -f "$PIDFILE"
    echo "$NAME stopped"
    ;;
  health)
    if curl -fsS -m 5 "http://127.0.0.1:$PORT/health" > /dev/null \
       && curl -fsS -m 5 "http://127.0.0.1:$PORT/v1/models" | grep -q vulnllm-r-7b; then
      echo "$NAME healthy (port $PORT)"
    else
      echo "$NAME NOT healthy"; exit 1
    fi
    ;;
  status)
    if running; then echo "$NAME running (pid $(cat "$PIDFILE"))"; else echo "$NAME not running"; fi
    nvidia-smi --query-gpu=index,memory.used,memory.total,utilization.gpu --format=csv,noheader
    ;;
  *) echo "unknown action $ACTION" >&2; exit 2 ;;
esac
