# Sourced by every 184-toast service script. Keeps all caches and temp files on ~/disk4
# (the root partition has only ~23 GB free).
export CS224=$HOME/disk4/cs224
export VENV=$CS224/venv
export MODELS=$CS224/models
export LOGS=$CS224/logs
export RUN=$CS224/run
export HF_HOME=$CS224/cache/hf
export HF_HUB_OFFLINE=1
export HF_ENDPOINT=https://hf-mirror.com
export XDG_CACHE_HOME=$CS224/cache/xdg
export TRITON_CACHE_DIR=$CS224/cache/triton
export TORCHINDUCTOR_CACHE_DIR=$CS224/cache/inductor
export VLLM_CACHE_ROOT=$CS224/cache/vllm
export VLLM_CONFIG_ROOT=$CS224/cache/vllm_config
export VLLM_NO_USAGE_STATS=1
export DO_NOT_TRACK=1
export FLASHINFER_WORKSPACE_BASE=$CS224/cache/flashinfer
export CUDA_CACHE_PATH=$CS224/cache/nv
export TMPDIR=$CS224/tmp
export PYTHONPYCACHEPREFIX=$CS224/cache/pycache
# Triton JIT-compiles a small C launcher that needs Python.h; 184-toast has no python3.12-dev and we
# have no sudo, so the identical 3.12.3-1ubuntu0.17 headers were copied from dell into pyinclude/.
export CPATH=$CS224/pyinclude/include:$CS224/pyinclude/include/python3.12${CPATH:+:$CPATH}
mkdir -p "$LOGS" "$RUN" "$HF_HOME" "$XDG_CACHE_HOME" "$TRITON_CACHE_DIR" "$TORCHINDUCTOR_CACHE_DIR" \
  "$VLLM_CACHE_ROOT" "$VLLM_CONFIG_ROOT" "$FLASHINFER_WORKSPACE_BASE" "$CUDA_CACHE_PATH" "$TMPDIR"
