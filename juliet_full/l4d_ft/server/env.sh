# Sourced by every l4d_ft server script on 184-toast: gpu lane env (caches on ~/disk4, HF offline, CPATH) + ours.
source "$HOME/disk4/cs224/gpu/server/env.sh"
export L4D=$CS224/l4d_ft
export VENV=${VENV:-$CS224/venv}
export TOKENIZERS_PARALLELISM=false
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
mkdir -p "$L4D/logs" "$L4D/status" "$L4D/runs" "$L4D/results"
