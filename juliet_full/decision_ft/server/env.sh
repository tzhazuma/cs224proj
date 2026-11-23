# Sourced by every decision_ft server script on 184-toast. The gpu lane's env.sh sets all caches/temp on ~/disk4,
# HF_HUB_OFFLINE=1 and CPATH (Python.h for Triton JIT, needed by flash-linear-attention); we only add our own vars.
source "$HOME/disk4/cs224/gpu/server/env.sh"
export DFT=$CS224/decision_ft
export TOKENIZERS_PARALLELISM=false
mkdir -p "$DFT/logs" "$DFT/status"
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
