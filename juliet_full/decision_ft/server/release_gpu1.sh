#!/usr/bin/env bash
# Hand GPU 1 to the gpu lane once the last GPU-1 training job (L3_fold1) has ended: wait until its claim
# records an exit code and GPU 1 has no compute process, then touch $CS224/GPU1_FREE_FOR_SERVICES.
source "$HOME/disk4/cs224/decision_ft/server/env.sh"
cd "$DFT"
job=${1:-L3_fold1}
until grep -q '^rc=' "status/$job.claim/info" 2>/dev/null; do sleep 30; done
while [ -n "$(nvidia-smi -i 1 --query-compute-apps=pid --format=csv,noheader)" ]; do sleep 10; done
touch "$CS224/GPU1_FREE_FOR_SERVICES"
echo "$(date -u +%FT%TZ) $job: $(grep '^rc=' "status/$job.claim/info"); touched $CS224/GPU1_FREE_FOR_SERVICES"
