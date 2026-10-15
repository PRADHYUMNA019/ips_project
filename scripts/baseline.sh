#!/usr/bin/env bash
# scripts/baseline.sh <label> [runs]  ->  results/csv/baseline_<label>_<ts>.csv
set -euo pipefail
cd "$(dirname "$0")/.."
LABEL=${1:?label}; RUNS=${2:-3}
mkdir -p results/csv
OUT=results/csv/baseline_${LABEL}_$(date +%Y%m%d_%H%M%S).csv
echo "run,p50_ms,p95_ms,p99_ms,throughput_mbps" > "$OUT"

sudo ip netns exec srv iperf3 -s -D 2>/dev/null || true
sleep 1

for i in $(seq "$RUNS"); do
  sudo ip netns exec iot1 ping -c 500 -i 0.01 10.0.2.10 > /tmp/p.txt
  LAT=$(python3 - <<'PY'
import re
times = sorted(float(m) for m in re.findall(r"time=([\d.]+)", open("/tmp/p.txt").read()))
pct = lambda p: times[min(len(times) - 1, int(len(times) * p))]
print(f"{pct(.5):.3f},{pct(.95):.3f},{pct(.99):.3f}")
PY
)
  MBPS=$(sudo ip netns exec iot1 iperf3 -c 10.0.2.10 -t 5 2>/dev/null | awk '/sender/ {print $7}')
  echo "$i,$LAT,${MBPS:-0}" >> "$OUT"
done
echo "[OK] $OUT"
column -t -s, "$OUT"
