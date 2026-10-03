#!/usr/bin/env bash
# Measures how many database connections each request rate holds open.
#
#   ./connections.sh 1 5 10 25 50 100 150 200 250 300
#
# Npgsql opens connections on demand. For each rate, `pg_stat_activity` is sampled during the
# load and the peak and mean are reported. The sampling session itself is excluded.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

warmup="${WARMUP:-10}"
duration="${DURATION:-20}"
rates=("$@")
[ ${#rates[@]} -eq 0 ] && rates=(1 5 10 25 50 100 150 200 250 300)

results="$here/results"
mkdir -p "$results"
out="$results/connections.csv"
echo "rate,peak_backends,mean_backends,samples" > "$out"

printf '%8s %14s %14s\n' rate "peak backends" "mean backends"

for rate in "${rates[@]}"; do
  samples="$(mktemp)"
  (
    while true; do
      docker compose exec -T postgres psql -U subactid -d subactid -qAt \
        -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'subactid' AND application_name <> 'psql' AND pid <> pg_backend_pid();" 2>/dev/null
      sleep 2
    done
  ) >> "$samples" &
  sampler=$!

  ./bench.sh load \
    --shape exchange --rate "$rate" --warmup "$warmup" --duration "$duration" \
    --out "/results/connections-$rate.json" >/dev/null 2>&1 || true

  kill "$sampler" 2>/dev/null || true
  wait "$sampler" 2>/dev/null || true

  # Samples include the warmup. That cannot raise the peak.
  awk -v rate="$rate" -v out="$out" '
    /^[0-9]+$/ { n++; sum += $1; if ($1 > peak) peak = $1 }
    END {
      if (n == 0) { printf "%8s %14s %14s\n", rate, "n/a", "n/a"; exit }
      printf "%8s %14d %14.1f\n", rate, peak, sum / n;
      printf "%s,%d,%.1f,%d\n", rate, peak, sum / n, n >> out;
    }' "$samples"
  rm -f "$samples"
done

echo
echo "wrote $out"
