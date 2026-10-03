#!/usr/bin/env bash
# The full measurement campaign behind docs/sizing.md, run in this order on one rig.
#
#   ./campaign.sh capacity   what it costs and where it stops
#   ./campaign.sh growth     the long soak the ledger growth model is measured from
#   ./campaign.sh all        both, in that order
#
# Rate limiting is off for the capacity runs, so the ceiling is the service's own. The limiter
# is measured separately at the end.
#
# Per-request costs run before the ceiling sweep, and phases that measure memory restart the
# instance first, because .NET does not release memory after an overload run.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# Sponsors for the capacity runs. The soak uses more, since sponsor cardinality affects index size.
users="${USERS:-8}"
soak_users="${SOAK_USERS:-64}"
warmup="${WARMUP:-15}"
duration="${DURATION:-45}"

# Rates scale with the core count. The rig costs about ten millicores per exchange per second
# (4.4 Subact ID, 2.9 Postgres, 1.1 identity provider, the rest the load generator), so about 100
# exchanges a second per core, or 125 with a remote generator. PEAK overrides the estimate.
cores="${CORES:-$(nproc)}"
per_core="${PER_CORE:-$([ -n "${BENCH_DOCKER_HOST:-}" ] && echo 125 || echo 100)}"
peak="${PEAK:-$(( cores * per_core ))}"

# Fractions of the estimate. On four cores: 1, 5, 10, 25, 50, 100, 150, 200, 250, 300, and a
# ceiling sweep of 350 to 850.
at() { awk -v p="$peak" -v f="$1" 'BEGIN { printf "%.0f", p * f }'; }
rungs() { local out=(); for f in "$@"; do out+=("$(at "$f")"); done; echo "${out[@]}"; }

LADDER_RATES="1 $(rungs 0.0125 0.025 0.0625 0.125 0.25 0.375 0.5 0.625 0.75)"
CEILING_RATES="$(rungs 0.875 1.0 1.125 1.25 1.375 1.75 2.125)"
INTROSPECT_RATES="$(rungs 0.75 1.5 2.25 3.0 3.75)"
JWKS_RATES="$(rungs 1.25 2.5 3.75)"
LOW_RATE="$(at 0.25)"    # where the per-request and limiter comparisons are taken
HIGH_RATE="$(at 0.75)"   # the highest rate that still serves cleanly here
GC_RATE="$(at 0.025)"

mark() { echo "### $* $(date -u +%H:%M:%S)"; }

ready() { until curl -fsS "http://${RIG_BIND:-127.0.0.1}:5100/readyz" >/dev/null 2>&1; do sleep 0.5; done; }

# Recreates the instance with the given environment overrides and waits until it is ready.
restart() {
  env "$@" docker compose up -d --force-recreate subactid >/dev/null
  ready
}

# A discarded warm-up run, so JIT compilation in .NET and in Keycloak's JVM is not measured.
# It runs long enough for the JVM's C2 compiler to settle.
warm() {
  ./bench.sh load --shape exchange --rate "${WARM_RATE:-$(at 0.375)}" --warmup 10 --duration 60 --users "$users" >/dev/null 2>&1
}

fresh() {
  ./rig.sh reset >/dev/null 2>&1
  SUBACTID_RATELIMIT_ENABLED=false ./rig.sh up
  echo -n "    SubactId__RateLimit__Enabled="
  docker compose exec -T subactid printenv SubactId__RateLimit__Enabled || echo "(unset)"
  ./bench.sh setup --users "${1:-$users}" ${2:+--task-ttl "$2"} ${3:+--token-ttl "$3"}
}

capacity() {
  fresh

  mark "PHASE idle and cold start"
  # On a fresh instance, so memory is the floor.
  restart SUBACTID_RATELIMIT_ENABLED=false
  ./measure.sh idle -- idle 60
  docker compose stop subactid >/dev/null
  started="$(date +%s.%N)"
  docker compose start subactid >/dev/null
  ready
  awk -v s="$started" -v e="$(date +%s.%N)" 'BEGIN { printf "    ready %.0f ms after the container started\n", (e - s) * 1000 }'
  # Startup time reported by the process itself.
  docker compose logs subactid --since 2m 2>/dev/null | grep -iE "now listening|started|ready" | head -3

  mark "PHASE what each request costs"
  warm
  ./measure.sh cost-exchange   -- load --shape exchange   --rate "$LOW_RATE" --warmup "$warmup" --duration "$duration" --users "$users"
  ./measure.sh cost-refresh    -- load --shape refresh    --rate "$LOW_RATE" --warmup "$warmup" --duration "$duration" --users "$users"
  ./measure.sh cost-introspect -- load --shape introspect --rate "$HIGH_RATE" --warmup "$warmup" --duration "$duration" --users "$users"
  ./measure.sh cost-jwks       -- load --shape jwks       --rate "$HIGH_RATE" --warmup "$warmup" --duration "$duration" --users "$users"
  ./measure.sh cost-discovery  -- load --shape discovery  --rate "$HIGH_RATE" --warmup "$warmup" --duration "$duration" --users "$users"
  ./measure.sh cost-denied     -- load --shape denied     --rate "$HIGH_RATE" --warmup "$warmup" --duration "$duration" --users "$users"

  mark "PHASE statements per request"
  half="$(at 0.5)"
  for spec in "exchange $LOW_RATE 30" "refresh $LOW_RATE 30" "introspect $half 30" "jwks $half 20" "denied $half 20"; do
    set -- $spec
    ./statements.sh "$1" "$2" "$3" > "results/statements-$1.txt" 2>&1
    echo "--- $1"; tail -12 "results/statements-$1.txt"
  done

  mark "PHASE the garbage collector"
  restart SUBACTID_RATELIMIT_ENABLED=false DOTNET_GCSERVER=0
  ./measure.sh gc-workstation-idle -- idle 60
  warm
  ./measure.sh gc-workstation-10 -- load --shape exchange --rate "$GC_RATE" --warmup "$warmup" --duration "$duration"
  restart SUBACTID_RATELIMIT_ENABLED=false

  mark "PHASE the ladder"
  warm
  for rate in $LADDER_RATES; do
    ./measure.sh "ladder-$rate" -- load --shape exchange --rate "$rate" --warmup 10 --duration 30 --users "$users"
  done

  # Restart to empty the connection pool left by the ladder. No warm-up, since it would refill
  # the pool, and this phase counts connections, not CPU. Rates ascend.
  mark "PHASE database connections"
  restart SUBACTID_RATELIMIT_ENABLED=false
  ./connections.sh $LADDER_RATES

  mark "PHASE the ceiling"
  restart SUBACTID_RATELIMIT_ENABLED=false
  warm
  for rate in $CEILING_RATES; do
    ./measure.sh "ceiling-$rate" -- load --shape exchange --rate "$rate" --warmup "$warmup" --duration "$duration" --users "$users"
  done

  mark "PHASE the read paths"
  restart SUBACTID_RATELIMIT_ENABLED=false
  warm
  for rate in $INTROSPECT_RATES; do
    ./measure.sh "introspect-$rate" -- load --shape introspect --rate "$rate" --warmup 10 --duration 30 --users "$users"
  done
  for rate in $JWKS_RATES; do
    ./measure.sh "jwks-$rate" -- load --shape jwks --rate "$rate" --warmup 10 --duration 30 --users "$users"
  done

  mark "PHASE denial aggregation off"
  restart SUBACTID_RATELIMIT_ENABLED=false SUBACTID_AGGREGATION_ENABLED=false
  warm
  ./measure.sh denied-unaggregated -- load --shape denied --rate "$HIGH_RATE" --warmup "$warmup" --duration "$duration" --users "$users"

  # The limiter at its shipped defaults: 600 per minute, ten a second from the single generator.
  mark "PHASE the limiter at its shipped defaults"
  restart SUBACTID_RATELIMIT_ENABLED=true SUBACTID_RATELIMIT_PERMITS=600 SUBACTID_RATELIMIT_BURST=120
  warm
  ./measure.sh limiter-defaults -- load --shape exchange --rate "$LOW_RATE" --warmup "$warmup" --duration "$duration" --users "$users"

  # The limiter raised above the offered load. Compare with the ladder at the same rates to get
  # the limiter's overhead.
  mark "PHASE the limiter raised above the load"
  restart SUBACTID_RATELIMIT_ENABLED=true SUBACTID_RATELIMIT_PERMITS=120000 SUBACTID_RATELIMIT_BURST=4000
  warm
  ./measure.sh "limiter-raised-$LOW_RATE" -- load --shape exchange --rate "$LOW_RATE" --warmup "$warmup" --duration "$duration" --users "$users"
  ./measure.sh "limiter-raised-$HIGH_RATE" -- load --shape exchange --rate "$HIGH_RATE" --warmup "$warmup" --duration "$duration" --users "$users"
  restart SUBACTID_RATELIMIT_ENABLED=false

  mark "capacity done"
}

growth() {
  # PT5M and PT1M keep the default five-to-one ratio of task to token lifetime, with shorter holds.
  fresh "$soak_users" "${SOAK_TASK_TTL:-PT5M}" "${SOAK_TOKEN_TTL:-PT1M}"
  warm

  # The hold must be at least two task lifetimes, so every task has expired and been swept
  # before anything is counted.
  ./measure.sh soak -- soak \
    --rate "${SOAK_RATE:-20}" \
    --issue-seconds "${SOAK_ISSUE:-600}" \
    --hold-seconds "${SOAK_HOLD:-720}" \
    --refresh-seconds "${SOAK_REFRESH:-54}" \
    --users "$soak_users"

  ./storage-report.sh | tee results/storage-report.txt
  ./audit-queries.sh > results/audit-queries.txt 2>&1
  sed -n '1,12p' results/audit-queries.txt
  ./reindex.sh > results/reindex.txt 2>&1
  grep -E "ledger:|as written|rebuilt|offered|p50" results/reindex.txt | head -20
  mark "growth done"
}

plan() {
  echo "    cores      $cores, $per_core exchanges a second each, so a peak of about $peak/s"
  echo "    ladder     $LADDER_RATES"
  echo "    ceiling    $CEILING_RATES"
  echo "    introspect $INTROSPECT_RATES"
  echo "    jwks       $JWKS_RATES"
  echo "    soak       ${SOAK_RATE:-20}/s for ${SOAK_ISSUE:-600}s, then held ${SOAK_HOLD:-720}s"
  echo "    override the estimate with PEAK, or its halves with CORES and PER_CORE"
}

case "${1:-all}" in
  capacity) capacity ;;
  growth)   growth ;;
  all)      capacity; growth ;;
  plan)     plan; exit 0 ;;
  *) echo "usage: campaign.sh <capacity|growth|all|plan>" >&2; exit 2 ;;
esac

mark "CAMPAIGN DONE"
