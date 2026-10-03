#!/usr/bin/env bash
# Stress runs on the sizing rig: load past the ceiling, spikes from idle, and dependency failures
# under steady load, checking that the service recovers on its own.
#
#   ./stress.sh plan               the rates it would use here, and nothing else
#   ./stress.sh <scenario> ...     one or more of the scenarios below
#   ./stress.sh all                every scenario, in the order listed
#
# Scenarios:
#
#   spike              idle, then three times the ceiling for thirty seconds, then a normal load
#   overload           the production mix at twice its ceiling for two minutes, then a normal load
#   limiter            the rate limiter at its shipped defaults, offered more than it allows
#   postgres-pause     the database frozen for fifteen seconds under load (a stalled primary)
#   postgres-restart   the database restarted under load (a failover: every connection dropped)
#   keycloak-down      the identity provider stopped for thirty seconds under load
#   keycloak-stall     the identity provider frozen for thirty seconds (a black hole, not a refusal)
#   subactid-restart       the control plane stopped gracefully and started again under load
#   subactid-kill          the control plane killed outright and started again under load
#   slow-senders       300 token requests whose bodies trickle in, held open under a normal load
#   smoke              twenty seconds of the production mix, to check the harness itself
#   soak               the production mix at half its ceiling for SOAK_MINUTES (default 20)
#
# The generator offers load and records responses. Faults are injected from here, timed against
# the generator's start, and logged beside its timeline.
#
# After each run the audit ledger is reconciled with the responses: every successful exchange
# needs a `token.issued` record and every refusal a `token.denied` one. A mismatch fails the script.

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# CEILING is the highest clean exchange rate, and MIX_CEILING the same for the production mix.
# Set both from a campaign's results. Defaults are estimated from the core count.
cores="${CORES:-$(nproc)}"
ceiling="${CEILING:-$(( cores * 90 ))}"
mix_ceiling="${MIX_CEILING:-$(( ceiling * 3 ))}"
users="${USERS:-8}"
soak_minutes="${SOAK_MINUTES:-20}"

at() { awk -v p="$1" -v f="$2" 'BEGIN { printf "%.0f", p * f }'; }
BASE="$(at "$ceiling" 0.25)"
MIX_BASE="$(at "$mix_ceiling" 0.25)"

results="$here/results/stress"
mkdir -p "$results"
failed=0

bind="${RIG_BIND:-127.0.0.1}"
ready() {
  for _ in $(seq 1 240); do
    curl -fsS -m 2 "http://$bind:5100/readyz" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "the control plane did not come back ready" >&2
  return 1
}

# Recreates the control plane with the given environment and the stress overlay's restart policy.
restart_subactid() {
  env "$@" docker compose -f compose.yaml -f compose.stress.yaml up -d --force-recreate subactid >/dev/null 2>&1
  ready
}

psql_subactid() {
  docker compose exec -T postgres psql -U postgres -d subactid -At -F '|' -c "$1" 2>/dev/null
}

# Ledger totals for the busy agent by event, decision, reason and summary flag. Summary records
# carry a count, so rows are summed by it.
ledger() {
  psql_subactid "select event || ':' || coalesce(decision, '-') || ':' || coalesce(reason, '-')
                    || ':' || case when count is null then 'single' else 'summary' end,
                    sum(coalesce(count, 1))
             from audit_events where agent_id = 'bench-busy' or (agent_id is null and event = 'token.denied')
             group by 1 order by 1"
}

# Renewals counted on grants created since the run began. Only the first renewal is written
# immediately. The rest reach the ledger as a summary when the task ends (spec, audit section).
renewals_since() {
  psql_subactid "select coalesce(sum(renewals), 0) from task_grants
             where agent_id = 'bench-busy' and created_at >= to_timestamp($1 / 1000.0)"
}

# Samples readiness, memory, restarts, OOM kills and database connections every second.
watch_rig() {
  local out="$1" start_ms="$2"
  local id
  echo "t,readyz,subactid_rss_mb,subactid_restarts,subactid_oom,db_connections" > "$out"
  while :; do
    local now_ms t code rss restarts oom conns
    now_ms="$(date +%s%3N)"
    t="$(awk -v n="$now_ms" -v s="$start_ms" 'BEGIN { printf "%.1f", (n - s) / 1000 }')"
    code="$(curl -s -o /dev/null -m 1 -w '%{http_code}' "http://$bind:5100/readyz" 2>/dev/null || true)"
    id="$(docker compose ps -q subactid 2>/dev/null || true)"
    rss=0
    if [ -n "$id" ]; then
      for f in "/sys/fs/cgroup/memory/docker/$id/memory.stat" "/sys/fs/cgroup/system.slice/docker-$id.scope/memory.stat"; do
        if [ -r "$f" ]; then
          rss="$(awk '/^(total_rss|anon) /{ printf "%.0f", $2 / 1048576; exit }' "$f")"
          break
        fi
      done
      restarts="$(docker inspect -f '{{.RestartCount}}' "$id" 2>/dev/null || echo '?')"
      oom="$(docker inspect -f '{{.State.OOMKilled}}' "$id" 2>/dev/null || echo '?')"
    else
      restarts='?'
      oom='?'
    fi
    conns="$(docker compose exec -T postgres psql -U postgres -d subactid -At -c "select count(*) from pg_stat_activity where usename = 'subactid'" 2>/dev/null || echo '-')"
    echo "$t,$code,$rss,$restarts,$oom,${conns:--}" >> "$out"
    sleep 1
  done
}

# One scenario: run the load profile, inject faults at their offsets, reconcile the ledger.
#
#   run <label> <shape> <profile> [<offset seconds> <command> ...]
run() {
  local label="$1" shape="$2" profile="$3"
  shift 3

  echo
  echo "### $label: $shape, $profile  $(date -u +%H:%M:%S)"
  local started="$results/$label.started"
  local events="$results/$label.events"
  rm -f "$started"
  : > "$events"

  local before before_ms
  before_ms="$(date +%s%3N)"
  before="$(ledger)"

  ./bench.sh stress --shape "$shape" --profile "$profile" --users "$users" --label "$label" \
    --started-file "/results/stress/$label.started" --out "/results/stress/$label.json" \
    > "$results/$label.log" 2>&1 &
  local generator=$!

  # The generator writes this file just before its first request, after setup, so offsets start there.
  for _ in $(seq 1 600); do
    [ -s "$started" ] && break
    kill -0 "$generator" 2>/dev/null || break
    sleep 0.1
  done
  if [ ! -s "$started" ]; then
    echo "the generator never started offering load; see $results/$label.log" >&2
    wait "$generator"
    failed=1
    return
  fi
  local start_ms
  start_ms="$(cat "$started")"

  watch_rig "$results/$label.rig.csv" "$start_ms" &
  local watcher=$!

  while [ $# -ge 2 ]; do
    local offset="$1" action="$2"
    shift 2
    local due_ms=$(( start_ms + ${offset%.*} * 1000 ))
    local now_ms
    now_ms="$(date +%s%3N)"
    [ "$due_ms" -gt "$now_ms" ] && sleep "$(awk -v d=$(( due_ms - now_ms )) 'BEGIN { printf "%.3f", d / 1000 }')"
    local t
    t="$(awk -v n="$(date +%s%3N)" -v s="$start_ms" 'BEGIN { printf "%.1f", (n - s) / 1000 }')"
    echo "  t=${t}s  $action"
    echo "$t,$action" >> "$events"
    eval "$action" >/dev/null 2>&1 || echo "  (the action returned non-zero)"
  done

  wait "$generator"
  local status=$?
  kill "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null

  # Restore every dependency before the next scenario.
  for service in postgres keycloak; do
    docker compose unpause "$service" >/dev/null 2>&1
    docker compose start "$service" >/dev/null 2>&1
  done
  ready || failed=1

  # Wait for aggregated denials to flush.
  sleep "${LEDGER_SETTLE:-70}"
  local after
  after="$(ledger)"

  cat "$results/$label.log" | sed -n '1,/^   sec/p' | sed '$d'
  if [ "$status" -ne 0 ]; then
    echo "  the generator exited $status; see $results/$label.log"
    failed=1
    return
  fi

  reconcile "$label" "$before" "$after" "$(renewals_since "$before_ms")"
  summarise_rig "$label"
}

# Compares ledger changes with the token endpoint's responses.
reconcile() {
  local label="$1" before="$2" after="$3" counted="$4"
  python3 - "$results/$label.json" "$label" "$counted" <<EOF
import json, sys
def parse(text):
    out = {}
    for line in text.strip().splitlines():
        if '|' in line:
            k, v = line.rsplit('|', 1)
            out[k] = int(v)
    return out
before = parse("""$before""")
after = parse("""$after""")
delta = {k: after.get(k, 0) - before.get(k, 0) for k in set(before) | set(after)}
delta = {k: v for k, v in delta.items() if v}
summary = json.load(open(sys.argv[1]))
# Token endpoint responses, keyed grant:status[:error].
answers = summary["token_answers"]
def total(pred):
    return sum(v for k, v in answers.items() if pred(k.split(":")))
exchanged = total(lambda p: p[0] == "exchange" and p[1].startswith("2"))
refreshed = total(lambda p: p[0] == "refresh" and p[1].startswith("2"))
ok = exchanged + refreshed
counted = int(sys.argv[3] or 0)
# A 500, or a 503 for an unreachable database, is not a decision. Every other refusal must be audited.
def undecided(p):
    return p[1] == "500" or (len(p) > 2 and p[2].endswith("(database)"))
refused = {k: v for k, v in answers.items() if k.split(":")[1][:1] in "45" and not undecided(k.split(":"))}
server_errors = total(undecided)
transport = total(lambda p: p[1] == "0")
issued = sum(v for k, v in delta.items() if k.startswith("token.issued:"))
first_renewals = sum(v for k, v in delta.items() if k.startswith("token.refreshed:") and k.endswith(":single"))
denied = sum(v for k, v in delta.items() if ":deny:" in k)
print("  ledger moved: " + (", ".join(f"{k}={v}" for k, v in sorted(delta.items())) or "nothing"))
print(f"  renewals counted on this run's grants: {counted}")
print(f"  token endpoint: {exchanged} exchanged and {refreshed} refreshed, {sum(refused.values())} refused {refused or ''}, {server_errors} undecided (500 or database unreachable), {transport} never answered")
verdict = []
if issued < exchanged:
    verdict.append(f"BROKEN: {exchanged} exchanges answered with a token but only {issued} token.issued records")
if issued > exchanged:
    verdict.append(f"note: {issued - exchanged} issue records for tokens the caller never received (an answer lost after commit)")
# The grant counts every renewal, including the first.
if counted < refreshed:
    verdict.append(f"BROKEN: {refreshed} refreshes answered with a token but only {counted} counted on their grants")
if counted > refreshed:
    verdict.append(f"note: {counted - refreshed} renewals counted that the caller never received")
if first_renewals > refreshed:
    verdict.append(f"BROKEN: {first_renewals} first-renewal records for {refreshed} refreshes")
if denied < sum(refused.values()):
    verdict.append(f"BROKEN: {sum(refused.values())} refusals answered but only {denied} denial records")
if server_errors or transport:
    verdict.append(f"note: {server_errors + transport} requests got no decision at all (500, database unreachable, or no answer), so there is nothing to audit for them")
print("  audit: " + ("; ".join(verdict) if verdict else "every answered decision has its record"))
sys.exit(1 if any(v.startswith("BROKEN") for v in verdict) else 0)
EOF
  [ $? -eq 0 ] || failed=1
}

summarise_rig() {
  local csv="$results/$1.rig.csv"
  [ -f "$csv" ] || return
  awk -F, 'NR > 1 {
      n++; if ($2 != "200") { unready++; if (first == "") first = $1; last = $1 }
      if ($3 + 0 > peak) peak = $3 + 0
      if ($6 ~ /^[0-9]+$/ && $6 + 0 > conns) conns = $6 + 0
      restarts = $4; oom = $5
    }
    END {
      printf "  rig: subactid peak rss %d MB, peak db connections %d, restarts %s, oom-killed %s", peak, conns, restarts, oom
      if (unready) printf ", /readyz not 200 for %d of %d samples (t=%s..%s)", unready, n, first, last
      printf "\n"
    }' "$csv"
}

limiter_on_defaults() {
  restart_subactid SUBACTID_RATELIMIT_PERMITS=600 SUBACTID_RATELIMIT_BURST=120
}

limiter_raised() {
  restart_subactid
}

# An unmeasured pass to warm up the JIT in the control plane and Keycloak.
warm() {
  echo "warming the rig"
  ./bench.sh load --shape exchange --rate "$BASE" --warmup 5 --duration 40 --users "$users" >/dev/null 2>&1
  ./bench.sh load --shape introspect --rate "$(at "$BASE" 3)" --warmup 5 --duration 20 --users "$users" >/dev/null 2>&1
}

scenario() {
  case "$1" in
    spike)
      run spike exchange "20@0,30@$BASE,30@$(at "$ceiling" 3),90@$BASE"
      ;;
    overload)
      run overload mixed "30@$MIX_BASE,120@$(at "$mix_ceiling" 2),90@$MIX_BASE"
      ;;
    limiter)
      limiter_on_defaults
      warm
      # 600 a minute with a burst of 120, offered 30/s, three times the limit.
      run limiter exchange "60@30,30@5"
      limiter_raised
      warm
      ;;
    postgres-pause)
      run postgres-pause exchange "120@$BASE" 30 "docker compose pause postgres" 45 "docker compose unpause postgres"
      ;;
    postgres-restart)
      run postgres-restart exchange "120@$BASE" 30 "docker compose restart -t 10 postgres"
      ;;
    keycloak-down)
      run keycloak-down exchange "120@$BASE" 30 "docker compose stop -t 5 keycloak" 60 "docker compose start keycloak"
      ;;
    keycloak-stall)
      run keycloak-stall exchange "120@$BASE" 30 "docker compose pause keycloak" 60 "docker compose unpause keycloak"
      ;;
    subactid-restart)
      run subactid-restart exchange "120@$BASE" 30 "docker compose restart -t 30 subactid"
      warm
      ;;
    subactid-kill)
      # Killed from the host, since the restart policy ignores a `docker kill`.
      run subactid-kill exchange "120@$BASE" 30 'kill -9 "$(docker inspect -f "{{.State.Pid}}" "$(docker compose ps -q subactid)")"'
      warm
      ;;
    smoke)
      run smoke mixed "10@50,10@100"
      ;;
    slow-senders)
      # Slow bodies from the host, not the generator's container, so they have their own rate
      # limit allowance. Normal load must keep being served.
      run slow-senders exchange "90@$BASE" 10 "./slow-senders.py --host $bind --connections 300 --seconds 60 > $results/slow-senders.attack.log 2>&1 &"
      ;;
    soak)
      run soak mixed "$(( soak_minutes * 60 ))@$(at "$mix_ceiling" 0.5)"
      ;;
    *)
      echo "unknown scenario: $1" >&2
      exit 2
      ;;
  esac
}

all=(spike overload limiter postgres-pause postgres-restart keycloak-down keycloak-stall subactid-restart subactid-kill slow-senders soak)

case "${1:-}" in
  ""|-h|--help)
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
  plan)
    echo "    ceiling      $ceiling exchanges/s (CEILING), $mix_ceiling mixed requests/s (MIX_CEILING)"
    echo "    normal load  $BASE exchanges/s, $MIX_BASE mixed requests/s"
    echo "    spike        $(at "$ceiling" 3)/s   overload $(at "$mix_ceiling" 2)/s mixed   soak $(at "$mix_ceiling" 0.5)/s for ${soak_minutes}m"
    exit 0
    ;;
  all)
    set -- "${all[@]}"
    ;;
esac

# Start the control plane with the stress overlay's restart policy.
restart_subactid
./bench.sh setup --users "$users" >/dev/null
warm
for name in "$@"; do
  scenario "$name"
done

echo
if [ "$failed" -ne 0 ]; then
  echo "at least one scenario broke an invariant or did not finish; the logs are in $results"
  exit 1
fi
echo "every scenario finished and every answered decision was audited; the logs are in $results"
