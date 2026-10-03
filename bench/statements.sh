#!/usr/bin/env bash
# Measures database statements per request with pg_stat_statements.
#
#   ./statements.sh exchange 100 30
#
# Resets the counters, runs load with no warmup, and divides total calls by successful requests.
# The expiry sweeper's statements are included in the total and also printed separately.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

shape="${1:-exchange}"
rate="${2:-100}"
duration="${3:-30}"
label="statements-$shape"

# Runs as the superuser, since the server's role has no access to statement statistics.
psql() { docker compose exec -T postgres psql -U postgres -d subactid -qAt -v ON_ERROR_STOP=1 "$@"; }

psql -c 'SELECT pg_stat_statements_reset();' >/dev/null

./bench.sh load \
  --shape "$shape" --rate "$rate" --warmup 0 --duration "$duration" \
  --out "/results/$label.json"

calls="$(psql -c "SELECT coalesce(sum(calls), 0) FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid WHERE d.datname = 'subactid';")"
sweeper="$(psql -c "SELECT coalesce(sum(calls), 0) FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid WHERE d.datname = 'subactid' AND s.query ILIKE '%tasks%' AND s.query ILIKE '%expires_at%';")"
succeeded="$(sed -n 's/.*"succeeded": *\([0-9]*\).*/\1/p' "results/$label.json" | head -1)"

echo
echo "$shape at $rate/s for ${duration}s"
echo "  succeeded          $succeeded"
echo "  statements         $calls"
echo "  of which sweeper   $sweeper"
awk -v c="$calls" -v s="$succeeded" 'BEGIN { if (s > 0) printf "  per request        %.2f\n", c / s }'

echo
echo "the ten statements the run spent most calls on:"
docker compose exec -T postgres psql -U postgres -d subactid -P pager=off -c "
SELECT calls, round(total_exec_time::numeric, 1) AS total_ms, left(regexp_replace(query, '\s+', ' ', 'g'), 90) AS statement
FROM pg_stat_statements s JOIN pg_database d ON d.oid = s.dbid
WHERE d.datname = 'subactid'
ORDER BY calls DESC
LIMIT 10;"
