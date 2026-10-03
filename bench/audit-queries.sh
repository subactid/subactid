#!/usr/bin/env bash
# Measures the database cost of each audit query filter: time range, sponsor, task and decision,
# ordered by (ts, seq) and limited as EfAuditQuery does. Each runs many times inside the server,
# so client round trips are excluded. The denial query's plan is printed with and without the
# partial index.
#
# Compare shapes against each other. Absolute numbers depend on the rig and the ledger size.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

repeats="${REPEATS:-50}"

psql() { docker compose exec -T postgres psql -U subactid -d subactid -qAt -v ON_ERROR_STOP=1 "$@"; }
plan() { docker compose exec -T postgres psql -U subactid -d subactid -P pager=off -v ON_ERROR_STOP=1 "$@"; }

rows="$(psql -c 'SELECT count(*) FROM audit_events;')"
denials="$(psql -c "SELECT count(*) FROM audit_events WHERE decision = 'deny';")"
sponsor="$(psql -c "SELECT sponsor FROM audit_events WHERE sponsor IS NOT NULL GROUP BY sponsor ORDER BY count(*) DESC LIMIT 1;")"
task="$(psql -c "SELECT task_id FROM audit_events WHERE task_id IS NOT NULL LIMIT 1;")"

echo "ledger: $rows records, $denials of them denials"
echo "each shape repeated $repeats times; the mean of one execution follows"
echo

# Runs `sql` `repeats` times in one DO block and prints the mean in microseconds. `setup` runs
# first in the same transaction, which is rolled back.
timed() {
  local name="$1" sql="$2" setup="${3:-}"
  local micros
  micros="$(psql -c "
    BEGIN;
    ${setup}
    DO \$do\$
    DECLARE started timestamptz := clock_timestamp(); i int;
    BEGIN
      FOR i IN 1..$repeats LOOP
        EXECUTE \$q\$${sql}\$q\$;
      END LOOP;
      RAISE NOTICE 'micros %', round(EXTRACT(epoch FROM clock_timestamp() - started) * 1000000 / $repeats);
    END
    \$do\$;
    ROLLBACK;" 2>&1 | sed -n 's/.*micros \([0-9]*\).*/\1/p')"
  printf '%-52s %10s µs\n' "$name" "${micros:-n/a}"
}

since="SELECT * FROM audit_events WHERE ts >= now() - interval '1 day' ORDER BY ts, seq LIMIT 1000"
# The sponsor index is on a fingerprint of the string, so the query has both equalities, as
# EfAuditQuery writes them. The fingerprint reaches the index and the column equality filters
# collisions.
bysponsor="SELECT * FROM audit_events WHERE sponsor = '$sponsor' AND audit_events_fingerprint(sponsor) = audit_events_fingerprint('$sponsor') AND ts >= now() - interval '1 day' ORDER BY ts, seq LIMIT 50"
bysponsorplain="SELECT * FROM audit_events WHERE sponsor = '$sponsor' AND ts >= now() - interval '1 day' ORDER BY ts, seq LIMIT 50"
bytask="SELECT * FROM audit_events WHERE task_id = '$task' ORDER BY ts, seq LIMIT 100"
denied="SELECT * FROM audit_events WHERE decision = 'deny' AND ts >= now() - interval '1 day' ORDER BY ts, seq LIMIT 1000"

timed "since ts, limit 1000"                            "$since"
timed "sponsor + ts, limit 50, on the fingerprint"      "$bysponsor"
timed "sponsor + ts, limit 50, string equality only"    "$bysponsorplain"
timed "task_id, limit 100"                              "$bytask"
timed "decision = deny + ts, limit 1000"                "$denied"
timed "decision = deny + ts, without the partial index" "$denied" "DROP INDEX ix_audit_events_deny_ts_seq;"

echo
echo "=== the denial query's plan, on the partial index ==="
plan -c "EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) $denied;"

echo
echo "=== and without it ==="
plan -c "
BEGIN;
DROP INDEX ix_audit_events_deny_ts_seq;
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF) $denied;
ROLLBACK;"
