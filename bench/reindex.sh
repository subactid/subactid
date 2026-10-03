#!/usr/bin/env bash
# Measures index size and exchange cost on the ledger before and after REINDEX.
#
# Run it on a ledger that has been written to for a while, for example after `campaign.sh growth`.
#
# Three measurements: as written, rebuilt at the default fillfactor, and rebuilt at fillfactor 70.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

rate="${RATE:-150}"
duration="${DURATION:-30}"

psql() { docker compose exec -T postgres psql -U subactid -d subactid -qAt -v ON_ERROR_STOP=1 "$@"; }

# Summed over partitions, since the partitioned parent holds nothing.
indexes() {
  psql -c "
    SELECT coalesce(sum(pg_indexes_size(i.inhrelid)), pg_indexes_size(to_regclass('audit_events')))
    FROM pg_inherits i WHERE i.inhparent = to_regclass('audit_events');"
}
records() { psql -c "SELECT count(*) FROM audit_events;"; }

# The ledger's indexes. ALTER INDEX ... SET (fillfactor) is refused on the partitioned parent's index.
ledger_indexes() {
  psql -c "
    SELECT c.relname
    FROM pg_class c
    JOIN pg_index x ON x.indexrelid = c.oid
    WHERE c.relkind = 'i'
      AND (x.indrelid = to_regclass('audit_events')
           OR x.indrelid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = to_regclass('audit_events')));"
}

report() {
  local stage="$1" bytes="$2" baseline="$3" rows="$4"
  awk -v stage="$stage" -v b="$bytes" -v base="$baseline" -v rows="$rows" 'BEGIN {
    printf "%-28s %12.1f MB  %8.1f bytes/row", stage, b / 1048576, (rows > 0 ? b / rows : 0);
    if (base > 0 && b != base) printf "  %+6.1f%% against the starting size", (b - base) / base * 100;
    printf "\n";
  }'
}

rows="$(records)"
before="$(indexes)"
echo "ledger: $rows records"
report "as written" "$before" 0 "$rows"
./measure.sh reindex-as-written -- load --shape exchange --rate "$rate" --warmup 10 --duration "$duration"

echo
echo "== rebuilding at the default fillfactor =="
psql -c 'REINDEX TABLE audit_events;' >/dev/null
rebuilt="$(indexes)"
report "rebuilt, default fillfactor" "$rebuilt" "$before" "$rows"
./measure.sh reindex-default -- load --shape exchange --rate "$rate" --warmup 10 --duration "$duration"

echo
echo "== rebuilding at fillfactor 70 =="
for index in $(ledger_indexes); do
  psql -c "ALTER INDEX $index SET (fillfactor = 70);" >/dev/null
done
psql -c 'REINDEX TABLE audit_events;' >/dev/null
loose="$(indexes)"
report "rebuilt, fillfactor 70" "$loose" "$before" "$rows"
./measure.sh reindex-fillfactor70 -- load --shape exchange --rate "$rate" --warmup 10 --duration "$duration"

echo
echo "== putting the fillfactor back =="
for index in $(ledger_indexes); do
  psql -c "ALTER INDEX $index RESET (fillfactor);" >/dev/null
done
