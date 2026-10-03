#!/usr/bin/env bash
# Reports table row counts and bytes per row, for the storage section of docs/sizing.md. Rows
# are counted exactly, after `VACUUM ANALYZE`.
#
# Ledger sizes are summed over partitions, since the partitioned parent reports zero.
#
#   ./storage-report.sh            print the report
#   ./storage-report.sh --raw      the same, without the ANALYZE (for a snapshot mid-run)

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

psql() { docker compose exec -T postgres psql -U subactid -d subactid -v ON_ERROR_STOP=1 "$@"; }

if [ "${1:-}" != "--raw" ]; then
  psql -q -c 'VACUUM (ANALYZE) audit_events, tasks, task_grants, assertion_replays;' >/dev/null
fi

echo "=== rows, and what each table costs per row ==="
psql -P pager=off -c "
WITH wanted(table_name) AS (
  VALUES ('audit_events'), ('tasks'), ('task_grants'), ('assertion_replays'),
         ('audit_outbox'), ('audit_checkpoints'), ('audit_archives')
),
rel AS (
  SELECT w.table_name, c.oid, c.relkind
  FROM wanted w
  JOIN pg_class c ON c.relname = w.table_name
  JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
),
-- A partitioned parent holds nothing itself; its leaves hold all of it.
sized AS (
  SELECT r.table_name,
         CASE WHEN r.relkind = 'p'
              THEN (SELECT coalesce(sum(pg_total_relation_size(i.inhrelid)), 0) FROM pg_inherits i WHERE i.inhparent = r.oid)
              ELSE pg_total_relation_size(r.oid) END AS total,
         CASE WHEN r.relkind = 'p'
              THEN (SELECT coalesce(sum(pg_relation_size(i.inhrelid)), 0) FROM pg_inherits i WHERE i.inhparent = r.oid)
              ELSE pg_relation_size(r.oid) END AS heap,
         CASE WHEN r.relkind = 'p'
              THEN (SELECT coalesce(sum(pg_indexes_size(i.inhrelid)), 0) FROM pg_inherits i WHERE i.inhparent = r.oid)
              ELSE pg_indexes_size(r.oid) END AS indexes
  FROM rel r
),
counted AS (
  SELECT 'audit_events'      AS table_name, count(*) AS rows FROM audit_events
  UNION ALL SELECT 'tasks',             count(*) FROM tasks
  UNION ALL SELECT 'task_grants',       count(*) FROM task_grants
  UNION ALL SELECT 'assertion_replays', count(*) FROM assertion_replays
  UNION ALL SELECT 'audit_outbox',      count(*) FROM audit_outbox
  UNION ALL SELECT 'audit_checkpoints', count(*) FROM audit_checkpoints
  UNION ALL SELECT 'audit_archives',    count(*) FROM audit_archives
)
SELECT s.table_name,
       c.rows,
       pg_size_pretty(s.total)   AS total,
       pg_size_pretty(s.heap)    AS heap,
       pg_size_pretty(s.indexes) AS indexes,
       CASE WHEN c.rows > 0 THEN round(s.total::numeric   / c.rows, 1) END AS bytes_per_row,
       CASE WHEN c.rows > 0 THEN round(s.heap::numeric    / c.rows, 1) END AS heap_per_row,
       CASE WHEN c.rows > 0 THEN round(s.indexes::numeric / c.rows, 1) END AS index_per_row
FROM sized s JOIN counted c USING (table_name)
ORDER BY s.total DESC;"

echo
echo "=== the ledger's indexes, largest first (summed over partitions) ==="
psql -P pager=off -c "
WITH ledger AS (SELECT count(*) AS rows FROM audit_events),
parent AS (
  SELECT c.oid, c.relname
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  WHERE c.relkind IN ('i', 'I')
    AND c.oid IN (SELECT indexrelid FROM pg_index WHERE indrelid = to_regclass('audit_events'))
),
sized AS (
  SELECT p.relname AS index_name,
         CASE WHEN EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhparent = p.oid)
              THEN (SELECT coalesce(sum(pg_relation_size(i.inhrelid)), 0) FROM pg_inherits i WHERE i.inhparent = p.oid)
              ELSE pg_relation_size(p.oid) END AS bytes
  FROM parent p
)
SELECT s.index_name,
       pg_size_pretty(s.bytes) AS size,
       round(100.0 * s.bytes / NULLIF(sum(s.bytes) OVER (), 0), 1) AS pct_of_indexes,
       round(s.bytes::numeric / NULLIF((SELECT rows FROM ledger), 0), 1) AS bytes_per_row
FROM sized s
ORDER BY s.bytes DESC;"

echo
echo "=== how the ledger is partitioned ==="
psql -P pager=off -c "
SELECT child.relname AS partition,
       (SELECT count(*) FROM pg_inherits WHERE inhparent = to_regclass('audit_events')) AS partitions,
       pg_size_pretty(pg_total_relation_size(child.oid)) AS total
FROM pg_inherits i
JOIN pg_class child ON child.oid = i.inhrelid
WHERE i.inhparent = to_regclass('audit_events')
ORDER BY child.relname;"

echo
echo "=== the months actually holding records ==="
# Only partitions with records. Empty future partitions are a fixed cost that distorts the
# per-row figure at small row counts.
psql -P pager=off -c "
WITH held AS (
  SELECT child.oid, child.relname,
         (SELECT count(*) FROM audit_events e
           WHERE e.ts >= (regexp_replace(child.relname, '^audit_events_p(\d{4})(\d{2})$', '\1-\2-01'))::timestamptz
             AND e.ts <  ((regexp_replace(child.relname, '^audit_events_p(\d{4})(\d{2})$', '\1-\2-01'))::timestamptz + interval '1 month')) AS rows
  FROM pg_inherits i
  JOIN pg_class child ON child.oid = i.inhrelid
  WHERE i.inhparent = to_regclass('audit_events')
)
SELECT relname AS partition,
       rows,
       pg_size_pretty(pg_total_relation_size(oid)) AS total,
       round(pg_total_relation_size(oid)::numeric / rows, 1) AS bytes_per_row,
       round(pg_relation_size(oid)::numeric / rows, 1) AS heap_per_row,
       round(pg_indexes_size(oid)::numeric / rows, 1) AS index_per_row
FROM held
WHERE rows > 0
ORDER BY relname;"

echo
echo "=== what the empty runway ahead costs ==="
psql -P pager=off -c "
WITH empty AS (
  SELECT child.oid
  FROM pg_inherits i
  JOIN pg_class child ON child.oid = i.inhrelid
  WHERE i.inhparent = to_regclass('audit_events')
    AND pg_total_relation_size(child.oid) <= 131072
)
SELECT count(*) AS empty_partitions,
       pg_size_pretty(coalesce(sum(pg_total_relation_size(oid)), 0)) AS total
FROM empty;"

echo
echo "=== what is in the ledger, by agent and event ==="
psql -P pager=off -c "
SELECT coalesce(agent_id, '(none)') AS agent, event, decision, count(*) AS records
FROM audit_events
GROUP BY 1, 2, 3
ORDER BY 1, 4 DESC;"

echo
echo "=== the seal ==="
psql -P pager=off -c "
SELECT count(*) AS checkpoints,
       min(first_seq) AS first_seq,
       max(last_seq) AS last_seq,
       round(avg(tree_size), 1) AS mean_records_per_checkpoint,
       (SELECT max(seq) FROM audit_events) AS highest_record,
       (SELECT count(*) FROM audit_events WHERE seq > coalesce((SELECT max(last_seq) FROM audit_checkpoints), 0)) AS records_not_yet_sealed
FROM audit_checkpoints;"
