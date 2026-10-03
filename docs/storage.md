# Storage

Subact ID keeps its state in a relational database: the agent registry, tasks and their grants,
revocations, and the append-only audit ledger with the signed checkpoints that seal it.

There are two providers. Both share one implementation in `SubactId.Storage.Ef`; each provider
(`SubactId.Storage.Postgres`, `SubactId.Storage.Sqlite`) supplies only its engine-specific parts.

| | Postgres | Embedded (SQLite) |
|---|---|---|
| Use it for | any deployment | a trial, a demo, a single node |
| Setup | a server, a database, a role | a file path |
| Instances | as many as you like | one writer at a time |
| Configuration | `SubactId:Database:ConnectionString` | `SubactId:Database:Provider=sqlite` and `SubactId:Database:Path` |
| Versions | 16 or later | built into the server |

On Postgres, CI runs everything against 18, the current major version, and runs the integration
tests again on 16, the oldest supported one. Versions in between are not tested separately.

## Configuration

    SubactId__Database__Provider=postgres              # the default; postgres or sqlite
    SubactId__Database__ConnectionString=Host=...      # required for postgres
    SubactId__Database__MigrationConnectionString=...  # optional, postgres only: a role that may change the schema
    SubactId__Database__Path=/var/lib/subactid/subactid.db     # required for sqlite

Setting a value the chosen provider does not use is a startup error. See
[Configuration](configuration.md#database) for the full table.

## Migrations

Apply the schema with an explicit command. It never runs at startup.

    SubactId.Server migrate

It reads the same configuration as the server and applies that provider's migrations. For SQLite
it also creates the file and its directory if needed and turns on write-ahead logging.

Each provider has its own migrations because the schemas differ. Postgres stores lists as arrays
and partitions the audit ledger by month. SQLite stores lists as JSON text and timestamps as
fixed-width UTC strings, so they sort correctly. v0.1 starts from a single migration per
provider, so a database created by a build from before v0.1 cannot be upgraded: start a fresh one.

## The ledger's partitions

On Postgres the audit ledger is one table partitioned by calendar month. The ledger refuses
`UPDATE`, `DELETE` and `TRUNCATE`, so the only way to remove records is to detach a whole
month's partition. That is what [retention](#retention-taking-a-month-out-of-the-ledger) does.

**Partitions are created ahead, and there is no default partition.** `SubactId.Server migrate`
creates the current month plus `SubactId:Audit:Partitions:MonthsAhead` months after it (2 by
default). Each server tops this up at start and then hourly. Each extra partition adds planning
time to every `/audit` query, so keep the runway short; see [sizing](sizing.md#storage).

A record for a month with no partition is refused by the database. The audit record is written in
the same transaction as the action it records, so that action fails too. An instance whose
current month has no partition fails `/readyz`. It becomes ready again without a restart once the
partition exists.

**If the server's role cannot change the schema, run `migrate`.** Creating a partition requires
owning the ledger. If the server runs with a role that does not (see
`SubactId:Database:MigrationConnectionString`), its hourly top-up fails and logs it, and `doctor`
reports the shortfall. Run `SubactId.Server migrate` with the migration credentials to fix it. You
have as many months of warning as the runway is long.

**Every partition carries the append-only guard.** A `TRUNCATE` on a partition checks that
partition's privileges and triggers, not the parent's. The function that creates a partition
also revokes the privileges and attaches the trigger. `doctor` checks every partition for both,
including ones created by hand:

    ok  audit partitions  3 partition(s), all guarded, 2 month(s) ahead of this one.

A partition's indexes are named after the parent index plus the month, for example
`ix_audit_events_sponsor_fingerprint_ts_seq_202609`, so query plans and bloat reports show which
index they refer to.

## Retention: taking a month out of the ledger

No record is removed automatically. Records leave only when you run:

    SubactId.Server audit-archive --before 2026-07 --to /var/lib/subactid/archive

For each month before the cutoff, the command:

1. exports the month to a file,
2. reads the export back and checks it against the checkpoints that sealed it,
3. writes an `audit.archived` record to the ledger,
4. detaches and drops the partition, but only once it holds nothing the export does not.

A month that fails verification, or whose export does not read back, stops the run with nothing
detached. If `SubactId:Audit:Retention` is set, you can omit `--before`; the cutoff is then the month
containing `now - retention`. Retention must be at least 31 days. §7.5 of
[the spec](spec/v0.1.md) has the full order of operations and the export format.

Run the command on your own schedule, for example monthly from a timer. For how large the ledger
and the archive grow, see [sizing](sizing.md#storage).

**Store exports away from the database.** An export is one gzip file per month. Its SHA-256 is
in the `audit.archived` record that stays in the online ledger, so a changed or truncated export
is detectable.

- `SubactId.Server audit-verify --archive <export>` verifies one export against the published key set.
- `SubactId.Server audit-verify` verifies the online ledger, starting from the checkpoint after the
  last archived one and checking that it links to it.

Checkpoints are not removed with their records, so a `checkpoint_id:root` from an earlier run
still verifies after its month is archived.

**Keep every key that signed an archived checkpoint.** An export verifies only while the keys that
signed its checkpoints are published. See [Signing keys](keys.md#retired-keys-and-the-audit-ledger).

**Cold in place.** To keep old history queryable in SQL without the archive command, detach the
month's partition yourself and drop its query indexes, but keep the table. It stays readable by
name, and `/audit` does not return it. There is no command for this.

`audit_archives` holds one row per archived month. `/audit` reads `archived_before` from it, and
`audit-verify` reads where to start. It is an ordinary table with no guard; the tamper-evident
record is the `audit.archived` entry in the ledger.

## What the server removes on its own

Outside the ledger, a few tables are trimmed by the server as it runs, on every instance:

- finished tasks and their grants, `SubactId:Tasks:Retention` after they ended;
- used client assertion and signal identifiers, once they could no longer be replayed;
- sign-outs (the `revocations` rows a back-channel logout or a Shared Signals `session-revoked`
  writes), `SubactId:Revocations:SignOutRetention` after they were recorded. See
  [Revocation](revocation.md) for why that must be at least the identity provider's access-token
  lifetime.

Every other revocation, the agent registry, sponsor blocks and the order of Shared Signals events
are kept until somebody changes them. See [sizing](sizing.md#storage) for how each table grows.

## What the embedded provider gives up

Everything the spec requires still holds: tasks expire, revocation works, grants narrow, the
ledger is append-only and sealed by signed checkpoints, and denials are recorded. The limits are
operational:

- **Nothing leaves the ledger.** SQLite has no partitioning, so `audit-archive` refuses to run.
  The ledger grows for the life of the deployment.
- **One writer at a time.** Every transaction takes SQLite's single write lock when it opens. A
  second process on the same file stays correct but waits, and its request fails if it waits too
  long. Run one instance.
- **Local disk only.** Network filesystems such as NFS are not supported.
- **No failover.** Losing the host loses anything not backed up.
- **Back up with SQLite's backup API or `VACUUM INTO`.** Do not copy the file under a running
  server: with write-ahead logging the file alone may not be consistent.

Sealing is safe on both providers. A checkpoint must not seal a range that could still gain a
record. On Postgres every append holds a shared advisory lock until it commits, and the sealing
pass takes it exclusively. On SQLite the write lock gives the same guarantee.

Move to Postgres when you need more than one instance, a standby, or online backups. There is no
data migration between providers: start a fresh database and register agents again. Keep the old
SQLite file if you need its audit history.

## Checking which provider is running

`GET /readyz` runs a `database` check for the configured provider and an `audit-partition` check
that this month's records have a partition. When the embedded provider is in use, the server says
so in its startup log.
