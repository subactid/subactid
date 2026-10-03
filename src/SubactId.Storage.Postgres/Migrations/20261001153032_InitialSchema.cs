using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace SubactId.Storage.Postgres.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        // The v0.1 schema. Everything but the audit ledger is as the model declares it. The
        // ledger and its checkpoints are written here by hand, because EF cannot express what
        // makes them a ledger:
        //
        //   1. Append-only. UPDATE, DELETE and TRUNCATE are revoked from every role, this one
        //      included, and a trigger refuses them regardless of privileges.
        //   2. Partitioned by month on ts, so a month can be detached for retention. A unique
        //      constraint on a partitioned table must include the partition key, so the primary
        //      key is (seq, ts). The parent's TRUNCATE trigger and REVOKE do not cover a TRUNCATE
        //      naming a partition, so every partition carries its own guard, attached by the
        //      function that creates it. DETACH and DROP are DDL and no trigger stops them, so
        //      retention is an explicit, audited command.
        //   3. The sponsor and agent indexes are over a four-byte fingerprint of the string, to
        //      keep them small. The row still holds the string and queries still compare it, so
        //      a collision costs a row read and nothing else.
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "agents",
                columns: table => new
                {
                    agent_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    display_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    sponsor_required = table.Column<bool>(type: "boolean", nullable: false),
                    allowed_scopes = table.Column<string[]>(type: "text[]", nullable: false),
                    allowed_audiences = table.Column<string[]>(type: "text[]", nullable: false),
                    max_task_ttl = table.Column<TimeSpan>(type: "interval", nullable: false),
                    max_token_ttl = table.Column<TimeSpan>(type: "interval", nullable: false),
                    max_delegation_depth = table.Column<int>(type: "integer", nullable: false),
                    high_risk_audiences = table.Column<string[]>(type: "text[]", nullable: false),
                    jwks_uri = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    jwks = table.Column<string>(type: "character varying(16384)", maxLength: 16384, nullable: true),
                    enabled = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_agents", x => x.agent_id);
                    table.CheckConstraint("ck_agents_max_delegation_depth", "max_delegation_depth BETWEEN 1 AND 5");
                });

            migrationBuilder.CreateTable(
                name: "audit_archives",
                columns: table => new
                {
                    month = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    partition = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    first_checkpoint_id = table.Column<long>(type: "bigint", nullable: false),
                    last_checkpoint_id = table.Column<long>(type: "bigint", nullable: false),
                    first_seq = table.Column<long>(type: "bigint", nullable: false),
                    last_seq = table.Column<long>(type: "bigint", nullable: false),
                    records = table.Column<long>(type: "bigint", nullable: false),
                    location = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    digest = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    archived_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_archives", x => x.month);
                    table.CheckConstraint("ck_audit_archives_checkpoints", "first_checkpoint_id >= 1 AND last_checkpoint_id >= first_checkpoint_id - 1");
                    table.CheckConstraint("ck_audit_archives_records", "records >= 0");
                    table.CheckConstraint("ck_audit_archives_seqs", "first_seq >= 1 AND last_seq >= first_seq - 1");
                });

            migrationBuilder.CreateTable(
                name: "audit_checkpoints",
                columns: table => new
                {
                    checkpoint_id = table.Column<long>(type: "bigint", nullable: false),
                    first_seq = table.Column<long>(type: "bigint", nullable: false),
                    last_seq = table.Column<long>(type: "bigint", nullable: false),
                    tree_size = table.Column<long>(type: "bigint", nullable: false),
                    root_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    prev_checkpoint_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: true),
                    closed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    kid = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    signature = table.Column<byte[]>(type: "bytea", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_checkpoints", x => x.checkpoint_id);
                    table.CheckConstraint("ck_audit_checkpoints_range", "first_seq >= 1 AND first_seq <= last_seq");
                    table.CheckConstraint("ck_audit_checkpoints_tree_size", "tree_size >= 1");
                });

            migrationBuilder.CreateTable(
                name: "audit_outbox",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityAlwaysColumn),
                    audit_seq = table.Column<long>(type: "bigint", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    attempts = table.Column<int>(type: "integer", nullable: false),
                    last_error = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    next_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_outbox", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "revocations",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityAlwaysColumn),
                    jti = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    task_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    agent_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    sponsor_key = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    session_id = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    subject = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    issued_before = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    reason = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    revoked_by = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_revocations", x => x.id);
                    table.CheckConstraint("ck_revocations_target", "jti IS NOT NULL OR task_id IS NOT NULL OR agent_id IS NOT NULL OR sponsor_key IS NOT NULL OR session_id IS NOT NULL OR subject IS NOT NULL");
                });

            migrationBuilder.CreateTable(
                name: "scim_users",
                columns: table => new
                {
                    id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    user_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    external_id = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    sponsor_key = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    active = table.Column<bool>(type: "boolean", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scim_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "signal_replays",
                columns: table => new
                {
                    issuer = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    jti = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_signal_replays", x => new { x.issuer, x.jti });
                });

            migrationBuilder.CreateTable(
                name: "sponsor_blocks",
                columns: table => new
                {
                    sponsor_key = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    source = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    kind = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    blocked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    placed_by_deletion = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_sponsor_blocks", x => x.sponsor_key);
                    table.CheckConstraint("ck_sponsor_blocks_kind", "kind IN ('disabled', 'deleted')");
                    table.CheckConstraint("ck_sponsor_blocks_source", "source IN ('admin', 'poll', 'logout', 'scim', 'ssf')");
                });

            migrationBuilder.CreateTable(
                name: "ssf_signal_watermarks",
                columns: table => new
                {
                    sponsor_key = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    event_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_ssf_signal_watermarks", x => x.sponsor_key);
                });

            migrationBuilder.CreateTable(
                name: "assertion_replays",
                columns: table => new
                {
                    agent_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    jti = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_assertion_replays", x => new { x.agent_id, x.jti });
                    table.ForeignKey(
                        name: "fk_assertion_replays_agents_agent_id",
                        column: x => x.agent_id,
                        principalTable: "agents",
                        principalColumn: "agent_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "tasks",
                columns: table => new
                {
                    task_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    agent_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    sponsor = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    sponsor_key = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    session_id = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    parent_task_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    delegation_depth = table.Column<int>(type: "integer", nullable: false),
                    audience = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: false),
                    scopes = table.Column<string[]>(type: "text[]", nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revocation_reason = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_tasks", x => x.task_id);
                    table.CheckConstraint("ck_tasks_delegation_depth", "delegation_depth >= 1");
                    table.CheckConstraint("ck_tasks_status", "status IN ('active', 'expired', 'revoked')");
                    table.ForeignKey(
                        name: "fk_tasks_agents_agent_id",
                        column: x => x.agent_id,
                        principalTable: "agents",
                        principalColumn: "agent_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_tasks_tasks_parent_task_id",
                        column: x => x.parent_task_id,
                        principalTable: "tasks",
                        principalColumn: "task_id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "task_grants",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityAlwaysColumn),
                    grant_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    task_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    agent_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    scopes = table.Column<string[]>(type: "text[]", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    renewals = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_task_grants", x => x.id);
                    table.ForeignKey(
                        name: "fk_task_grants_agents_agent_id",
                        column: x => x.agent_id,
                        principalTable: "agents",
                        principalColumn: "agent_id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "fk_task_grants_tasks_task_id",
                        column: x => x.task_id,
                        principalTable: "tasks",
                        principalColumn: "task_id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_assertion_replays_expires_at",
                table: "assertion_replays",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_audit_checkpoints_last_seq",
                table: "audit_checkpoints",
                column: "last_seq",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_audit_outbox_audit_seq",
                table: "audit_outbox",
                column: "audit_seq",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_audit_outbox_next_attempt_at",
                table: "audit_outbox",
                column: "next_attempt_at");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_agent_id",
                table: "revocations",
                column: "agent_id");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_expires_at",
                table: "revocations",
                column: "expires_at",
                filter: "jti IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_jti",
                table: "revocations",
                column: "jti",
                unique: true,
                filter: "jti IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_session_id",
                table: "revocations",
                column: "session_id");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_sign_outs_revoked_at",
                table: "revocations",
                column: "revoked_at",
                filter: "session_id IS NOT NULL OR issued_before IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_sponsor_key",
                table: "revocations",
                column: "sponsor_key");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_subject",
                table: "revocations",
                column: "subject");

            migrationBuilder.CreateIndex(
                name: "ix_revocations_task_id",
                table: "revocations",
                column: "task_id");

            migrationBuilder.CreateIndex(
                name: "ix_scim_users_external_id",
                table: "scim_users",
                column: "external_id");

            migrationBuilder.CreateIndex(
                name: "ix_scim_users_sponsor_key",
                table: "scim_users",
                column: "sponsor_key");

            migrationBuilder.CreateIndex(
                name: "ix_scim_users_user_name",
                table: "scim_users",
                column: "user_name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_signal_replays_expires_at",
                table: "signal_replays",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ix_task_grants_agent_id",
                table: "task_grants",
                column: "agent_id");

            migrationBuilder.CreateIndex(
                name: "ix_task_grants_grant_hash",
                table: "task_grants",
                column: "grant_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_task_grants_task_id",
                table: "task_grants",
                column: "task_id");

            migrationBuilder.CreateIndex(
                name: "ix_tasks_agent_id",
                table: "tasks",
                column: "agent_id");

            migrationBuilder.CreateIndex(
                name: "ix_tasks_expires_at",
                table: "tasks",
                column: "expires_at",
                filter: "status = 'active'");

            migrationBuilder.CreateIndex(
                name: "ix_tasks_parent_task_id",
                table: "tasks",
                column: "parent_task_id");

            migrationBuilder.CreateIndex(
                name: "ix_tasks_session_id",
                table: "tasks",
                column: "session_id");

            migrationBuilder.CreateIndex(
                name: "ix_tasks_sponsor",
                table: "tasks",
                column: "sponsor");

            migrationBuilder.CreateIndex(
                name: "ix_tasks_sponsor_key",
                table: "tasks",
                column: "sponsor_key");

            migrationBuilder.Sql(
                """
                CREATE FUNCTION audit_events_append_only() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_events is append-only: % is not allowed', TG_OP
                        USING ERRCODE = 'raise_exception';
                END
                $$;
                """);

            // Renames each partition's cloned indexes to the parent index name plus the month.
            // A later migration that adds a ledger index must run this again over every partition.
            migrationBuilder.Sql(
                """
                CREATE FUNCTION audit_events_name_partition_indexes(p_partition regclass) RETURNS void
                LANGUAGE plpgsql AS $fn$
                DECLARE
                    suffix text := substring(p_partition::text from '[0-9]{6}$');
                    cloned record;
                BEGIN
                    -- A partition nobody here named is left alone: its indexes are not ours to
                    -- rename, and a name derived from one is not one we can promise is unique.
                    IF suffix IS NULL THEN
                        RETURN;
                    END IF;

                    FOR cloned IN
                        SELECT child.oid::regclass::text AS child_index,
                               parent_index.relname || '_' || suffix AS wanted
                        FROM pg_catalog.pg_index ix
                        JOIN pg_catalog.pg_class child ON child.oid = ix.indexrelid
                        JOIN pg_catalog.pg_inherits inh ON inh.inhrelid = ix.indexrelid
                        JOIN pg_catalog.pg_class parent_index ON parent_index.oid = inh.inhparent
                        WHERE ix.indrelid = p_partition::oid
                          -- An index a constraint owns is named by the constraint, so it keeps
                          -- the name Postgres gave it rather than being renamed out from under one.
                          AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conindid = ix.indexrelid)
                          AND child.relname <> parent_index.relname || '_' || suffix
                    LOOP
                        EXECUTE format('ALTER INDEX %s RENAME TO %I', cloned.child_index, cloned.wanted);
                    END LOOP;
                END
                $fn$;
                """);

            // The one way to create a partition, used by this migration, the top-up pass and
            // operators. It attaches the TRUNCATE trigger and revokes the privilege on the
            // partition itself, since a TRUNCATE naming the partition does not reach the parent.
            migrationBuilder.Sql(
                """
                CREATE FUNCTION audit_events_add_partition(p_month date) RETURNS boolean
                LANGUAGE plpgsql AS $fn$
                DECLARE
                    first_day      date        := date_trunc('month', p_month)::date;
                    partition_name text        := 'audit_events_p' || to_char(first_day, 'YYYYMM');
                    lower_bound    timestamptz := (to_char(first_day, 'YYYY-MM-DD') || ' 00:00:00+00')::timestamptz;
                    upper_bound    timestamptz := (to_char((first_day + INTERVAL '1 month')::date, 'YYYY-MM-DD') || ' 00:00:00+00')::timestamptz;
                BEGIN
                    -- Looked up before it is created, because the top-up pass calls this for a
                    -- year of months every hour and CREATE TABLE ... PARTITION OF locks the
                    -- parent. A month that is already there costs a catalogue lookup and no lock.
                    IF to_regclass(quote_ident(partition_name)) IS NOT NULL THEN
                        RETURN false;
                    END IF;

                    -- The bounds are built as UTC instants rather than as bare dates: a date cast
                    -- to timestamptz is read in the session's time zone, and a partition whose
                    -- edges moved by an offset would route a month's records into its neighbour.
                    --
                    -- The handler covers this one statement and nothing else, so a failure
                    -- anywhere below is raised rather than reported as a lost race.
                    BEGIN
                        EXECUTE format(
                            'CREATE TABLE %I PARTITION OF audit_events FOR VALUES FROM (%L) TO (%L)',
                            partition_name, lower_bound, upper_bound);
                    EXCEPTION
                        WHEN duplicate_table THEN
                            -- Another instance's pass got there first. CREATE TABLE waits on its
                            -- lock and fails only once that transaction has committed, so the
                            -- partition this one found already carries the guard attached
                            -- alongside it.
                            RETURN false;
                    END;

                    -- The guard, in the same statement block that created the partition. The row
                    -- trigger refusing UPDATE and DELETE is cloned from the parent by Postgres;
                    -- these two are not, and without them the partition is a hole in the one
                    -- property this table exists to have.
                    EXECUTE format(
                        'CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON %I '
                        'FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only()',
                        partition_name);
                    EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM PUBLIC, CURRENT_USER', partition_name);

                    -- Postgres clones the parent's indexes onto a new partition under names of
                    -- its own; these get the parent's name and this month back.
                    PERFORM audit_events_name_partition_indexes(to_regclass(quote_ident(partition_name)));
                    RETURN true;
                END
                $fn$;
                """);

            // Used by the index and by queries, so the fingerprint is computed one way only. md5
            // is immutable and stable across Postgres versions. IMMUTABLE, as index expressions
            // require. Not STRICT, so the planner can inline it and match the query to the
            // index. It already returns NULL for NULL.
            migrationBuilder.Sql(
                """
                CREATE FUNCTION audit_events_fingerprint(p_value text) RETURNS integer
                LANGUAGE sql IMMUTABLE PARALLEL SAFE AS
                $fn$ SELECT (('x' || substr(md5(p_value), 1, 8))::bit(32))::int $fn$;
                """);

            migrationBuilder.Sql(
                """
                CREATE TABLE audit_events (
                    seq bigint GENERATED ALWAYS AS IDENTITY NOT NULL,
                    ts timestamp with time zone NOT NULL,
                    event character varying(64) NOT NULL,
                    task_id character varying(64),
                    agent_id character varying(128),
                    sponsor character varying(256),
                    audience character varying(2048),
                    scope text,
                    jti character varying(64),
                    delegation_depth integer,
                    decision character varying(8),
                    reason character varying(256),
                    count integer,
                    detail character varying(2048),
                    CONSTRAINT pk_audit_events PRIMARY KEY (seq, ts),
                    CONSTRAINT ck_audit_events_decision CHECK (decision IS NULL OR decision IN ('allow', 'deny'))
                ) PARTITION BY RANGE (ts);
                """);

            // Created before any partition. Postgres clones row triggers to every partition, now
            // and later, so all are guarded against UPDATE and DELETE.
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_events_no_update_or_delete
                    BEFORE UPDATE OR DELETE ON audit_events
                    FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

                CREATE TRIGGER audit_events_no_truncate
                    BEFORE TRUNCATE ON audit_events
                    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();

                REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC, CURRENT_USER;
                """);

            // Declared on the parent, so Postgres builds them on every partition. The denial
            // index holds only denials. The fingerprint indexes are ordered (fingerprint, ts,
            // seq), so a page for one person needs no sort.
            migrationBuilder.Sql(
                """
                CREATE INDEX ix_audit_events_ts_seq ON audit_events (ts, seq);
                CREATE INDEX ix_audit_events_deny_ts_seq ON audit_events (ts, seq) WHERE decision = 'deny';
                CREATE INDEX ix_audit_events_task_id ON audit_events (task_id);
                CREATE INDEX ix_audit_events_jti ON audit_events (jti);
                CREATE INDEX ix_audit_events_sponsor_fingerprint_ts_seq ON audit_events (audit_events_fingerprint(sponsor), ts, seq);
                CREATE INDEX ix_audit_events_agent_id_fingerprint_ts_seq ON audit_events (audit_events_fingerprint(agent_id), ts, seq);
                """);

            // This month's partition. Later months (SubactId:Audit:Partitions:MonthsAhead) are
            // created by 'migrate' and the server. No default partition: an append into a month
            // without one fails.
            migrationBuilder.Sql("SELECT audit_events_add_partition((now() AT TIME ZONE 'UTC')::date);");

            // The same two guards the ledger has.
            migrationBuilder.Sql(
                """
                CREATE FUNCTION audit_checkpoints_append_only() RETURNS trigger
                LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_checkpoints is append-only: % is not allowed', TG_OP
                        USING ERRCODE = 'raise_exception';
                END
                $$;

                CREATE TRIGGER audit_checkpoints_no_update_or_delete
                    BEFORE UPDATE OR DELETE ON audit_checkpoints
                    FOR EACH ROW EXECUTE FUNCTION audit_checkpoints_append_only();

                CREATE TRIGGER audit_checkpoints_no_truncate
                    BEFORE TRUNCATE ON audit_checkpoints
                    FOR EACH STATEMENT EXECUTE FUNCTION audit_checkpoints_append_only();

                REVOKE UPDATE, DELETE, TRUNCATE ON audit_checkpoints FROM PUBLIC, CURRENT_USER;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "assertion_replays");

            migrationBuilder.DropTable(
                name: "audit_archives");

            migrationBuilder.DropTable(
                name: "audit_checkpoints");

            migrationBuilder.DropTable(
                name: "audit_events");

            migrationBuilder.DropTable(
                name: "audit_outbox");

            migrationBuilder.DropTable(
                name: "revocations");

            migrationBuilder.DropTable(
                name: "scim_users");

            migrationBuilder.DropTable(
                name: "signal_replays");

            migrationBuilder.DropTable(
                name: "sponsor_blocks");

            migrationBuilder.DropTable(
                name: "ssf_signal_watermarks");

            migrationBuilder.DropTable(
                name: "task_grants");

            migrationBuilder.DropTable(
                name: "tasks");

            migrationBuilder.DropTable(
                name: "agents");

            migrationBuilder.Sql(
                """
                DROP FUNCTION audit_checkpoints_append_only();
                DROP FUNCTION audit_events_add_partition(date);
                DROP FUNCTION audit_events_name_partition_indexes(regclass);
                DROP FUNCTION audit_events_fingerprint(text);
                DROP FUNCTION audit_events_append_only();
                """);
        }
    }
}
