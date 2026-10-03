using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SubactId.Storage.Sqlite.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "agents",
                columns: table => new
                {
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    display_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    sponsor_required = table.Column<bool>(type: "INTEGER", nullable: false),
                    allowed_scopes = table.Column<string>(type: "TEXT", nullable: false),
                    allowed_audiences = table.Column<string>(type: "TEXT", nullable: false),
                    max_task_ttl = table.Column<TimeSpan>(type: "TEXT", nullable: false),
                    max_token_ttl = table.Column<TimeSpan>(type: "TEXT", nullable: false),
                    max_delegation_depth = table.Column<int>(type: "INTEGER", nullable: false),
                    high_risk_audiences = table.Column<string>(type: "TEXT", nullable: false),
                    jwks_uri = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    jwks = table.Column<string>(type: "TEXT", maxLength: 16384, nullable: true),
                    enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    created_at = table.Column<string>(type: "TEXT", nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", nullable: false)
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
                    month = table.Column<string>(type: "TEXT", nullable: false),
                    partition = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    first_checkpoint_id = table.Column<long>(type: "INTEGER", nullable: false),
                    last_checkpoint_id = table.Column<long>(type: "INTEGER", nullable: false),
                    first_seq = table.Column<long>(type: "INTEGER", nullable: false),
                    last_seq = table.Column<long>(type: "INTEGER", nullable: false),
                    records = table.Column<long>(type: "INTEGER", nullable: false),
                    location = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    digest = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    archived_at = table.Column<string>(type: "TEXT", nullable: false)
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
                    checkpoint_id = table.Column<long>(type: "INTEGER", nullable: false),
                    first_seq = table.Column<long>(type: "INTEGER", nullable: false),
                    last_seq = table.Column<long>(type: "INTEGER", nullable: false),
                    tree_size = table.Column<long>(type: "INTEGER", nullable: false),
                    root_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    prev_checkpoint_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: true),
                    closed_at = table.Column<string>(type: "TEXT", nullable: false),
                    kid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    signature = table.Column<byte[]>(type: "BLOB", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_checkpoints", x => x.checkpoint_id);
                    table.CheckConstraint("ck_audit_checkpoints_range", "first_seq >= 1 AND first_seq <= last_seq");
                    table.CheckConstraint("ck_audit_checkpoints_tree_size", "tree_size >= 1");
                });

            migrationBuilder.CreateTable(
                name: "audit_events",
                columns: table => new
                {
                    seq = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ts = table.Column<string>(type: "TEXT", nullable: false),
                    @event = table.Column<string>(name: "event", type: "TEXT", maxLength: 64, nullable: false),
                    task_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    sponsor = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    audience = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    scope = table.Column<string>(type: "TEXT", nullable: true),
                    jti = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    delegation_depth = table.Column<int>(type: "INTEGER", nullable: true),
                    decision = table.Column<string>(type: "TEXT", maxLength: 8, nullable: true),
                    reason = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    count = table.Column<int>(type: "INTEGER", nullable: true),
                    detail = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_events", x => x.seq);
                    table.CheckConstraint("ck_audit_events_decision", "decision IS NULL OR decision IN ('allow', 'deny')");
                });

            migrationBuilder.CreateTable(
                name: "audit_outbox",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    audit_seq = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<string>(type: "TEXT", nullable: false),
                    attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    last_error = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    next_attempt_at = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_audit_outbox", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "revocations",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    jti = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    task_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    sponsor_key = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    session_id = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    subject = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    issued_before = table.Column<string>(type: "TEXT", nullable: true),
                    revoked_at = table.Column<string>(type: "TEXT", nullable: false),
                    reason = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    revoked_by = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    expires_at = table.Column<string>(type: "TEXT", nullable: true)
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
                    id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    user_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    external_id = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    sponsor_key = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    active = table.Column<bool>(type: "INTEGER", nullable: false),
                    created_at = table.Column<string>(type: "TEXT", nullable: false),
                    updated_at = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scim_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "signal_replays",
                columns: table => new
                {
                    issuer = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    jti = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_signal_replays", x => new { x.issuer, x.jti });
                });

            migrationBuilder.CreateTable(
                name: "sponsor_blocks",
                columns: table => new
                {
                    sponsor_key = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    source = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    kind = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    blocked_at = table.Column<string>(type: "TEXT", nullable: false),
                    placed_by_deletion = table.Column<bool>(type: "INTEGER", nullable: false)
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
                    sponsor_key = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    event_at = table.Column<string>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_ssf_signal_watermarks", x => x.sponsor_key);
                });

            migrationBuilder.CreateTable(
                name: "assertion_replays",
                columns: table => new
                {
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    jti = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", nullable: false)
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
                    task_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    sponsor = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    sponsor_key = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    session_id = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    parent_task_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    delegation_depth = table.Column<int>(type: "INTEGER", nullable: false),
                    audience = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    scopes = table.Column<string>(type: "TEXT", nullable: false),
                    status = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    created_at = table.Column<string>(type: "TEXT", nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", nullable: false),
                    revoked_at = table.Column<string>(type: "TEXT", nullable: true),
                    revocation_reason = table.Column<string>(type: "TEXT", nullable: true)
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
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    grant_hash = table.Column<byte[]>(type: "BLOB", maxLength: 32, nullable: false),
                    task_id = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    agent_id = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    scopes = table.Column<string>(type: "TEXT", nullable: false),
                    created_at = table.Column<string>(type: "TEXT", nullable: false),
                    expires_at = table.Column<string>(type: "TEXT", nullable: false),
                    revoked_at = table.Column<string>(type: "TEXT", nullable: true),
                    last_used_at = table.Column<string>(type: "TEXT", nullable: true),
                    renewals = table.Column<int>(type: "INTEGER", nullable: false)
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
                name: "ix_audit_events_agent_id_ts_seq",
                table: "audit_events",
                columns: new[] { "agent_id", "ts", "seq" });

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_deny_ts_seq",
                table: "audit_events",
                columns: new[] { "ts", "seq" },
                filter: "decision = 'deny'");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_jti",
                table: "audit_events",
                column: "jti");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_sponsor_ts_seq",
                table: "audit_events",
                columns: new[] { "sponsor", "ts", "seq" });

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_task_id",
                table: "audit_events",
                column: "task_id");

            migrationBuilder.CreateIndex(
                name: "ix_audit_events_ts_seq",
                table: "audit_events",
                columns: new[] { "ts", "seq" });

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

            // The audit ledger and its checkpoints are append-only. SQLite has no privileges to
            // revoke, so these triggers are the only guard. They refuse every UPDATE and DELETE,
            // including a bare DELETE FROM.
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_events_no_update
                    BEFORE UPDATE ON audit_events
                    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only: UPDATE is not allowed'); END
                """);
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_events_no_delete
                    BEFORE DELETE ON audit_events
                    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only: DELETE is not allowed'); END
                """);
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_checkpoints_no_update
                    BEFORE UPDATE ON audit_checkpoints
                    BEGIN SELECT RAISE(ABORT, 'audit_checkpoints is append-only: UPDATE is not allowed'); END
                """);
            migrationBuilder.Sql(
                """
                CREATE TRIGGER audit_checkpoints_no_delete
                    BEFORE DELETE ON audit_checkpoints
                    BEGIN SELECT RAISE(ABORT, 'audit_checkpoints is append-only: DELETE is not allowed'); END
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS audit_checkpoints_no_delete");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS audit_checkpoints_no_update");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS audit_events_no_delete");
            migrationBuilder.Sql("DROP TRIGGER IF EXISTS audit_events_no_update");

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
        }
    }
}
