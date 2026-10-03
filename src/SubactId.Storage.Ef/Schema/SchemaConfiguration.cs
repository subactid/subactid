using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// Tables, keys, constraints and indexes shared by both providers. Provider-specific mappings
/// (generated keys, arrays, JSON) are applied by the dialect.
/// </summary>
internal static class SchemaConfiguration
{
    public static void Configure(EntityTypeBuilder<AgentRow> agents)
    {
        agents.ToTable("agents");
        agents.HasKey(a => a.AgentId);
        agents.Property(a => a.AgentId).HasMaxLength(128);
        agents.Property(a => a.DisplayName).HasMaxLength(256);
        agents.Property(a => a.JwksUri).HasMaxLength(2048);

        // The whole key set as one JSON document. Bounded so the row cannot grow without limit.
        agents.Property(a => a.Jwks).HasMaxLength(16384);
        agents.ToTable(t => t.HasCheckConstraint("ck_agents_max_delegation_depth", "max_delegation_depth BETWEEN 1 AND 5"));
    }

    public static void Configure(EntityTypeBuilder<TaskRow> tasks)
    {
        tasks.ToTable("tasks");
        tasks.HasKey(t => t.TaskId);
        tasks.Property(t => t.TaskId).HasMaxLength(64);
        tasks.Property(t => t.AgentId).HasMaxLength(128);
        tasks.Property(t => t.Sponsor).HasMaxLength(256);
        tasks.Property(t => t.SponsorKey).HasMaxLength(256);
        tasks.Property(t => t.SessionId).HasMaxLength(256);
        tasks.Property(t => t.ParentTaskId).HasMaxLength(64);
        tasks.Property(t => t.Audience).HasMaxLength(2048);
        tasks.Property(t => t.Status).HasMaxLength(16);
        tasks.HasOne<AgentRow>().WithMany().HasForeignKey(t => t.AgentId).OnDelete(DeleteBehavior.Restrict);
        tasks.HasOne<TaskRow>().WithMany().HasForeignKey(t => t.ParentTaskId).OnDelete(DeleteBehavior.Restrict);
        tasks.HasIndex(t => t.AgentId);
        tasks.HasIndex(t => t.Sponsor);
        tasks.HasIndex(t => t.SponsorKey);
        tasks.HasIndex(t => t.SessionId);
        tasks.HasIndex(t => t.ParentTaskId);
        tasks.HasIndex(t => t.ExpiresAt).HasFilter("status = 'active'");
        tasks.ToTable(t =>
        {
            t.HasCheckConstraint("ck_tasks_status", "status IN ('active', 'expired', 'revoked')");
            t.HasCheckConstraint("ck_tasks_delegation_depth", "delegation_depth >= 1");
        });
    }

    public static void Configure(EntityTypeBuilder<SponsorBlockRow> sponsors)
    {
        sponsors.ToTable("sponsor_blocks");

        // One block per human. A block from a second source never replaces the first.
        sponsors.HasKey(s => s.SponsorKey);
        sponsors.Property(s => s.SponsorKey).HasMaxLength(256);
        sponsors.Property(s => s.Source).HasMaxLength(16);
        sponsors.Property(s => s.Kind).HasMaxLength(16);
        sponsors.ToTable(t =>
        {
            t.HasCheckConstraint("ck_sponsor_blocks_source", "source IN ('admin', 'poll', 'logout', 'scim', 'ssf')");
            t.HasCheckConstraint("ck_sponsor_blocks_kind", "kind IN ('disabled', 'deleted')");
        });
    }

    public static void Configure(EntityTypeBuilder<TaskGrantRow> grants)
    {
        grants.ToTable("task_grants");
        grants.HasKey(g => g.Id);
        grants.Property(g => g.Id).ValueGeneratedOnAdd();
        grants.Property(g => g.GrantHash).HasMaxLength(32);
        grants.Property(g => g.TaskId).HasMaxLength(64);
        grants.Property(g => g.AgentId).HasMaxLength(128);
        grants.HasOne<TaskRow>().WithMany().HasForeignKey(g => g.TaskId).OnDelete(DeleteBehavior.Cascade);
        grants.HasOne<AgentRow>().WithMany().HasForeignKey(g => g.AgentId).OnDelete(DeleteBehavior.Restrict);
        grants.HasIndex(g => g.GrantHash).IsUnique();
        grants.HasIndex(g => g.TaskId);
    }

    public static void Configure(EntityTypeBuilder<AuditEventRow> events)
    {
        events.ToTable("audit_events");
        events.HasKey(e => e.Seq);
        events.Property(e => e.Seq).ValueGeneratedOnAdd();
        events.Property(e => e.Event).HasMaxLength(64);
        events.Property(e => e.TaskId).HasMaxLength(64);
        events.Property(e => e.AgentId).HasMaxLength(128);
        events.Property(e => e.Sponsor).HasMaxLength(256);
        events.Property(e => e.Audience).HasMaxLength(2048);
        events.Property(e => e.Jti).HasMaxLength(64);
        events.Property(e => e.Decision).HasMaxLength(8);
        // Longer than other reason columns because an update's reason lists every changed field.
        // A reason that does not fit fails the audit write, and so the mutation.
        events.Property(e => e.Reason).HasMaxLength(256);
        // The archive command refuses a location long enough to push a record over this bound.
        events.Property(e => e.Detail).HasMaxLength(2048);
        // The audit query orders by (ts, seq), so a page for one sponsor or agent is one index range.
        // A provider with LedgerFiltersAreFingerprinted replaces the first two with fingerprint indexes.
        events.HasIndex(e => new { e.Sponsor, e.Ts, e.Seq });
        events.HasIndex(e => new { e.AgentId, e.Ts, e.Seq });
        events.HasIndex(e => new { e.Ts, e.Seq });
        // Partial index for the denial query. It is only used when the query's filter provably
        // implies it, so EfAuditQuery writes the decision as a literal, not a parameter.
        events.HasIndex(e => new { e.Ts, e.Seq }, "ix_audit_events_deny_ts_seq").HasFilter("decision = 'deny'");
        events.HasIndex(e => e.TaskId);
        events.HasIndex(e => e.Jti);
        events.ToTable(t => t.HasCheckConstraint("ck_audit_events_decision", "decision IS NULL OR decision IN ('allow', 'deny')"));

        // No check constraint on count: adding one in SQLite rebuilds the table, which drops the
        // append-only triggers. DenialAggregator only emits a positive count.
    }

    public static void Configure(EntityTypeBuilder<AuditCheckpointRow> checkpoints)
    {
        checkpoints.ToTable("audit_checkpoints");

        // The sealing pass allocates the id, since it is part of the signed bytes. The primary key
        // stops two instances from writing the same checkpoint.
        checkpoints.HasKey(c => c.CheckpointId);
        checkpoints.Property(c => c.CheckpointId).ValueGeneratedNever();
        checkpoints.Property(c => c.RootHash).HasMaxLength(32);
        checkpoints.Property(c => c.PrevCheckpointHash).HasMaxLength(32);
        checkpoints.Property(c => c.Kid).HasMaxLength(64);
        checkpoints.Property(c => c.Signature).HasMaxLength(64);

        // Finds the checkpoint covering a sequence number.
        checkpoints.HasIndex(c => c.LastSeq).IsUnique();

        checkpoints.ToTable(t =>
        {
            t.HasCheckConstraint("ck_audit_checkpoints_range", "first_seq >= 1 AND first_seq <= last_seq");
            t.HasCheckConstraint("ck_audit_checkpoints_tree_size", "tree_size >= 1");
        });
    }

    public static void Configure(EntityTypeBuilder<AuditArchiveRow> archives)
    {
        archives.ToTable("audit_archives");

        // One row per month. A month is archived once.
        archives.HasKey(a => a.Month);
        archives.Property(a => a.Partition).HasMaxLength(128);
        archives.Property(a => a.Location).HasMaxLength(2048);
        archives.Property(a => a.Digest).HasMaxLength(32);
        archives.ToTable(t =>
        {
            // An empty range is stored as last = first - 1.
            t.HasCheckConstraint("ck_audit_archives_checkpoints", "first_checkpoint_id >= 1 AND last_checkpoint_id >= first_checkpoint_id - 1");
            t.HasCheckConstraint("ck_audit_archives_seqs", "first_seq >= 1 AND last_seq >= first_seq - 1");
            t.HasCheckConstraint("ck_audit_archives_records", "records >= 0");
        });
    }

    public static void Configure(EntityTypeBuilder<AuditOutboxRow> outbox)
    {
        outbox.ToTable("audit_outbox");
        outbox.HasKey(o => o.Id);
        outbox.Property(o => o.Id).ValueGeneratedOnAdd();
        outbox.Property(o => o.LastError).HasMaxLength(1024);

        // No foreign key to the ledger: the check would need the UPDATE privilege the ledger revokes.
        // The ledger is append-only, so a queued sequence number always exists.
        outbox.HasIndex(o => o.AuditSeq).IsUnique();
        outbox.HasIndex(o => o.NextAttemptAt);
    }

    public static void Configure(EntityTypeBuilder<AssertionReplayRow> replays)
    {
        replays.ToTable("assertion_replays");
        replays.HasKey(r => new { r.AgentId, r.Jti });
        replays.Property(r => r.AgentId).HasMaxLength(128);
        replays.Property(r => r.Jti).HasMaxLength(256);
        replays.HasOne<AgentRow>().WithMany().HasForeignKey(r => r.AgentId).OnDelete(DeleteBehavior.Cascade);
        replays.HasIndex(r => r.ExpiresAt);
    }

    public static void Configure(EntityTypeBuilder<SignalWatermarkRow> watermarks)
    {
        watermarks.ToTable("ssf_signal_watermarks");

        // One row per human a transmitter has sent an account event about.
        watermarks.HasKey(w => w.SponsorKey);
        watermarks.Property(w => w.SponsorKey).HasMaxLength(256);
    }

    public static void Configure(EntityTypeBuilder<SignalReplayRow> replays)
    {
        replays.ToTable("signal_replays");

        // Keyed by issuer and jti: two issuers may mint the same jti. No foreign key, since issuers
        // have no row here.
        replays.HasKey(r => new { r.Issuer, r.Jti });
        replays.Property(r => r.Issuer).HasMaxLength(2048);
        replays.Property(r => r.Jti).HasMaxLength(256);
        replays.HasIndex(r => r.ExpiresAt);
    }

    public static void Configure(EntityTypeBuilder<ScimUserRow> users)
    {
        users.ToTable("scim_users");

        users.HasKey(u => u.Id);
        users.Property(u => u.Id).HasMaxLength(64);
        users.Property(u => u.UserName).HasMaxLength(256);
        users.Property(u => u.ExternalId).HasMaxLength(256);
        users.Property(u => u.SponsorKey).HasMaxLength(256);

        // SCIM requires userName to be unique. A duplicate is answered with a conflict.
        users.HasIndex(u => u.UserName).IsUnique();
        users.HasIndex(u => u.ExternalId);

        // Used by deactivation lookups. Not unique, so a misconfigured duplicate cannot stop a
        // deactivation from blocking the person.
        users.HasIndex(u => u.SponsorKey);
    }

    public static void Configure(EntityTypeBuilder<RevocationRow> revocations)
    {
        revocations.ToTable("revocations");
        revocations.HasKey(r => r.Id);
        revocations.Property(r => r.Id).ValueGeneratedOnAdd();
        revocations.Property(r => r.Jti).HasMaxLength(64);
        revocations.Property(r => r.TaskId).HasMaxLength(64);
        revocations.Property(r => r.AgentId).HasMaxLength(128);
        revocations.Property(r => r.SponsorKey).HasMaxLength(256);
        revocations.Property(r => r.SessionId).HasMaxLength(256);
        revocations.Property(r => r.Subject).HasMaxLength(256);
        revocations.Property(r => r.Reason).HasMaxLength(128);
        revocations.Property(r => r.RevokedBy).HasMaxLength(256);
        revocations.HasIndex(r => r.Jti).IsUnique().HasFilter("jti IS NOT NULL");
        revocations.HasIndex(r => r.TaskId);
        revocations.HasIndex(r => r.AgentId);
        revocations.HasIndex(r => r.SponsorKey);
        revocations.HasIndex(r => r.SessionId);
        revocations.HasIndex(r => r.Subject);
        revocations.HasIndex(r => r.ExpiresAt).HasFilter("jti IS NOT NULL");

        // The sign-outs an exchange reads, in the order they are pruned. Every other revocation
        // is kept, and is left out of the index.
        revocations.HasIndex(r => r.RevokedAt, "ix_revocations_sign_outs_revoked_at").HasFilter("session_id IS NOT NULL OR issued_before IS NOT NULL");
        revocations.ToTable(t => t.HasCheckConstraint(
            "ck_revocations_target",
            "jti IS NOT NULL OR task_id IS NOT NULL OR agent_id IS NOT NULL OR sponsor_key IS NOT NULL OR session_id IS NOT NULL OR subject IS NOT NULL"));
    }
}
