using Microsoft.EntityFrameworkCore;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Ef;

/// <summary>
/// The control plane's database, shared by both providers. Migrations are applied by the explicit
/// <c>migrate</c> command, never at startup.
/// </summary>
public sealed class SubactIdDbContext(DbContextOptions<SubactIdDbContext> options, IStorageDialect dialect) : DbContext(options)
{
    /// <summary>The provider this context runs on.</summary>
    public IStorageDialect Dialect => dialect;

    /// <summary>Registered agents.</summary>
    public DbSet<AgentRow> Agents => Set<AgentRow>();

    /// <summary>Tasks.</summary>
    public DbSet<TaskRow> Tasks => Set<TaskRow>();

    /// <summary>Task grants, stored hashed.</summary>
    public DbSet<TaskGrantRow> TaskGrants => Set<TaskGrantRow>();

    /// <summary>The append-only audit ledger.</summary>
    public DbSet<AuditEventRow> AuditEvents => Set<AuditEventRow>();

    /// <summary>The signed checkpoints that seal the ledger.</summary>
    public DbSet<AuditCheckpointRow> AuditCheckpoints => Set<AuditCheckpointRow>();

    /// <summary>Months of the ledger that have been exported and removed.</summary>
    public DbSet<AuditArchiveRow> AuditArchives => Set<AuditArchiveRow>();

    /// <summary>Audit events awaiting delivery to an external sink.</summary>
    public DbSet<AuditOutboxRow> AuditOutbox => Set<AuditOutboxRow>();

    /// <summary>Explicit revocations.</summary>
    public DbSet<RevocationRow> Revocations => Set<RevocationRow>();

    /// <summary>Used client assertion identifiers, for replay protection.</summary>
    public DbSet<AssertionReplayRow> AssertionReplays => Set<AssertionReplayRow>();

    /// <summary>Humans this control plane refuses to act for.</summary>
    public DbSet<SponsorBlockRow> SponsorBlocks => Set<SponsorBlockRow>();

    /// <summary>The latest Shared Signals account event applied for each human, so a late one is not.</summary>
    public DbSet<SignalWatermarkRow> SignalWatermarks => Set<SignalWatermarkRow>();

    /// <summary>Identifiers of signals already accepted from outside, for replay protection.</summary>
    public DbSet<SignalReplayRow> SignalReplays => Set<SignalReplayRow>();

    /// <summary>User records a SCIM provisioning client created.</summary>
    public DbSet<ScimUserRow> ScimUsers => Set<ScimUserRow>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        SchemaConfiguration.Configure(modelBuilder.Entity<AgentRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<TaskRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<TaskGrantRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<AuditEventRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<AuditCheckpointRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<AuditArchiveRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<AuditOutboxRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<RevocationRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<AssertionReplayRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<SponsorBlockRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<SignalWatermarkRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<SignalReplayRow>());
        SchemaConfiguration.Configure(modelBuilder.Entity<ScimUserRow>());

        // Provider-specific mappings go after the shared ones, and naming goes last.
        dialect.Configure(modelBuilder);
        SnakeCaseNaming.Apply(modelBuilder);
    }
}
