using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Npgsql;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Postgres;

/// <summary>
/// The Postgres dialect. Generated keys are identity-always columns, scope and audience lists are
/// native arrays, and the audit ledger is partitioned by month and keyed by <c>(seq, ts)</c>. The
/// ledger's sponsor and agent indexes are over a fingerprint. The seal fence and seal claim are
/// transaction-scoped advisory locks.
/// </summary>
public sealed class PostgresDialect : IStorageDialect
{
    /// <summary>
    /// Advisory lock key of the seal fence. Appends hold it shared. The sealing pass takes it
    /// exclusively for one query. The value is arbitrary but fixed: instances of different versions
    /// share a database during a rolling upgrade, and must take the same lock, so it never changes.
    /// </summary>
    public const long SealFenceKey = 0x4F4E4245_41554454;

    /// <summary>
    /// Advisory lock key of the seal claim. Held exclusively for a whole sealing pass, so only one
    /// instance seals at a time. Separate from the fence so appends are not blocked. Arbitrary but
    /// fixed, for the same reason as <see cref="SealFenceKey"/>.
    /// </summary>
    public const long SealClaimKey = 0x4F4E42455F53_45_41;

    /// <summary>
    /// The fence, taken shared, as a separate statement before the insert so the insert still binds
    /// against the column types. Npgsql sends both in one round trip.
    /// </summary>
    private static readonly string SharedFenceSql = $"SELECT pg_advisory_xact_lock_shared({SealFenceKey});\n";

    /// <inheritdoc />
    public void Configure(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        // Not reused after a rollback, so a failed append leaves a gap.
        modelBuilder.Entity<AuditEventRow>().Property(e => e.Seq).UseIdentityAlwaysColumn();

        // A unique constraint on a partitioned table must include the partition key, so the
        // primary key is (seq, ts). seq alone still identifies a record.
        modelBuilder.Entity<AuditEventRow>().HasKey(e => new { e.Seq, e.Ts });

        // The sponsor and agent indexes are over a four-byte fingerprint of the string, to keep
        // them small. EF cannot model an expression index, so the shared declarations are removed
        // here and the migration's SQL creates the fingerprint indexes.
        var ledger = modelBuilder.Entity<AuditEventRow>().Metadata;
        RemoveIndexOverTheString(ledger, nameof(AuditEventRow.Sponsor));
        RemoveIndexOverTheString(ledger, nameof(AuditEventRow.AgentId));

        // Both sides of the comparison use the database function the index uses, so the planner
        // can match them.
        modelBuilder.HasDbFunction(AuditFingerprint.Method).HasName("audit_events_fingerprint");

        modelBuilder.Entity<AuditOutboxRow>().Property(o => o.Id).UseIdentityAlwaysColumn();
        modelBuilder.Entity<TaskGrantRow>().Property(g => g.Id).UseIdentityAlwaysColumn();
        modelBuilder.Entity<RevocationRow>().Property(r => r.Id).UseIdentityAlwaysColumn();
    }

    /// <summary>The sponsor and agent indexes here are over a fingerprint, so a filter on either carries the fingerprint equality too.</summary>
    /// <inheritdoc />
    public bool LedgerFiltersAreFingerprinted => true;

    /// <inheritdoc />
    public async Task<IDbContextTransaction> BeginTransactionAsync(SubactIdDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        return await db.Database.BeginTransactionAsync(cancellationToken);
    }

    /// <inheritdoc />
    public FencedAppend FenceAppend(SubactIdDbContext db, string insertSql)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrWhiteSpace(insertSql);

        return new FencedAppend(SharedFenceSql + insertSql, ResultSetsBefore: 1);
    }

    /// <inheritdoc />
    public async Task LockAuditSealAsync(SubactIdDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({SealFenceKey})", cancellationToken);
    }

    /// <summary>A row lock, held to commit. Under read committed, the read after it sees the latest committed row.</summary>
    /// <inheritdoc />
    public async Task LockAgentAsync(SubactIdDbContext db, string agentId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrEmpty(agentId);

        await db.Database.ExecuteSqlAsync($"SELECT 1 FROM agents WHERE agent_id = {agentId} FOR UPDATE", cancellationToken);
    }

    /// <summary>
    /// Transaction-scoped advisory locks, one per scope, taken in key order so two units of work
    /// taking several never wait on each other in a cycle. Each is its own statement, so a
    /// statement after them reads with a snapshot taken once they are held.
    /// </summary>
    /// <inheritdoc />
    public async Task LockRevocationScopesAsync(SubactIdDbContext db, IReadOnlyCollection<string> scopes, bool exclusive, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(scopes);

        foreach (var key in scopes.Select(RevocationScope.LockKey).Distinct().Order())
        {
            if (exclusive)
            {
                await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock({key})", cancellationToken);
            }
            else
            {
                await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock_shared({key})", cancellationToken);
            }
        }
    }

    /// <inheritdoc />
    public async Task<bool> TryClaimAuditSealAsync(SubactIdDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        // Does not wait: if another pass holds the claim, this one skips.
        return await db.Database
            .SqlQuery<bool>($"""SELECT pg_try_advisory_xact_lock({SealClaimKey}) AS "Value" """)
            .SingleAsync(cancellationToken);
    }

    /// <summary>Postgres stores a timestamp as one, so the parameter is the instant itself.</summary>
    /// <inheritdoc />
    public object Timestamp(DateTimeOffset value) => value.ToUniversalTime();

    /// <summary>Postgres stores a list as a native array.</summary>
    /// <inheritdoc />
    public object StringList(IReadOnlyList<string> values) => values.ToArray();

    /// <inheritdoc />
    public bool IsUniqueViolation(Exception exception) => exception is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };

    /// <inheritdoc />
    /// <remarks>
    /// A delete blocked by an <c>ON DELETE RESTRICT</c> key reports <c>23503</c> before Postgres 18
    /// and <c>23001</c> (restrict_violation) from 18 on, so both are recognised.
    /// </remarks>
    public bool IsForeignKeyViolation(Exception exception) =>
        exception is PostgresException { SqlState: PostgresErrorCodes.ForeignKeyViolation or PostgresErrorCodes.RestrictViolation };

    /// <summary>
    /// Removes the shared schema's <c>(<paramref name="column"/>, ts, seq)</c> index from the model,
    /// since the migration creates a fingerprint index instead. Throws if the index is not found.
    /// </summary>
    private static void RemoveIndexOverTheString(IMutableEntityType ledger, string column)
    {
        var over = new[] { column, nameof(AuditEventRow.Ts), nameof(AuditEventRow.Seq) }
            .Select(name => ledger.FindProperty(name) ?? throw new InvalidOperationException($"The audit ledger has no {name} to index."))
            .ToList();

        var declared = ledger.FindIndex(over)
            ?? throw new InvalidOperationException($"The shared schema no longer declares an index on ({string.Join(", ", over.Select(p => p.Name))}); Postgres indexes a fingerprint of {column} in its place and needs to know which declaration that replaces.");

        ledger.RemoveIndex(declared);
    }
}
