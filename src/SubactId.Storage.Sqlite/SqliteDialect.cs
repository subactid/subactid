using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Sqlite;

/// <summary>
/// The SQLite storage dialect. Lists are stored as JSON text. Timestamps are stored as fixed-width
/// UTC strings that sort in time order. The audit seal fence and seal claim use the database write
/// lock, which every unit of work takes up front with an immediate transaction.
/// </summary>
public sealed class SqliteDialect : IStorageDialect
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.General);

    /// <summary>
    /// Timestamps as <c>yyyy-MM-dd HH:mm:ss.fffffffZ</c> in UTC. Fixed width, so string order
    /// is time order. The expiry sweep, the outbox and ledger time ranges rely on this.
    /// </summary>
    private const string TimestampFormat = "yyyy-MM-dd HH:mm:ss.fffffff'Z'";

    private static readonly ValueConverter<DateTimeOffset, string> TimestampConverter = new(
        value => value.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture),
        text => DateTimeOffset.ParseExact(text, TimestampFormat, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal));

    /// <summary>The transactions this dialect began, so an append can tell whether it holds the write lock.</summary>
    private static readonly ConditionalWeakTable<DbTransaction, object> Immediate = new();

    private static readonly ValueComparer<string[]> StringArrayComparer = new(
        (left, right) => (left ?? Array.Empty<string>()).SequenceEqual(right ?? Array.Empty<string>(), StringComparer.Ordinal),
        value => value.Aggregate(0, (hash, item) => HashCode.Combine(hash, StringComparer.Ordinal.GetHashCode(item))),
        value => value.ToArray());

    /// <inheritdoc />
    public void Configure(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        // A list is one JSON array in one text column. Nothing queries inside these.
        StoreAsJson(modelBuilder.Entity<AgentRow>().Property(a => a.AllowedScopes));
        StoreAsJson(modelBuilder.Entity<AgentRow>().Property(a => a.AllowedAudiences));
        StoreAsJson(modelBuilder.Entity<AgentRow>().Property(a => a.HighRiskAudiences));
        StoreAsJson(modelBuilder.Entity<TaskRow>().Property(t => t.Scopes));
        StoreAsJson(modelBuilder.Entity<TaskGrantRow>().Property(g => g.Scopes));

        // Converts every timestamp in the model. A missed column would sort wrongly.
        foreach (var property in modelBuilder.Model.GetEntityTypes().SelectMany(entity => entity.GetProperties()))
        {
            if (property.ClrType == typeof(DateTimeOffset) || property.ClrType == typeof(DateTimeOffset?))
            {
                property.SetValueConverter(TimestampConverter);
                property.SetColumnType("TEXT");
            }
        }
    }

    /// <summary>
    /// Plain indexes over the strings themselves. SQLite has no immutable hash for an expression index.
    /// </summary>
    /// <inheritdoc />
    public bool LedgerFiltersAreFingerprinted => false;

    /// <summary>
    /// Begins an immediate transaction, which takes the write lock when it opens. Writers queue,
    /// so a unit of work that reads and then writes is not refused by a concurrent commit.
    /// </summary>
    /// <inheritdoc />
    public async Task<IDbContextTransaction> BeginTransactionAsync(SubactIdDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        var connection = (SqliteConnection)db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken);
        }

        var transaction = connection.BeginTransaction(IsolationLevel.Serializable, deferred: false);
        var scope = await db.Database.UseTransactionAsync(transaction, cancellationToken)
            ?? throw new InvalidOperationException("The context refused the transaction.");
        Immediate.AddOrUpdate(transaction, this);
        return new OwnedTransaction(scope, transaction);
    }

    /// <summary>
    /// Returns the statement unchanged. <see cref="BeginTransactionAsync"/> already holds the write
    /// lock, so an append cannot commit under a sealing pass's high-water mark.
    /// <para>
    /// Throws outside this dialect's own transaction, so a read-then-append unit of work fails
    /// clearly instead of with an intermittent busy error.
    /// </para>
    /// </summary>
    /// <inheritdoc />
    public FencedAppend FenceAppend(SubactIdDbContext db, string insertSql)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrWhiteSpace(insertSql);

        RequireWriteLock(db, "An append to the audit ledger must run inside a unit of work: on SQLite that is what takes the write lock every write of that unit of work needs.");
        return new FencedAppend(insertSql, ResultSetsBefore: 0);
    }

    /// <summary>
    /// No-op beyond a check: the pass's transaction already holds the write lock. Throws if it is
    /// not this dialect's immediate transaction.
    /// </summary>
    /// <inheritdoc />
    public Task LockAuditSealAsync(SubactIdDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        RequireWriteLock(db, "Reading the audit ledger's high-water mark must run inside a unit of work: on SQLite that is what takes the write lock the fence is made of.");
        return Task.CompletedTask;
    }

    /// <summary>
    /// No-op beyond a check: the unit of work's transaction already holds the write lock, so no
    /// other writer runs until it commits. Throws if it is not this dialect's immediate transaction.
    /// </summary>
    /// <inheritdoc />
    public Task LockAgentAsync(SubactIdDbContext db, string agentId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrEmpty(agentId);

        RequireWriteLock(db, "Locking an agent must run inside a unit of work: on SQLite that is what takes the write lock the row lock is made of.");
        return Task.CompletedTask;
    }

    /// <summary>
    /// No-op: a unit of work already holds the write lock from its first statement, so an issue
    /// and a revocation never overlap, and whichever runs second reads what the first committed.
    /// </summary>
    /// <inheritdoc />
    public Task LockRevocationScopesAsync(SubactIdDbContext db, IReadOnlyCollection<string> scopes, bool exclusive, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(scopes);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Always granted. The write lock held by the pass's transaction is the claim.
    /// </summary>
    /// <inheritdoc />
    public Task<bool> TryClaimAuditSealAsync(SubactIdDbContext db, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(db);

        RequireWriteLock(db, "Sealing the audit ledger must run inside a unit of work: on SQLite that is what takes the write lock the claim is made of.");
        return Task.FromResult(true);
    }

    /// <summary>Throws unless this dialect's own immediate transaction is open.</summary>
    private static void RequireWriteLock(SubactIdDbContext db, string message)
    {
        var transaction = db.Database.CurrentTransaction?.GetDbTransaction();
        if (transaction is null || !Immediate.TryGetValue(transaction, out _))
        {
            throw new InvalidOperationException(message);
        }
    }

    /// <summary>The same fixed-width UTC string the model stores.</summary>
    /// <inheritdoc />
    public object Timestamp(DateTimeOffset value) => value.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);

    /// <summary>The same JSON text the model stores for a list.</summary>
    /// <inheritdoc />
    public object StringList(IReadOnlyList<string> values) => JsonSerializer.Serialize(values.ToArray(), Json);

    /// <inheritdoc />
    public bool IsUniqueViolation(Exception exception) =>
        exception is SqliteException { SqliteExtendedErrorCode: SqliteUniqueViolation or SqlitePrimaryKeyViolation };

    /// <inheritdoc />
    public bool IsForeignKeyViolation(Exception exception) =>
        exception is SqliteException sqlite
        && (sqlite.SqliteExtendedErrorCode == SqliteForeignKeyViolation
            // A delete that would orphan a row reports the trigger code, as the ledger's
            // append-only guard does. The message tells them apart.
            || (sqlite.SqliteExtendedErrorCode == SqliteTriggerViolation
                && sqlite.Message.Contains("FOREIGN KEY constraint failed", StringComparison.Ordinal)));

    /// <summary>SQLITE_CONSTRAINT_UNIQUE.</summary>
    private const int SqliteUniqueViolation = 2067;

    /// <summary>SQLITE_CONSTRAINT_PRIMARYKEY.</summary>
    private const int SqlitePrimaryKeyViolation = 1555;

    /// <summary>SQLITE_CONSTRAINT_FOREIGNKEY.</summary>
    private const int SqliteForeignKeyViolation = 787;

    /// <summary>SQLITE_CONSTRAINT_TRIGGER, which a refused delete with dependants also reports.</summary>
    private const int SqliteTriggerViolation = 1811;

    private static void StoreAsJson(Microsoft.EntityFrameworkCore.Metadata.Builders.PropertyBuilder<string[]> property) =>
        property
            .HasConversion(
                value => JsonSerializer.Serialize(value, Json),
                text => JsonSerializer.Deserialize<string[]>(text, Json) ?? Array.Empty<string>(),
                StringArrayComparer)
            .HasColumnType("TEXT");

    /// <summary>
    /// The transaction the unit of work disposes. EF does not own a transaction it was handed,
    /// so this disposes it too.
    /// </summary>
    private sealed class OwnedTransaction(IDbContextTransaction scope, SqliteTransaction transaction) : IDbContextTransaction
    {
        public Guid TransactionId => scope.TransactionId;

        public void Commit() => scope.Commit();

        public Task CommitAsync(CancellationToken cancellationToken = default) => scope.CommitAsync(cancellationToken);

        public void Rollback() => scope.Rollback();

        public Task RollbackAsync(CancellationToken cancellationToken = default) => scope.RollbackAsync(cancellationToken);

        public void Dispose()
        {
            scope.Dispose();
            transaction.Dispose();
        }

        public async ValueTask DisposeAsync()
        {
            await scope.DisposeAsync();
            await transaction.DisposeAsync();
        }
    }
}
