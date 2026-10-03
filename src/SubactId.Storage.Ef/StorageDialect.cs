using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace SubactId.Storage.Ef;

/// <summary>
/// An append statement with the seal fence included, and how many result sets the fence adds
/// before the appended rows. A provider with no fence adds none.
/// </summary>
/// <param name="Sql">The command text to send.</param>
/// <param name="ResultSetsBefore">Result sets to step over before the appended rows.</param>
public sealed record FencedAppend(string Sql, int ResultSetsBefore);

/// <summary>
/// What differs between the databases Subact ID runs on. The schema, mapping and repositories are
/// shared by both providers. Each provider only supplies how its engine does these things.
/// </summary>
public interface IStorageDialect
{
    /// <summary>Applies the provider's own column mappings to the shared model, after the shared configuration and before naming.</summary>
    /// <param name="modelBuilder">The model being built.</param>
    void Configure(ModelBuilder modelBuilder);

    /// <summary>
    /// Whether the ledger indexes <c>sponsor</c> and <c>agent_id</c> by a fingerprint of the string.
    /// If so, a query filtering on either must compare the fingerprint as well as the column, or the
    /// index is not used. The column comparison keeps the answer exact.
    /// </summary>
    bool LedgerFiltersAreFingerprinted { get; }

    /// <summary>
    /// Begins the transaction a unit of work commits. A provider that serialises writers takes the
    /// write lock here.
    /// </summary>
    /// <param name="db">The context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<IDbContextTransaction> BeginTransactionAsync(SubactIdDbContext db, CancellationToken cancellationToken);

    /// <summary>
    /// The append statement with the seal fence taken in shared mode ahead of it, in the same round
    /// trip. Appends do not block each other. Each holds the fence from before its sequence number is
    /// allocated until commit, so the sealing pass knows nothing below its high-water mark is in flight.
    /// </summary>
    /// <param name="db">The context, inside the unit of work the append will run in.</param>
    /// <param name="insertSql">The <c>INSERT</c> the append would otherwise send on its own.</param>
    FencedAppend FenceAppend(SubactIdDbContext db, string insertSql);

    /// <summary>
    /// Takes the seal fence exclusively for the rest of the current transaction. It is granted once
    /// every in-flight append has committed, so every sequence number up to the ledger's maximum is
    /// committed afterwards.
    /// </summary>
    /// <param name="db">The context, inside a transaction.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LockAuditSealAsync(SubactIdDbContext db, CancellationToken cancellationToken);

    /// <summary>
    /// Locks one agent's row for the rest of the current transaction, so a read-modify-write of
    /// the registration is not interleaved with another. A second one waits for the first to
    /// commit and then reads what it wrote. Locking an agent that does not exist is not an error.
    /// </summary>
    /// <param name="db">The context, inside a unit of work.</param>
    /// <param name="agentId">The agent to lock.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LockAgentAsync(SubactIdDbContext db, string agentId, CancellationToken cancellationToken);

    /// <summary>
    /// Takes the locks of <paramref name="scopes"/> for the rest of the current transaction:
    /// shared by a unit of work that issues a task in them, exclusive by one that revokes
    /// everything in one of them. So a revocation waits for every issue already under way and
    /// then sees its task, and an issue that starts later waits for the revocation and then sees
    /// whatever it committed, such as a block. See <see cref="RevocationScope"/>.
    /// </summary>
    /// <param name="db">The context, inside a unit of work.</param>
    /// <param name="scopes">The scopes, from <see cref="RevocationScope"/>.</param>
    /// <param name="exclusive">Whether to take them exclusively, to revoke.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LockRevocationScopesAsync(SubactIdDbContext db, IReadOnlyCollection<string> scopes, bool exclusive, CancellationToken cancellationToken);

    /// <summary>
    /// Claims the right to seal for the rest of the current transaction, or returns <c>false</c>
    /// when another instance holds it. Held for a whole pass, separately from the fence.
    /// </summary>
    /// <param name="db">The context, inside a transaction.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> TryClaimAuditSealAsync(SubactIdDbContext db, CancellationToken cancellationToken);

    /// <summary>
    /// The value to pass for a timestamp parameter in hand-written SQL, in the form the provider
    /// stores. Every timestamp in hand-written SQL goes through here.
    /// </summary>
    /// <param name="value">The instant to store.</param>
    object Timestamp(DateTimeOffset value);

    /// <summary>
    /// The value to pass for a scope list parameter in hand-written SQL, in the form the provider
    /// stores, so a column can be compared with and set to it.
    /// </summary>
    /// <param name="values">The list to store.</param>
    object StringList(IReadOnlyList<string> values);

    /// <summary>Whether <paramref name="exception"/> is this provider's unique-constraint violation.</summary>
    /// <param name="exception">The exception a write threw.</param>
    bool IsUniqueViolation(Exception exception);

    /// <summary>Whether <paramref name="exception"/> is this provider's foreign-key violation.</summary>
    /// <param name="exception">The exception a write threw.</param>
    bool IsForeignKeyViolation(Exception exception);
}
