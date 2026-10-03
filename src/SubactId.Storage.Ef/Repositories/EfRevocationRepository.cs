using Microsoft.EntityFrameworkCore;
using SubactId.Core.Revocation;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>The <see cref="IRevocationRepository"/> over the <c>revocations</c> table.</summary>
public sealed class EfRevocationRepository(SubactIdDbContext db, IStorageDialect dialect) : IRevocationRepository
{
    /// <inheritdoc />
    public async Task<bool> AddAsync(Revocation revocation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(revocation);
        if ((revocation.Jti is null ? 0 : 1) + (revocation.TaskId is null ? 0 : 1) + (revocation.AgentId is null ? 0 : 1) + (revocation.SponsorKey is null ? 0 : 1) + (revocation.SessionId is null ? 0 : 1) + (revocation.Subject is null ? 0 : 1) != 1)
        {
            throw new ArgumentException("Exactly one of jti, task id, agent id, sponsor key, session id or subject must be set.", nameof(revocation));
        }

        if (revocation.IssuedBefore is not null && revocation.SponsorKey is null && revocation.Subject is null)
        {
            throw new ArgumentException("Only a revocation of a person signs them out.", nameof(revocation));
        }

        var at = dialect.Timestamp(revocation.RevokedAt);
        var expiresAt = revocation.ExpiresAt is { } expiry ? dialect.Timestamp(expiry) : null;
        var issuedBefore = revocation.IssuedBefore is { } floor ? dialect.Timestamp(floor) : null;
        var inserted = await db.Database.ExecuteSqlAsync(
            $"""
            INSERT INTO revocations (jti, task_id, agent_id, sponsor_key, session_id, subject, revoked_at, reason, revoked_by, expires_at, issued_before)
            VALUES ({revocation.Jti}, {revocation.TaskId}, {revocation.AgentId}, {revocation.SponsorKey}, {revocation.SessionId}, {revocation.Subject}, {at}, {revocation.Reason}, {revocation.RevokedBy}, {expiresAt}, {issuedBefore})
            ON CONFLICT (jti) WHERE jti IS NOT NULL DO NOTHING
            """,
            cancellationToken);
        return inserted == 1;
    }

    /// <inheritdoc />
    public async Task<Revocation?> FindTokenAsync(string jti, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(jti);

        var row = await db.Revocations.AsNoTracking().SingleOrDefaultAsync(r => r.Jti == jti, cancellationToken);
        return row is null ? null : new Revocation(row.Jti, row.TaskId, row.AgentId, row.SponsorKey, row.SessionId, row.RevokedAt, row.Reason, row.RevokedBy, row.ExpiresAt, row.Subject, row.IssuedBefore);
    }

    /// <inheritdoc />
    public Task<bool> IsSignedOutAsync(SignIn signIn, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        ArgumentException.ThrowIfNullOrEmpty(signIn.Subject);
        ArgumentException.ThrowIfNullOrEmpty(signIn.SponsorKey);

        var subject = signIn.Subject;
        var sponsorKey = signIn.SponsorKey;
        var sessionId = signIn.SessionId;
        var issuedAt = signIn.IssuedAt?.ToUniversalTime();

        // Only a logout writes a session row, and only a revocation that signs the person out sets
        // issued_before; an operator's kill switch by sponsor key does not, and is not matched.
        // Each branch is served by the index on its column.
        return db.Revocations.AsNoTracking().AnyAsync(
            r => (sessionId != null && r.SessionId == sessionId)
                || (r.IssuedBefore != null
                    && (r.Subject == subject || r.SponsorKey == sponsorKey)
                    && (issuedAt == null || r.IssuedBefore > issuedAt)),
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<int> PruneSignOutsAsync(DateTimeOffset before, int batchSize, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(batchSize, 0);

        // The predicate is the partial index's filter, so the scan reads only sign-outs, in
        // revoked_at order. The ids are read first because neither provider bounds a DELETE, and
        // the delete repeats the predicate, so it removes nothing else whatever those ids name.
        var cutoff = before.ToUniversalTime();
        var ids = await db.Revocations.AsNoTracking()
            .Where(r => (r.SessionId != null || r.IssuedBefore != null) && r.RevokedAt < cutoff)
            .OrderBy(r => r.RevokedAt)
            .Take(batchSize)
            .Select(r => r.Id)
            .ToArrayAsync(cancellationToken);
        if (ids.Length == 0)
        {
            return 0;
        }

        return await db.Revocations
            .Where(r => ids.Contains(r.Id) && (r.SessionId != null || r.IssuedBefore != null) && r.RevokedAt < cutoff)
            .ExecuteDeleteAsync(cancellationToken);
    }
}
