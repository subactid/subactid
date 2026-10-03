using SubactId.Core.Revocation;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>The revocation fence, as the scope locks of <see cref="IStorageDialect.LockRevocationScopesAsync"/>.</summary>
/// <param name="db">The context, inside the unit of work that stores the task.</param>
public sealed class EfRevocationFence(SubactIdDbContext db) : IRevocationFence
{
    /// <inheritdoc />
    public Task EnterIssueAsync(string sponsorKey, string subject, string? sessionId, string agentId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);
        ArgumentException.ThrowIfNullOrEmpty(subject);
        ArgumentException.ThrowIfNullOrEmpty(agentId);

        List<string> scopes = [RevocationScope.Sponsor(sponsorKey), RevocationScope.Subject(subject), RevocationScope.Agent(agentId)];
        if (!string.IsNullOrEmpty(sessionId))
        {
            scopes.Add(RevocationScope.Session(sessionId));
        }

        return db.Dialect.LockRevocationScopesAsync(db, scopes, exclusive: false, cancellationToken);
    }
}
