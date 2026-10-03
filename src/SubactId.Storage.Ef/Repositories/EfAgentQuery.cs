using Microsoft.EntityFrameworkCore;
using SubactId.Core.Agents;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>Read-only registry questions, as one projected query each.</summary>
/// <param name="db">The context.</param>
public sealed class EfAgentQuery(SubactIdDbContext db) : IAgentQuery
{
    /// <inheritdoc />
    public async Task<TimeSpan?> LongestMaxTokenTtlAsync(CancellationToken cancellationToken = default)
    {
        // Loads one column only. The maximum is taken here because the providers store durations
        // differently, and a text duration does not order correctly under SQL's MAX.
        var ttls = await db.Agents
            .Select(a => a.MaxTokenTtl)
            .ToListAsync(cancellationToken);

        return ttls.Count == 0 ? null : ttls.Max();
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<Agent>> ListAsync(string? afterId, int limit, CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        // A keyset page on the primary key: the comparison and the order use the same collation,
        // so pages neither overlap nor skip whatever that collation is.
        var page = db.Agents.AsNoTracking();
        if (afterId is not null)
        {
            page = page.Where(a => a.AgentId.CompareTo(afterId) > 0);
        }

        var rows = await page.OrderBy(a => a.AgentId).Take(limit).ToListAsync(cancellationToken);
        return rows.Select(r => r.ToDomain()).ToList();
    }
}
