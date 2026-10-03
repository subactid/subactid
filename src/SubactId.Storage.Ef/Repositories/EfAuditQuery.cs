using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// The <see cref="IAuditQuery"/>. Each filter is written so that an index starts with it.
/// <list type="bullet">
/// <item>The sponsor filter uses <c>(sponsor, ts, seq)</c> and the agent filter
/// <c>(agent_id, ts, seq)</c>, or their fingerprint indexes on a provider that has them.</item>
/// <item>The denial filter uses the partial <c>(ts, seq) WHERE decision = 'deny'</c> index.</item>
/// <item>Otherwise the query uses <c>(ts, seq)</c>.</item>
/// </list>
/// Pages are read in index order without a sort. The cursor is a keyset over <c>(ts, seq)</c>.
/// </summary>
public sealed class EfAuditQuery(SubactIdDbContext db, IStorageDialect dialect) : IAuditQuery
{
    /// <inheritdoc />
    public async Task<IReadOnlyList<AuditLedgerRecord>> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(query.Limit, 0);

        return await Build(query).ToLedgerRecordsAsync(cancellationToken);
    }

    /// <summary>The ordered, bounded query for <paramref name="query"/>, before projection. Exposed so its plan can be examined.</summary>
    /// <param name="query">The query.</param>
    public IQueryable<AuditEventRow> Build(AuditQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);

        var rows = db.AuditEvents.AsNoTracking();
        if (query.Sponsor is { } sponsor)
        {
            rows = rows.Where(e => e.Sponsor == sponsor);
            if (dialect.LedgerFiltersAreFingerprinted)
            {
                // The column equality gives the exact answer. The fingerprint equality lets the
                // index be used.
                rows = rows.Where(e => AuditFingerprint.Of(e.Sponsor!) == AuditFingerprint.Of(sponsor));
            }
        }

        if (query.AgentId is { } agentId)
        {
            rows = rows.Where(e => e.AgentId == agentId);
            if (dialect.LedgerFiltersAreFingerprinted)
            {
                rows = rows.Where(e => AuditFingerprint.Of(e.AgentId!) == AuditFingerprint.Of(agentId));
            }
        }

        if (query.TaskId is { } taskId)
        {
            rows = rows.Where(e => e.TaskId == taskId);
        }

        if (query.From is { } from)
        {
            var fromUtc = from.ToUniversalTime();
            rows = rows.Where(e => e.Ts >= fromUtc);
        }

        if (query.To is { } to)
        {
            var toUtc = to.ToUniversalTime();
            rows = rows.Where(e => e.Ts < toUtc);
        }

        if (query.Decision is { } decision)
        {
            // A literal, not a parameter, so the planner can match the partial denial index.
            // The value is this server's own constant.
            var code = AuditDecisionCodes.ToCode(decision);
            rows = rows.Where(e => e.Decision == EF.Constant(code));
        }

        if (query.After is { } after)
        {
            // Keyset over (ts, seq). The plain lower bound keeps the index usable, the second clause breaks ties.
            var afterTs = after.Ts.ToUniversalTime();
            var afterSeq = after.Seq;
            rows = rows.Where(e => e.Ts >= afterTs && (e.Ts > afterTs || e.Seq > afterSeq));
        }

        return rows.OrderBy(e => e.Ts).ThenBy(e => e.Seq).Take(query.Limit);
    }
}
