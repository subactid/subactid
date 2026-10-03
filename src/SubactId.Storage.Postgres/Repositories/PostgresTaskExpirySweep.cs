using Microsoft.EntityFrameworkCore;
using SubactId.Core.Delegation;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Postgres.Repositories;

/// <summary>
/// Postgres's expiry claim: one statement that selects due tasks with <c>SKIP LOCKED</c>, marks
/// them expired and returns them. No two sweepers return the same task.
/// </summary>
/// <param name="db">The context.</param>
public sealed class PostgresTaskExpirySweep(SubactIdDbContext db) : EfTaskExpirySweep(db)
{
    /// <inheritdoc />
    protected override async Task<IReadOnlyList<ExpiredTask>> ClaimDueAsync(DateTimeOffset at, int batchSize, CancellationToken cancellationToken)
    {
        var expired = await Db.Database.SqlQuery<ExpiredTaskProjection>($"""
            WITH due AS (
                SELECT task_id FROM tasks
                WHERE status = {TaskRow.StatusActive} AND expires_at <= {at}
                ORDER BY expires_at
                LIMIT {batchSize}
                FOR UPDATE SKIP LOCKED)
            UPDATE tasks AS t SET status = {TaskRow.StatusExpired}
            FROM due WHERE t.task_id = due.task_id
            RETURNING t.task_id AS "TaskId", t.agent_id AS "AgentId", t.sponsor AS "Sponsor", t.audience AS "Audience", t.scopes AS "Scopes", t.delegation_depth AS "DelegationDepth", t.expires_at AS "ExpiresAt"
            """).ToListAsync(cancellationToken);

        return expired.Select(e => new ExpiredTask(e.TaskId, e.AgentId, e.Sponsor, e.Audience, e.Scopes, e.DelegationDepth, e.ExpiresAt)).ToList();
    }

    /// <summary>Shape of the <c>RETURNING</c> clause; column aliases match these names.</summary>
    private sealed class ExpiredTaskProjection
    {
        public required string TaskId { get; init; }

        public required string AgentId { get; init; }

        public required string Sponsor { get; init; }

        public required string Audience { get; init; }

        public required string[] Scopes { get; init; }

        public int DelegationDepth { get; init; }

        public DateTimeOffset ExpiresAt { get; init; }
    }
}
