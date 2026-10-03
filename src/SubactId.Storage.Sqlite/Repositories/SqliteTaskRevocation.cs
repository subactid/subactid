using Microsoft.EntityFrameworkCore;
using SubactId.Core.Revocation;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Sqlite.Repositories;

/// <summary>
/// SQLite's revocation walk. Walks the task tree, reads the live tasks (active and unexpired), then
/// revokes them. Named tasks get the caller's reason, and tasks below them get
/// <see cref="ITaskRevocation.ParentRevoked"/>. All of it runs in one transaction under the write lock.
/// </summary>
/// <param name="db">The context.</param>
public sealed class SqliteTaskRevocation(SubactIdDbContext db) : EfTaskRevocation(db)
{
    /// <inheritdoc />
    protected override async Task<IReadOnlyList<RevokedTaskRow>> RevokeTreeRowsAsync(string rootTaskId, DateTimeOffset at, string reason, CancellationToken cancellationToken)
    {
        var levels = await Db.Database.SqlQuery<TaskLevel>($"""
            WITH RECURSIVE tree(task_id, level) AS (
                SELECT task_id, 0 FROM tasks WHERE task_id = {rootTaskId}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            SELECT task_id AS "TaskId", MIN(level) AS "Level" FROM tree GROUP BY task_id
            """).ToListAsync(cancellationToken);
        return await FlipAsync(levels, at, reason, cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task<IReadOnlyList<RevokedTaskRow>> RevokeAgentRowsAsync(string agentId, DateTimeOffset at, string reason, CancellationToken cancellationToken)
    {
        var levels = await Db.Database.SqlQuery<TaskLevel>($"""
            WITH RECURSIVE tree(task_id, level) AS (
                SELECT task_id, 0 FROM tasks WHERE agent_id = {agentId} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            SELECT task_id AS "TaskId", MIN(level) AS "Level" FROM tree GROUP BY task_id
            """).ToListAsync(cancellationToken);
        return await FlipAsync(levels, at, reason, cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task<IReadOnlyList<RevokedTaskRow>> RevokeSponsorRowsAsync(string sponsorKey, DateTimeOffset at, string reason, CancellationToken cancellationToken)
    {
        var levels = await Db.Database.SqlQuery<TaskLevel>($"""
            WITH RECURSIVE tree(task_id, level) AS (
                SELECT task_id, 0 FROM tasks WHERE sponsor_key = {sponsorKey} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            SELECT task_id AS "TaskId", MIN(level) AS "Level" FROM tree GROUP BY task_id
            """).ToListAsync(cancellationToken);
        return await FlipAsync(levels, at, reason, cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task<IReadOnlyList<RevokedTaskRow>> RevokeSubjectRowsAsync(string subject, DateTimeOffset at, string reason, CancellationToken cancellationToken)
    {
        var levels = await Db.Database.SqlQuery<TaskLevel>($"""
            WITH RECURSIVE tree(task_id, level) AS (
                SELECT task_id, 0 FROM tasks WHERE sponsor = {subject} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            SELECT task_id AS "TaskId", MIN(level) AS "Level" FROM tree GROUP BY task_id
            """).ToListAsync(cancellationToken);
        return await FlipAsync(levels, at, reason, cancellationToken);
    }

    /// <inheritdoc />
    protected override async Task<IReadOnlyList<RevokedTaskRow>> RevokeSessionRowsAsync(string sessionId, DateTimeOffset at, string reason, CancellationToken cancellationToken)
    {
        var levels = await Db.Database.SqlQuery<TaskLevel>($"""
            WITH RECURSIVE tree(task_id, level) AS (
                SELECT task_id, 0 FROM tasks WHERE session_id = {sessionId} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            SELECT task_id AS "TaskId", MIN(level) AS "Level" FROM tree GROUP BY task_id
            """).ToListAsync(cancellationToken);
        return await FlipAsync(levels, at, reason, cancellationToken);
    }

    /// <summary>Reads the live tasks from the walk, revokes them by level, and returns them.</summary>
    private async Task<IReadOnlyList<RevokedTaskRow>> FlipAsync(IReadOnlyList<TaskLevel> levels, DateTimeOffset at, string reason, CancellationToken cancellationToken)
    {
        if (levels.Count == 0)
        {
            return [];
        }

        var level = levels.ToDictionary(l => l.TaskId, l => l.Level, StringComparer.Ordinal);
        var walked = level.Keys.ToArray();

        // Read before revoking, since revoked rows no longer match the filter.
        var live = await Db.Tasks.AsNoTracking()
            .Where(t => walked.Contains(t.TaskId) && t.Status == TaskRow.StatusActive && t.ExpiresAt > at)
            .Select(t => new RevokedTaskRow
            {
                TaskId = t.TaskId,
                AgentId = t.AgentId,
                Sponsor = t.Sponsor,
                Audience = t.Audience,
                Scopes = t.Scopes,
                DelegationDepth = t.DelegationDepth,
                ParentTaskId = t.ParentTaskId,
            })
            .ToListAsync(cancellationToken);
        if (live.Count == 0)
        {
            return [];
        }

        var named = live.Where(t => level[t.TaskId] == 0).Select(t => t.TaskId).ToArray();
        var below = live.Where(t => level[t.TaskId] > 0).Select(t => t.TaskId).ToArray();
        await FlipAsync(named, at, reason, cancellationToken);
        await FlipAsync(below, at, ITaskRevocation.ParentRevoked, cancellationToken);

        return live.Select(t => new RevokedTaskRow
        {
            TaskId = t.TaskId,
            AgentId = t.AgentId,
            Sponsor = t.Sponsor,
            Audience = t.Audience,
            Scopes = t.Scopes,
            DelegationDepth = t.DelegationDepth,
            ParentTaskId = t.ParentTaskId,
            Level = level[t.TaskId],
        }).ToList();
    }

    private async Task FlipAsync(string[] taskIds, DateTimeOffset at, string reason, CancellationToken cancellationToken)
    {
        if (taskIds.Length == 0)
        {
            return;
        }

        await Db.Tasks
            .Where(t => taskIds.Contains(t.TaskId) && t.Status == TaskRow.StatusActive && t.ExpiresAt > at)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(t => t.Status, TaskRow.StatusRevoked)
                    .SetProperty(t => t.RevokedAt, at)
                    .SetProperty(t => t.RevocationReason, reason),
                cancellationToken);
    }

    /// <summary>A task from the walk and its depth below the named task.</summary>
    private sealed class TaskLevel
    {
        public required string TaskId { get; init; }

        public int Level { get; init; }
    }
}
