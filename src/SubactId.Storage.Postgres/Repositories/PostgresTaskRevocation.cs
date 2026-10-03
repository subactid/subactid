using Microsoft.EntityFrameworkCore;
using SubactId.Core.Revocation;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Postgres.Repositories;

/// <summary>
/// Postgres's revocation walk: a recursive query over the task tree, revoked in one update. Only
/// active, unexpired tasks are touched, so a repeat call does nothing and expired tasks are left
/// to the sweeper. A task's depth in the walk decides its reason.
/// </summary>
/// <param name="db">The context.</param>
public sealed class PostgresTaskRevocation(SubactIdDbContext db) : EfTaskRevocation(db)
{
    /// <inheritdoc />
    protected override Task<IReadOnlyList<RevokedTaskRow>> RevokeTreeRowsAsync(string rootTaskId, DateTimeOffset at, string reason, CancellationToken cancellationToken) =>
        RevokeAsync(
            $"""
            WITH RECURSIVE tree AS (
                SELECT task_id, 0 AS level FROM tasks WHERE task_id = {rootTaskId}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            UPDATE tasks AS t SET status = {TaskRow.StatusRevoked}, revoked_at = {at}, revocation_reason = CASE WHEN tree.level = 0 THEN {reason} ELSE {ITaskRevocation.ParentRevoked} END
            FROM tree WHERE t.task_id = tree.task_id AND t.status = {TaskRow.StatusActive} AND t.expires_at > {at}
            RETURNING t.task_id AS "TaskId", t.agent_id AS "AgentId", t.sponsor AS "Sponsor", t.audience AS "Audience", t.scopes AS "Scopes", t.delegation_depth AS "DelegationDepth", t.parent_task_id AS "ParentTaskId", tree.level AS "Level"
            """,
            cancellationToken);

    /// <inheritdoc />
    protected override Task<IReadOnlyList<RevokedTaskRow>> RevokeAgentRowsAsync(string agentId, DateTimeOffset at, string reason, CancellationToken cancellationToken) =>
        RevokeAsync(
            $"""
            WITH RECURSIVE tree AS (
                SELECT task_id, 0 AS level FROM tasks WHERE agent_id = {agentId} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            UPDATE tasks AS t SET status = {TaskRow.StatusRevoked}, revoked_at = {at}, revocation_reason = CASE WHEN tree.level = 0 THEN {reason} ELSE {ITaskRevocation.ParentRevoked} END
            FROM (SELECT task_id, MIN(level) AS level FROM tree GROUP BY task_id) AS tree WHERE t.task_id = tree.task_id AND t.status = {TaskRow.StatusActive} AND t.expires_at > {at}
            RETURNING t.task_id AS "TaskId", t.agent_id AS "AgentId", t.sponsor AS "Sponsor", t.audience AS "Audience", t.scopes AS "Scopes", t.delegation_depth AS "DelegationDepth", t.parent_task_id AS "ParentTaskId", tree.level AS "Level"
            """,
            cancellationToken);

    /// <inheritdoc />
    protected override Task<IReadOnlyList<RevokedTaskRow>> RevokeSponsorRowsAsync(string sponsorKey, DateTimeOffset at, string reason, CancellationToken cancellationToken) =>
        RevokeAsync(
            $"""
            WITH RECURSIVE tree AS (
                SELECT task_id, 0 AS level FROM tasks WHERE sponsor_key = {sponsorKey} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            UPDATE tasks AS t SET status = {TaskRow.StatusRevoked}, revoked_at = {at}, revocation_reason = CASE WHEN tree.level = 0 THEN {reason} ELSE {ITaskRevocation.ParentRevoked} END
            FROM (SELECT task_id, MIN(level) AS level FROM tree GROUP BY task_id) AS tree WHERE t.task_id = tree.task_id AND t.status = {TaskRow.StatusActive} AND t.expires_at > {at}
            RETURNING t.task_id AS "TaskId", t.agent_id AS "AgentId", t.sponsor AS "Sponsor", t.audience AS "Audience", t.scopes AS "Scopes", t.delegation_depth AS "DelegationDepth", t.parent_task_id AS "ParentTaskId", tree.level AS "Level"
            """,
            cancellationToken);

    /// <inheritdoc />
    protected override Task<IReadOnlyList<RevokedTaskRow>> RevokeSubjectRowsAsync(string subject, DateTimeOffset at, string reason, CancellationToken cancellationToken) =>
        RevokeAsync(
            $"""
            WITH RECURSIVE tree AS (
                SELECT task_id, 0 AS level FROM tasks WHERE sponsor = {subject} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            UPDATE tasks AS t SET status = {TaskRow.StatusRevoked}, revoked_at = {at}, revocation_reason = CASE WHEN tree.level = 0 THEN {reason} ELSE {ITaskRevocation.ParentRevoked} END
            FROM (SELECT task_id, MIN(level) AS level FROM tree GROUP BY task_id) AS tree WHERE t.task_id = tree.task_id AND t.status = {TaskRow.StatusActive} AND t.expires_at > {at}
            RETURNING t.task_id AS "TaskId", t.agent_id AS "AgentId", t.sponsor AS "Sponsor", t.audience AS "Audience", t.scopes AS "Scopes", t.delegation_depth AS "DelegationDepth", t.parent_task_id AS "ParentTaskId", tree.level AS "Level"
            """,
            cancellationToken);

    /// <inheritdoc />
    protected override Task<IReadOnlyList<RevokedTaskRow>> RevokeSessionRowsAsync(string sessionId, DateTimeOffset at, string reason, CancellationToken cancellationToken) =>
        RevokeAsync(
            $"""
            WITH RECURSIVE tree AS (
                SELECT task_id, 0 AS level FROM tasks WHERE session_id = {sessionId} AND status = {TaskRow.StatusActive}
                UNION ALL
                SELECT t.task_id, tree.level + 1 FROM tasks t JOIN tree ON t.parent_task_id = tree.task_id)
            UPDATE tasks AS t SET status = {TaskRow.StatusRevoked}, revoked_at = {at}, revocation_reason = CASE WHEN tree.level = 0 THEN {reason} ELSE {ITaskRevocation.ParentRevoked} END
            FROM (SELECT task_id, MIN(level) AS level FROM tree GROUP BY task_id) AS tree WHERE t.task_id = tree.task_id AND t.status = {TaskRow.StatusActive} AND t.expires_at > {at}
            RETURNING t.task_id AS "TaskId", t.agent_id AS "AgentId", t.sponsor AS "Sponsor", t.audience AS "Audience", t.scopes AS "Scopes", t.delegation_depth AS "DelegationDepth", t.parent_task_id AS "ParentTaskId", tree.level AS "Level"
            """,
            cancellationToken);

    private async Task<IReadOnlyList<RevokedTaskRow>> RevokeAsync(FormattableString update, CancellationToken cancellationToken) =>
        await Db.Database.SqlQuery<RevokedTaskRow>(update).ToListAsync(cancellationToken);
}
