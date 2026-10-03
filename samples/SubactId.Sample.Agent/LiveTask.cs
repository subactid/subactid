using System.Text.Json;

namespace SubactId.Sample.Agent;

/// <summary>
/// A task the portal started, as the agent holds it: the current token, the grant that renews it,
/// and its event log. The human's own token is not kept after the exchange.
/// </summary>
internal sealed class LiveTask
{
    private readonly Lock gate = new();
    private readonly List<TaskEvent> events = [];
    private TaskSession session;
    private long sequence;

    /// <summary>Records a task that has just been issued its first token.</summary>
    public LiveTask(string taskId, string kind, string agentId, string audience, string requestedScope, TaskSession session)
    {
        TaskId = taskId;
        Kind = kind;
        AgentId = agentId;
        Audience = audience;
        RequestedScope = requestedScope;
        this.session = session;
        StartedAt = DateTimeOffset.UtcNow;
        TokenExpiresAt = StartedAt.AddSeconds(session.ExpiresIn);
        LastWorkedAt = StartedAt;

        var claims = Jwt.Payload(session.AccessToken);
        Sponsor = Jwt.Claim(claims, "sub");
        Actor = claims.TryGetProperty("act", out var act) ? Jwt.Claim(act, "sub") : string.Empty;
    }

    /// <summary>The control plane's identifier for the task.</summary>
    public string TaskId { get; }

    /// <summary><c>short</c> or <c>long</c>.</summary>
    public string Kind { get; }

    /// <summary>The registration this task runs under.</summary>
    public string AgentId { get; }

    /// <summary>The tool server the task's tokens are for.</summary>
    public string Audience { get; }

    /// <summary>What was asked for at the exchange, which may be more than was granted.</summary>
    public string RequestedScope { get; }

    /// <summary>The human the task acts for: the <c>sub</c> of every token under it.</summary>
    public string Sponsor { get; }

    /// <summary>The agent, as it appears in <c>act.sub</c>.</summary>
    public string Actor { get; }

    /// <summary>When the task started.</summary>
    public DateTimeOffset StartedAt { get; }

    /// <summary>When the task itself runs out, whatever its tokens do.</summary>
    public DateTimeOffset TaskExpiresAt => session.TaskExpiresAt;

    /// <summary>When the token in hand runs out.</summary>
    public DateTimeOffset TokenExpiresAt { get; private set; }

    /// <summary>The token in hand.</summary>
    public string AccessToken => session.AccessToken;

    /// <summary>The task grant, which renews the token. Never widens it.</summary>
    public string Grant => session.Grant;

    /// <summary>The scope the task currently holds.</summary>
    public string Scope => session.Scope;

    /// <summary>How many times the token has been renewed under this one task.</summary>
    public int Refreshes { get; private set; }

    /// <summary>Whether the task is still live.</summary>
    public bool Running { get; private set; } = true;

    /// <summary>Why the task ended, once it has.</summary>
    public string? EndedReason { get; private set; }

    /// <summary>When a long task last did a piece of work.</summary>
    public DateTimeOffset LastWorkedAt { get; set; }

    /// <summary>Takes a freshly issued token as the current one.</summary>
    public void Adopt(TaskSession renewed)
    {
        lock (gate)
        {
            session = renewed;
            TokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(renewed.ExpiresIn);
            Refreshes++;
        }
    }

    /// <summary>Marks the task ended. The first reason is kept.</summary>
    public void End(string reason)
    {
        lock (gate)
        {
            if (!Running)
            {
                return;
            }

            Running = false;
            EndedReason = reason;
        }
    }

    /// <summary>Maximum number of log lines kept per task.</summary>
    private const int MaxEvents = 500;

    /// <summary>Adds a line to the task's log. Never a token, a grant or a key.</summary>
    public void Log(string level, string message, string? detail = null)
    {
        lock (gate)
        {
            events.Add(new TaskEvent(++sequence, DateTimeOffset.UtcNow, level, message, detail));
            if (events.Count > MaxEvents)
            {
                events.RemoveRange(0, events.Count - MaxEvents);
            }
        }
    }

    /// <summary>
    /// The task's state for the portal. Token claims are read unverified, for display only.
    /// </summary>
    public object Snapshot()
    {
        lock (gate)
        {
            var now = DateTimeOffset.UtcNow;
            return new
            {
                task_id = TaskId,
                kind = Kind,
                agent_id = AgentId,
                audience = Audience,
                sponsor = Sponsor,
                actor = Actor,
                requested_scope = RequestedScope,
                scope = Scope,
                running = Running,
                ended_reason = EndedReason,
                refreshes = Refreshes,
                started_at = StartedAt,
                task_expires_at = TaskExpiresAt,
                task_expires_in = (int)Math.Max(0, (TaskExpiresAt - now).TotalSeconds),
                token_expires_at = TokenExpiresAt,
                token_expires_in = (int)Math.Max(0, (TokenExpiresAt - now).TotalSeconds),
                token_claims = Claims(),
                events = events.Select(e => new { seq = e.Seq, at = e.At, level = e.Level, message = e.Message, detail = e.Detail }).ToArray(),
            };
        }
    }

    private object Claims()
    {
        var claims = Jwt.Payload(session.AccessToken);
        return new
        {
            iss = Jwt.Claim(claims, "iss"),
            sub = Jwt.Claim(claims, "sub"),
            aud = claims.TryGetProperty("aud", out var aud) && aud.ValueKind == JsonValueKind.String ? aud.GetString() : Audience,
            act = claims.TryGetProperty("act", out var act) ? Jwt.Claim(act, "sub") : string.Empty,
            scope = Jwt.Claim(claims, "scope"),
            jti = Jwt.Claim(claims, "jti"),
            task_id = Jwt.Claim(claims, "task_id"),
        };
    }
}

/// <summary>One line of a task's log.</summary>
/// <param name="Seq">Position in the task's log.</param>
/// <param name="At">When it happened.</param>
/// <param name="Level"><c>ok</c>, <c>deny</c> or <c>info</c>.</param>
/// <param name="Message">The one-line version.</param>
/// <param name="Detail">Optional explanation.</param>
internal sealed record TaskEvent(long Seq, DateTimeOffset At, string Level, string Message, string? Detail);
