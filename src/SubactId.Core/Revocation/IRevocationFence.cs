namespace SubactId.Core.Revocation;

/// <summary>
/// Keeps a new task and a revocation by person, session or agent from passing each other. Without it,
/// an exchange that checked the person before a block or logout committed, and stored its task
/// after the revocation's walk, would leave that task live.
/// </summary>
public interface IRevocationFence
{
    /// <summary>
    /// Holds off any revocation of <paramref name="sponsorKey"/>, <paramref name="subject"/>,
    /// <paramref name="sessionId"/> or <paramref name="agentId"/> until the current unit of work commits, after waiting for one
    /// already under way. Called inside the unit of work that stores the task, before anything it
    /// must read fresh, such as whether the person is blocked.
    /// </summary>
    /// <param name="sponsorKey">The human, as the configured key claim names them.</param>
    /// <param name="subject">The same human, as their upstream <c>sub</c>.</param>
    /// <param name="sessionId">The identity provider session the task starts from, if any.</param>
    /// <param name="agentId">The agent the task is issued to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task EnterIssueAsync(string sponsorKey, string subject, string? sessionId, string agentId, CancellationToken cancellationToken = default);
}
