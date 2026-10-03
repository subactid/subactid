namespace SubactId.Core.Agents;

/// <summary>
/// Remembers the <c>jti</c> of every accepted client assertion until it expires, so the same
/// assertion cannot authenticate twice, from any instance of the control plane.
/// </summary>
public interface IAssertionReplayStore
{
    /// <summary>Records <paramref name="jti"/> for <paramref name="agentId"/>. Returns <c>false</c> if it was already recorded, which means a replay.</summary>
    Task<bool> TryRecordAsync(string agentId, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>Removes records that expired before <paramref name="now"/>. Returns the number removed.</summary>
    Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
}
