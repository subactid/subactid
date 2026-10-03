namespace SubactId.Core.Signals;

/// <summary>
/// Remembers the <c>jti</c> of every accepted external signal until it expires, so it cannot be
/// replayed on any instance. Keyed by issuer, since a signal has no agent to key on.
/// </summary>
public interface ISignalReplayStore
{
    /// <summary>
    /// Records <paramref name="jti"/> against <paramref name="issuer"/>. Returns <c>false</c> if
    /// it was already recorded, which means a replay. The same <c>jti</c> from two issuers is two signals.
    /// </summary>
    /// <param name="issuer">The issuer that signed the signal.</param>
    /// <param name="jti">The signal's <c>jti</c>.</param>
    /// <param name="expiresAt">When the record may be purged.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> TryRecordAsync(string issuer, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);

    /// <summary>Removes records that expired before <paramref name="now"/>. Returns the number removed.</summary>
    /// <param name="now">The current time.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default);
}
