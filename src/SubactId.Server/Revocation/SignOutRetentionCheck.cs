using SubactId.Server.Configuration;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Revocation;

/// <summary>
/// Warns, once per process, when a subject token presented for an exchange lives longer than
/// <c>SubactId:Revocations:SignOutRetention</c>. The identity provider's access-token lifetime is
/// not published, so the tokens are the only place it can be read. A sign-out is removed after the
/// retention period, and a token it signed out that is still valid then is no longer refused, so
/// the retention must cover the longest lifetime. This only reports it; nothing is refused here.
/// </summary>
public sealed class SignOutRetentionCheck(SubactIdOptions options, ILogger<SignOutRetentionCheck> logger)
{
    private int warned;

    /// <summary>
    /// Compares a validated subject token's lifetime, with the clock skew it is allowed past its
    /// <c>exp</c>, against the retention, and logs the first one found longer. Logs durations only.
    /// </summary>
    /// <param name="issuedAt">
    /// The token's <c>iat</c>, if it carries one. Without it, the time it has left from
    /// <paramref name="now"/> is compared instead: a sign-out recorded now would be gone before it.
    /// </param>
    /// <param name="expiresAt">The token's <c>exp</c>.</param>
    /// <param name="now">The time of the exchange.</param>
    /// <returns>Whether this token outlives the retention.</returns>
    public bool Observe(DateTimeOffset? issuedAt, DateTimeOffset expiresAt, DateTimeOffset now)
    {
        var lifetime = expiresAt - (issuedAt ?? now) + UpstreamTokenValidator.ClockSkew;
        var retention = options.Revocations.SignOutRetention;
        if (lifetime <= retention)
        {
            return false;
        }

        if (Interlocked.Exchange(ref warned, 1) == 0)
        {
            logger.LogWarning(
                "A subject token is valid for {Lifetime} including clock skew, longer than SubactId:Revocations:SignOutRetention ({Retention}). A sign-out is removed after that period, so a token it signed out could start a task until the token expires. Set the retention to at least the identity provider's longest access-token lifetime.",
                lifetime,
                retention);
        }

        return true;
    }
}
