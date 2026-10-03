using Microsoft.Extensions.Diagnostics.HealthChecks;
using SubactId.Server.Upstream;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Health;

/// <summary>
/// Readiness: the upstream identity provider's discovery document and JWKS have been fetched and
/// contain at least one usable signing key.
/// <para>
/// Unhealthy only until the first successful fetch. After that it keeps serving from cached keys
/// and reports <c>Degraded</c> (still a 200) once the last fetch is older than
/// <see cref="UpstreamKeyRefresher.StaleAfter"/>.
/// </para>
/// <para>
/// Reads what the refresher last fetched. It fetches itself only on a cold start.
/// </para>
/// </summary>
/// <param name="keys">The upstream keys.</param>
/// <param name="clock">Time source, for how old the last successful fetch is.</param>
public sealed class UpstreamJwksHealthCheck(IUpstreamKeys keys, TimeProvider clock) : IHealthCheck
{
    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        var snapshot = keys.Current;
        if (snapshot is null)
        {
            // Cold start: nothing fetched yet, so the probe fetches. Not ready until this succeeds.
            try
            {
                snapshot = await keys.GetAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is HttpRequestException or UpstreamDiscoveryException or TaskCanceledException)
            {
                return HealthCheckResult.Unhealthy("The upstream discovery document or JWKS could not be fetched.", exception);
            }
        }

        if (snapshot.Keys.Count == 0)
        {
            return HealthCheckResult.Unhealthy($"The upstream JWKS from '{snapshot.Issuer}' contains no usable signing key.");
        }

        var age = clock.GetUtcNow() - snapshot.FetchedAt;
        return age > UpstreamKeyRefresher.StaleAfter
            ? HealthCheckResult.Degraded(
                $"The upstream JWKS from '{snapshot.Issuer}' was last fetched {age.TotalMinutes:F0} minute(s) ago; the identity provider has stopped answering. Tokens signed with the {snapshot.Keys.Count} key(s) held are still accepted.")
            : HealthCheckResult.Healthy($"{snapshot.Keys.Count} upstream signing key(s) from '{snapshot.Issuer}'.");
    }
}
