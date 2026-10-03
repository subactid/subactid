using SubactId.Server.Hosting;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Upstream;

/// <summary>
/// Fetches the upstream identity provider's discovery document and JWKS on a timer, so an
/// outage is detected and new keys are picked up without waiting for a request.
/// <para>
/// An outage is logged once when it starts and once when it ends. Nothing about a token or a
/// person is logged.
/// </para>
/// <para>
/// The first pass runs one interval after start. The cold-start fetch is left to the first
/// caller, such as the readiness probe.
/// </para>
/// </summary>
/// <param name="keys">The cache to refresh.</param>
/// <param name="clock">The clock the timer runs on.</param>
/// <param name="logger">Where the outage is reported.</param>
public sealed class UpstreamKeyRefresher(UpstreamKeyCache keys, TimeProvider clock, ILogger<UpstreamKeyRefresher> logger)
    : PeriodicBackgroundService(RefreshInterval, clock, logger)
{
    /// <summary>How often the upstream is re-fetched.</summary>
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How old the last successful fetch may be before readiness reports the upstream degraded.
    /// Three intervals, so one missed pass is not reported.
    /// </summary>
    public static readonly TimeSpan StaleAfter = RefreshInterval * 3;

    private bool failing;

    /// <inheritdoc />
    protected override string PassName => "Upstream key refresh";

    /// <inheritdoc />
    protected override async Task RunPassAsync(CancellationToken cancellationToken)
    {
        if (await keys.TryRefreshAsync(cancellationToken))
        {
            if (failing)
            {
                failing = false;
                Logger.LogInformation("The identity provider is answering again and its keys have been refreshed.");
            }

            return;
        }

        if (!failing)
        {
            failing = true;
            Logger.LogWarning(
                "The identity provider stopped answering. The keys last fetched are still being served, so tokens signed with them are still accepted, but a key rotation will not be picked up and refreshes that need the provider will be refused. Retrying every {Interval}.",
                RefreshInterval);
        }
    }
}
