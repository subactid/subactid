namespace SubactId.Tokens.Upstream;

/// <summary>
/// Stops asking an identity provider that has stopped answering, for a few seconds at a time.
/// </summary>
/// <remarks>
/// <para>
/// After <see cref="FailuresToOpen"/> consecutive provider failures, answers
/// <see cref="SponsorStatus.Unavailable"/> immediately for <see cref="OpenFor"/>, then lets one
/// request through to probe.
/// </para>
/// <para>
/// Only provider-wide failures count (<see cref="SponsorLookup.ProviderFailed"/>). An unusable
/// answer about one person does not open the circuit or keep it open.
/// </para>
/// <para>
/// The only answer it gives on its own is <see cref="SponsorStatus.Unavailable"/>, a refusal.
/// Everything else is passed through unchanged, so it never allows what the provider would refuse.
/// </para>
/// <para>
/// The open period uses the monotonic clock.
/// </para>
/// </remarks>
public sealed class SponsorStatusCircuit(ISponsorStatusProbe inner, TimeProvider clock) : ISponsorStatusSource
{
    /// <summary>Consecutive provider failures that open the circuit.</summary>
    public const int FailuresToOpen = 5;

    /// <summary>How long the circuit stays open before one request is let through.</summary>
    public static readonly TimeSpan OpenFor = TimeSpan.FromSeconds(5);

    private readonly ISponsorStatusProbe inner = inner ?? throw new ArgumentNullException(nameof(inner));
    private readonly TimeProvider clock = clock ?? throw new ArgumentNullException(nameof(clock));
    private readonly Lock gate = new();
    private int failures;
    private long? openedAt;
    private bool probing;

    /// <summary>Whether the circuit is open, refusing without asking the provider.</summary>
    public bool IsOpen
    {
        get
        {
            lock (gate)
            {
                return openedAt is not null;
            }
        }
    }

    /// <inheritdoc />
    public async Task<SponsorStatus> GetAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        var probe = false;
        lock (gate)
        {
            if (openedAt is { } opened)
            {
                // Open: refuse until the time is up, then let one probe through. Others are
                // refused until the probe returns.
                if (clock.GetElapsedTime(opened) < OpenFor || probing)
                {
                    return SponsorStatus.Unavailable;
                }

                probing = true;
                probe = true;
            }
        }

        SponsorLookup lookup;
        try
        {
            lookup = await inner.LookUpAsync(subject, maxAge, cancellationToken);
        }
        catch
        {
            // Caller cancellation says nothing about the provider. Let the next caller probe.
            if (probe)
            {
                lock (gate)
                {
                    probing = false;
                }
            }

            throw;
        }

        lock (gate)
        {
            if (probe)
            {
                probing = false;
            }

            if (lookup.ProviderFailed)
            {
                failures++;
                if (probe || failures >= FailuresToOpen)
                {
                    openedAt = clock.GetTimestamp();
                }
            }
            else
            {
                // The provider answered, so it is up.
                failures = 0;
                openedAt = null;
            }
        }

        return lookup.Status;
    }
}
