namespace SubactId.Tokens.Upstream;

/// <summary>Whether the human a task acts for is still active at the upstream identity provider.</summary>
public enum SponsorStatus
{
    /// <summary>The account exists and is enabled.</summary>
    Active,

    /// <summary>The account exists and is disabled.</summary>
    Disabled,

    /// <summary>No account with that subject exists any more.</summary>
    NotFound,

    /// <summary>The identity provider could not be asked. Never treated as active.</summary>
    Unavailable,
}

/// <summary>Source of a sponsor's status at the identity provider.</summary>
public interface ISponsorStatusSource
{
    /// <summary>The status of the account whose upstream <c>sub</c> is <paramref name="subject"/>.</summary>
    /// <param name="subject">The upstream subject identifier.</param>
    /// <param name="maxAge">Oldest answer the caller accepts, normally the lifetime of the token about to be issued.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SponsorStatus> GetAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default);
}

/// <summary>
/// A sponsor's status, and whether a missing answer was the provider failing as a whole.
/// </summary>
/// <param name="Status">The status, exactly as <see cref="ISponsorStatusSource.GetAsync"/> would give it.</param>
/// <param name="ProviderFailed">
/// <c>true</c> only for provider-wide failures: no connection, a timeout, a 5xx or 429, or no
/// service token. <c>false</c> for any answer the provider gave, even an unusable one.
/// </param>
public readonly record struct SponsorLookup(SponsorStatus Status, bool ProviderFailed);

/// <summary>A source of sponsor status that can also say whether its provider, rather than one answer, failed.</summary>
public interface ISponsorStatusProbe : ISponsorStatusSource
{
    /// <summary>As <see cref="ISponsorStatusSource.GetAsync"/>, and whether an <see cref="SponsorStatus.Unavailable"/> was the provider failing.</summary>
    /// <param name="subject">The upstream subject identifier.</param>
    /// <param name="maxAge">As for <see cref="ISponsorStatusSource.GetAsync"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<SponsorLookup> LookUpAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default);
}
