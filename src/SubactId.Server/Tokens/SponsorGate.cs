using SubactId.Core.Sponsors;
using SubactId.Server.Contracts;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Tokens;

/// <summary>
/// Decides whether this control plane will still act for a human. Used by both exchange and refresh.
///
/// A local block always refuses. If an outbound check is configured, the identity provider is
/// also asked, and a person it does not confirm as active is refused.
///
/// With no outbound check, a human is treated as active unless blocked locally.
/// </summary>
public sealed class SponsorGate(ISponsorRepository blocks, ISponsorStatusSource? upstream = null)
{
    /// <summary>Audit reason when the human is disabled.</summary>
    public const string SponsorDisabled = "sponsor_disabled";

    /// <summary>Audit reason when the human no longer exists.</summary>
    public const string SponsorNotFound = "sponsor_not_found";

    /// <summary>Audit reason when the identity provider could not say whether the human is active.</summary>
    public const string SponsorStatusUnavailable = "sponsor_status_unavailable";

    /// <summary>
    /// The <c>maxAge</c> an exchange uses: a fresh answer that is not cached.
    /// </summary>
    public static readonly TimeSpan AsOfNow = TimeSpan.Zero;

    private readonly ISponsorRepository blocks = blocks ?? throw new ArgumentNullException(nameof(blocks));

    /// <summary>Whether the identity provider is asked (the <c>poll</c> mode).</summary>
    public bool AsksUpstream => upstream is not null;

    /// <summary>
    /// The status of one human. The block list is keyed by <paramref name="sponsorKey"/> and the
    /// identity provider is asked by <paramref name="subject"/>. A provider that cannot answer
    /// yields <see cref="SponsorStatus.Unavailable"/>, which is a refusal.
    /// </summary>
    /// <param name="sponsorKey">The human, as the configured key claim named them.</param>
    /// <param name="subject">The same human, as their upstream <c>sub</c>.</param>
    /// <param name="maxAge">Oldest outbound answer the caller can accept: the lifetime of the token it is about to issue.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<SponsorStatus> GetAsync(string sponsorKey, string subject, TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);
        ArgumentException.ThrowIfNullOrEmpty(subject);

        if (await blocks.FindAsync(sponsorKey, cancellationToken) is { } block)
        {
            return StatusOf(block);
        }

        return upstream is null ? SponsorStatus.Active : await upstream.GetAsync(subject, maxAge, cancellationToken);
    }

    /// <summary>The status a local block puts its human in.</summary>
    /// <param name="block">The block.</param>
    public static SponsorStatus StatusOf(SponsorBlock block)
    {
        ArgumentNullException.ThrowIfNull(block);

        return block.Kind == SponsorBlockKind.Deleted ? SponsorStatus.NotFound : SponsorStatus.Disabled;
    }

    /// <summary>
    /// The refusal <paramref name="status"/> calls for, or <c>null</c> when the human may be acted
    /// for. Shared by both grants.
    /// </summary>
    /// <param name="status">The status to answer.</param>
    public static (string Error, string Description, string Reason)? Refusal(SponsorStatus status) => status switch
    {
        SponsorStatus.Active => null,
        SponsorStatus.Disabled => (OAuthErrorResponse.AccessDenied, "The user this task acts for is disabled.", SponsorDisabled),
        SponsorStatus.NotFound => (OAuthErrorResponse.AccessDenied, "The user this task acts for no longer exists.", SponsorNotFound),
        _ => (OAuthErrorResponse.TemporarilyUnavailable, "The identity provider could not confirm the user is active; retry later.", SponsorStatusUnavailable),
    };
}
