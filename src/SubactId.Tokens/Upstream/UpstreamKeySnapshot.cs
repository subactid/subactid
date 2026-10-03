namespace SubactId.Tokens.Upstream;

/// <summary>The upstream issuer and its usable signing keys as of one fetch.</summary>
/// <param name="Issuer">The issuer string every upstream token must carry, verbatim.</param>
/// <param name="Keys">Usable keys by kid.</param>
/// <param name="FetchedAt">When the documents were fetched.</param>
public sealed record UpstreamKeySnapshot(string Issuer, IReadOnlyDictionary<string, UpstreamKey> Keys, DateTimeOffset FetchedAt);

/// <summary>Source of upstream keys for the validator.</summary>
public interface IUpstreamKeys
{
    /// <summary>
    /// The snapshot held now, or <c>null</c> before the first successful fetch. Never fetches or
    /// blocks, so it is safe for health probes. Its <see cref="UpstreamKeySnapshot.FetchedAt"/> is
    /// the last time the upstream answered.
    /// </summary>
    UpstreamKeySnapshot? Current { get; }

    /// <summary>The current snapshot, fetched or refreshed as needed.</summary>
    Task<UpstreamKeySnapshot> GetAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// A fresh snapshot because a token named an unknown kid, as after an upstream key rotation.
    /// Rate-limited.
    /// </summary>
    Task<UpstreamKeySnapshot> RefreshForUnknownKidAsync(CancellationToken cancellationToken = default);
}
