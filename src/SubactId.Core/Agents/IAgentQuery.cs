namespace SubactId.Core.Agents;

/// <summary>Read-only questions about the registry, each answered by one query.</summary>
public interface IAgentQuery
{
    /// <summary>
    /// The largest <c>max_token_ttl</c> of any registered agent, or <c>null</c> when none is
    /// registered. Decides how long a retired signing key stays published. Disabled agents
    /// count, because tokens they were already issued stay valid.
    /// </summary>
    Task<TimeSpan?> LongestMaxTokenTtlAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Up to <paramref name="limit"/> agents whose id comes after <paramref name="afterId"/>, in
    /// id order; from the first when <paramref name="afterId"/> is <c>null</c>. One page of the
    /// registry, never all of it.
    /// </summary>
    Task<IReadOnlyList<Agent>> ListAsync(string? afterId, int limit, CancellationToken cancellationToken = default);
}
