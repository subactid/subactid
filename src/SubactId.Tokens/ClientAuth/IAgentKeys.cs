using SubactId.Core.Agents;

namespace SubactId.Tokens.ClientAuth;

/// <summary>Source of an agent's registered public keys.</summary>
public interface IAgentKeys
{
    /// <summary>The agent's keys from its registered JWKS URL, fetched or refreshed as needed.</summary>
    /// <exception cref="InvalidOperationException">The agent has no registered JWKS URL.</exception>
    Task<JwksSnapshot> GetAsync(Agent agent, CancellationToken cancellationToken = default);

    /// <summary>A fresh snapshot because an assertion named an unknown kid; rate-limited.</summary>
    Task<JwksSnapshot> RefreshForUnknownKidAsync(Agent agent, CancellationToken cancellationToken = default);
}
