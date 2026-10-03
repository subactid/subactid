using System.Collections.Concurrent;
using System.Net.Http;
using SubactId.Core.Agents;
using SubactId.Tokens.Upstream;

namespace SubactId.Tokens.ClientAuth;

/// <summary>
/// One <see cref="JwksCache"/> per agent, tied to the JWKS URL in its current registration.
/// When the URL changes, the old cache is dropped and keys come from the new URL.
/// <para>
/// Agents registered with inline keys are served from those. The parsed set is cached until
/// the registration changes.
/// </para>
/// </summary>
public sealed class AgentKeyCache(Func<HttpClient> clientFactory, TimeProvider clock) : IAgentKeys, IDisposable
{
    private readonly ConcurrentDictionary<string, JwksCache> caches = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, (string Json, JwksSnapshot Snapshot)> held = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task<JwksSnapshot> GetAsync(Agent agent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(agent);

        return agent.Jwks is not null
            ? Task.FromResult(Held(agent))
            : For(agent).GetAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<JwksSnapshot> RefreshForUnknownKidAsync(Agent agent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(agent);

        // Inline keys have no fresher source. An unknown kid means the key is not registered.
        return agent.Jwks is not null
            ? Task.FromResult(Held(agent))
            : For(agent).RefreshForUnknownKidAsync(cancellationToken);
    }

    private JwksSnapshot Held(Agent agent)
    {
        var json = agent.Jwks!.ToJson();
        if (held.TryGetValue(agent.AgentId, out var current) && current.Json == json)
        {
            return current.Snapshot;
        }

        var parsed = (json, new JwksSnapshot(UpstreamJwksParser.Parse(json), clock.GetUtcNow()));
        held[agent.AgentId] = parsed;
        return parsed.Item2;
    }

    private JwksCache For(Agent agent)
    {
        if (agent.JwksUri is not { } jwksUri)
        {
            throw new InvalidOperationException($"Agent '{agent.AgentId}' has no registered JWKS URL.");
        }

        while (true)
        {
            if (caches.TryGetValue(agent.AgentId, out var existing))
            {
                if (existing.JwksUri == jwksUri)
                {
                    return existing;
                }

                // Dropped, not disposed: a request may still be inside its refresh. The cache
                // holds only managed state, so the garbage collector reclaims it.
                caches.TryRemove(new KeyValuePair<string, JwksCache>(agent.AgentId, existing));
                continue;
            }

            var created = new JwksCache(clientFactory, jwksUri, clock);
            if (caches.TryAdd(agent.AgentId, created))
            {
                return created;
            }

            created.Dispose();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var cache in caches.Values)
        {
            cache.Dispose();
        }

        caches.Clear();
        held.Clear();
    }
}
