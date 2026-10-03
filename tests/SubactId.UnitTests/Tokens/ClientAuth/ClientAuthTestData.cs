using System.Net;
using System.Text;
using SubactId.Core.Agents;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Tokens.Upstream;

namespace SubactId.UnitTests.Tokens.ClientAuth;

/// <summary>In-memory stand-ins for the registry, an agent's published keys and the replay store.</summary>
internal static class ClientAuthTestData
{
    public const string SubactIdIssuer = "https://subactid.internal.example.com";
    public const string TokenEndpoint = SubactIdIssuer + "/oauth2/token";

    public static Agent Agent(string id = "jira-triage", bool enabled = true, Uri? jwks = null, bool noJwks = false) => new(
        id, "Agent " + id, true, ["jira:read"], ["https://jira.internal"], TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(5), 2, [],
        noJwks ? null : jwks ?? new Uri($"https://{id}.example/jwks.json"), null, enabled, UpstreamTestData.Now.AddDays(-1), UpstreamTestData.Now.AddDays(-1));

    public static JwksSnapshot Snapshot(string jwks) => new(UpstreamJwksParser.Parse(jwks), UpstreamTestData.Now);

    /// <summary>Claims for a valid assertion at <see cref="UpstreamTestData.Now"/>.</summary>
    public static Dictionary<string, object?> Assertion(string agentId = "jira-triage", params (string Key, object? Value)[] overrides)
    {
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = agentId,
            ["sub"] = agentId,
            ["aud"] = TokenEndpoint,
            ["exp"] = UpstreamTestData.Now.AddMinutes(2).ToUnixTimeSeconds(),
            ["iat"] = UpstreamTestData.Now.ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        };
        foreach (var (key, value) in overrides)
        {
            if (value is null && key.StartsWith('-')) claims.Remove(key[1..]);
            else claims[key] = value;
        }

        return claims;
    }
}

internal sealed class InMemoryAgentRepository : IAgentRepository
{
    private readonly Dictionary<string, Agent> agents = new(StringComparer.Ordinal);

    public InMemoryAgentRepository(params Agent[] seed)
    {
        foreach (var agent in seed) agents[agent.AgentId] = agent;
    }

    public Task<Agent?> FindAsync(string agentId, CancellationToken cancellationToken = default) => Task.FromResult(agents.GetValueOrDefault(agentId));

    public Task<Agent?> FindForUpdateAsync(string agentId, CancellationToken cancellationToken = default) => FindAsync(agentId, cancellationToken);

    public Task AddAsync(Agent agent, CancellationToken cancellationToken = default) { agents[agent.AgentId] = agent; return Task.CompletedTask; }

    public Task<bool> UpdateAsync(Agent agent, CancellationToken cancellationToken = default) { var found = agents.ContainsKey(agent.AgentId); if (found) agents[agent.AgentId] = agent; return Task.FromResult(found); }

    public Task<bool> DeleteAsync(string agentId, CancellationToken cancellationToken = default) => Task.FromResult(agents.Remove(agentId));
}

internal sealed class StaticAgentKeys(JwksSnapshot current, JwksSnapshot? afterRefresh = null, Exception? failure = null) : IAgentKeys
{
    public int Gets { get; private set; }

    public int Refreshes { get; private set; }

    public List<string> AgentsAsked { get; } = [];

    public Task<JwksSnapshot> GetAsync(Agent agent, CancellationToken cancellationToken = default)
    {
        Gets++;
        AgentsAsked.Add(agent.AgentId);
        return failure is null ? Task.FromResult(current) : Task.FromException<JwksSnapshot>(failure);
    }

    public Task<JwksSnapshot> RefreshForUnknownKidAsync(Agent agent, CancellationToken cancellationToken = default)
    {
        Refreshes++;
        return Task.FromResult(afterRefresh ?? current);
    }
}

internal sealed class InMemoryReplayStore : IAssertionReplayStore
{
    public Dictionary<(string AgentId, string Jti), DateTimeOffset> Recorded { get; } = [];

    public int Purges { get; private set; }

    public Task<bool> TryRecordAsync(string agentId, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default) =>
        Task.FromResult(Recorded.TryAdd((agentId, jti), expiresAt));

    public Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        Purges++;
        var expired = Recorded.Where(r => r.Value < now).Select(r => r.Key).ToList();
        foreach (var key in expired) Recorded.Remove(key);
        return Task.FromResult(expired.Count);
    }
}

/// <summary>An in-memory https server: URL to body, with status overrides and request counts.</summary>
internal sealed class FakeJsonServer : HttpMessageHandler
{
    private readonly Dictionary<string, string> bodies = new(StringComparer.Ordinal);

    public Dictionary<string, HttpStatusCode> Status { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, int> Requests { get; } = new(StringComparer.Ordinal);

    public string this[string url]
    {
        set => bodies[url] = value;
    }

    public HttpClient CreateClient() => new(this, disposeHandler: false);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        Requests[url] = Requests.GetValueOrDefault(url) + 1;
        if (!bodies.TryGetValue(url, out var body))
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        return Task.FromResult(new HttpResponseMessage(Status.GetValueOrDefault(url, HttpStatusCode.OK)) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
    }
}
