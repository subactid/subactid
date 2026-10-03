using Microsoft.AspNetCore.Http.HttpResults;
using SubactId.Core.Agents;
using SubactId.Server.Contracts;

namespace SubactId.Server.Agents;

/// <summary>
/// <c>GET /agents/{agent_id}/jwks.json</c>: the public keys of an agent whose registration carries
/// them inline. Unauthenticated and read-only.
/// </summary>
public static class AgentJwksEndpoints
{
    /// <summary>
    /// How long clients may cache the document. Shorter than the control plane's JWKS because
    /// these keys change when a registration is updated.
    /// </summary>
    public const int CacheSeconds = 60;

    /// <summary>Maps the agent JWKS endpoint.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdAgentJwksEndpoint(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        endpoints.MapGet(AgentJwksResponse.Path, Jwks);
    }

    private static async Task<Results<JsonHttpResult<AgentJwksResponse>, NotFound>> Jwks(
        string agent_id,
        IAgentRepository agents,
        HttpResponse response,
        CancellationToken cancellationToken)
    {
        var agent = await agents.FindAsync(agent_id, cancellationToken);

        // A disabled agent still publishes its keys: they verify the agent's own assertions, which
        // it may still use to revoke what it holds, and a key set that came and went with the
        // enabled flag would look like a rotation to anyone fetching it.
        if (agent?.Jwks is not { } jwks)
        {
            return TypedResults.NotFound();
        }

        response.Headers.CacheControl = $"public, max-age={CacheSeconds}";
        return TypedResults.Json(AgentJwksResponse.From(jwks));
    }
}
