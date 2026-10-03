using SubactId.Server.Contracts;
using SubactId.Server.Revocation;

namespace SubactId.Server.Admin;

/// <summary>
/// The admin API: the agent registry at <c>/admin/agents</c>, task revocation at
/// <c>/admin/tasks/{id}</c>, <c>/admin/agents/{id}/tasks</c> and
/// <c>/admin/sponsors/{sponsor_key}/tasks</c>, and sponsor blocks at
/// <c>/admin/sponsors/{sponsor_key}/block</c>. Authenticated by API key.
/// </summary>
public static class AdminEndpoints
{
    /// <summary>Route prefix of the admin API.</summary>
    public const string Prefix = "/admin";

    /// <summary>Registers the admin service.</summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSubactIdAdmin(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddScoped<AgentAdminService>();
        services.AddScoped<SponsorAdminService>();
        return services;
    }

    /// <summary>Maps the admin endpoints behind <see cref="AdminApiKeyFilter"/>.</summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    public static void MapSubactIdAdminEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var admin = endpoints.MapGroup(Prefix).AddEndpointFilter<AdminApiKeyFilter>();
        var agents = admin.MapGroup("/agents");

        agents.MapPost("/", async (RegisterAgentRequest request, AgentAdminService service, CancellationToken cancellationToken) =>
        {
            var result = await service.RegisterAsync(request, cancellationToken);
            return result.Agent is { } agent
                ? Results.Created($"{Prefix}/agents/{Uri.EscapeDataString(agent.AgentId)}", AgentResponse.From(agent))
                : ToProblem(result);
        });

        agents.MapGet("/", async ([AsParameters] ListAgentsRequest request, AgentAdminService service, CancellationToken cancellationToken) =>
        {
            var errors = request.TryToQuery(out var after, out var limit);
            if (errors.Count > 0)
            {
                return ValidationProblems.ToResult(errors);
            }

            var page = await service.ListAsync(after, limit + 1, cancellationToken);
            return Results.Ok(AgentsResponse.From(page, limit));
        });

        agents.MapGet("/{agentId}", async (string agentId, AgentAdminService service, CancellationToken cancellationToken) =>
        {
            var result = await service.GetAsync(agentId, cancellationToken);
            return result.Agent is { } agent ? Results.Ok(AgentResponse.From(agent)) : ToProblem(result);
        });

        agents.MapPatch("/{agentId}", async (string agentId, UpdateAgentRequest request, AgentAdminService service, CancellationToken cancellationToken) =>
        {
            var result = await service.UpdateAsync(agentId, request, cancellationToken);
            return result.Agent is { } agent ? Results.Ok(AgentResponse.From(agent)) : ToProblem(result);
        });

        agents.MapDelete("/{agentId}/tasks", async (string agentId, RevocationService revocation, CancellationToken cancellationToken) =>
        {
            var result = await revocation.RevokeAgentTasksAsync(agentId, cancellationToken);
            return result.Found ? Results.Ok(new RevokedTasksResponse(result.RevokedTasks)) : Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "No such agent.");
        });

        admin.MapDelete("/tasks/{taskId}", async (string taskId, RevocationService revocation, CancellationToken cancellationToken) =>
        {
            var result = await revocation.RevokeTaskAsync(taskId, cancellationToken);
            return result.Found ? Results.Ok(new RevokedTasksResponse(result.RevokedTasks)) : Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "No such task.");
        });

        // The path segment is the sponsor key, the claim named by SubactId:UpstreamIdp:SponsorKeyClaim.
        // When that claim is not `sub`, it differs from the value the audit query filters by.
        var sponsors = admin.MapGroup("/sponsors");

        sponsors.MapGet("/{sponsorKey}", async (string sponsorKey, SponsorAdminService service, CancellationToken cancellationToken) =>
        {
            var (block, failure) = await service.GetAsync(sponsorKey, cancellationToken);
            return block is null ? ToProblem(failure) : Results.Ok(SponsorResponse.From(block));
        });

        sponsors.MapPut("/{sponsorKey}/block", async (string sponsorKey, SponsorAdminService service, CancellationToken cancellationToken) =>
        {
            var (block, revoked, failure) = await service.BlockAsync(sponsorKey, cancellationToken);
            return failure is null ? Results.Ok(new SponsorBlockedResponse(SponsorResponse.From(block!), revoked)) : ToProblem(failure);
        });

        sponsors.MapDelete("/{sponsorKey}/block", async (string sponsorKey, SponsorAdminService service, CancellationToken cancellationToken) =>
        {
            var failure = await service.UnblockAsync(sponsorKey, cancellationToken);
            return failure is null ? Results.NoContent() : ToProblem(failure);
        });

        sponsors.MapDelete("/{sponsorKey}/tasks", async (string sponsorKey, SponsorAdminService service, CancellationToken cancellationToken) =>
        {
            var (revoked, failure) = await service.RevokeTasksAsync(sponsorKey, cancellationToken);
            return failure is null ? Results.Ok(new RevokedTasksResponse(revoked)) : ToProblem(failure);
        });

        agents.MapDelete("/{agentId}", async (string agentId, AgentAdminService service, CancellationToken cancellationToken) =>
            await service.DeleteAsync(agentId, cancellationToken) switch
            {
                null => Results.NoContent(),
                AdminFailure.NotFound => Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "No such agent."),
                AdminFailure.InUse => Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "The agent still has tasks.", detail: "Revoke the agent's tasks, disable it, and delete it once the sweeper has removed them after the retention period."),
                _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError),
            });
    }

    private static IResult ToProblem(SponsorAdminFailure? failure) => failure switch
    {
        SponsorAdminFailure.InvalidKey => Results.Problem(
            statusCode: StatusCodes.Status400BadRequest,
            title: "The sponsor key is not valid.",
            detail: $"A sponsor key is 1 to {SponsorAdminService.MaxSponsorKeyLength} characters with no whitespace or control characters."),
        SponsorAdminFailure.NotBlocked => Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "That human is not blocked."),
        SponsorAdminFailure.NotOwned => Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "That block was not placed by an operator.",
            detail: "Only the source that placed a block may lift it, so a block from the identity provider or a provisioning feed is cleared there, not here."),
        SponsorAdminFailure.BlockedElsewhere => Results.Problem(
            statusCode: StatusCodes.Status409Conflict,
            title: "That human is already blocked by another source.",
            detail: "A block another source placed is never replaced or taken over. It stands until that source lifts it, and GET on the sponsor shows it. The person's live tasks were still ended."),
        _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError),
    };

    private static IResult ToProblem(AdminResult result) => result switch
    {
        { ValidationErrors.Count: > 0 } => ValidationProblems.ToResult(result.ValidationErrors),
        { Failure: AdminFailure.NotFound } => Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "No such agent."),
        { Failure: AdminFailure.AlreadyExists } => Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "An agent with that id already exists."),
        { Failure: AdminFailure.InUse } => Results.Problem(statusCode: StatusCodes.Status409Conflict, title: "The agent still has tasks."),
        _ => Results.Problem(statusCode: StatusCodes.Status500InternalServerError),
    };
}
