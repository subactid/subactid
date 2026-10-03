using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SubactId.Core.Agents;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class RegisterAgentRequestTests
{
    private const string SpecExample = """
        {
          "agent_id": "jira-triage",
          "display_name": "Jira triage agent",
          "sponsor_required": true,
          "allowed_scopes": ["jira:read", "jira:comment", "confluence:read"],
          "allowed_audiences": ["https://jira.internal", "https://confluence.internal"],
          "max_task_ttl": "PT30M",
          "max_token_ttl": "PT5M",
          "max_delegation_depth": 2,
          "high_risk_audiences": ["https://db.internal"],
          "jwks_uri": "https://jira-triage.agents.internal/.well-known/jwks.json"
        }
        """;

    private static readonly DateTimeOffset Now = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_spec_example_deserializes_and_becomes_a_valid_agent()
    {
        var request = JsonSerializer.Deserialize<RegisterAgentRequest>(SpecExample, SubactIdJson.CreateOptions());

        Assert.NotNull(request);
        var errors = request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Empty(errors);
        Assert.NotNull(agent);
        Assert.Equal("jira-triage", agent.AgentId);
        Assert.Equal("Jira triage agent", agent.DisplayName);
        Assert.True(agent.SponsorRequired);
        Assert.Equal(["jira:read", "jira:comment", "confluence:read"], agent.AllowedScopes);
        Assert.Equal(["https://jira.internal", "https://confluence.internal"], agent.AllowedAudiences);
        Assert.Equal(TimeSpan.FromMinutes(30), agent.MaxTaskTtl);
        Assert.Equal(TimeSpan.FromMinutes(5), agent.MaxTokenTtl);
        Assert.Equal(2, agent.MaxDelegationDepth);
        Assert.Equal(["https://db.internal"], agent.HighRiskAudiences);
        Assert.Equal(new Uri("https://jira-triage.agents.internal/.well-known/jwks.json"), agent.JwksUri);
        Assert.True(agent.Enabled);
        Assert.Equal(Now, agent.CreatedAt);
        Assert.Equal(Now, agent.UpdatedAt);
    }

    [Fact]
    public void Optional_fields_default_safely()
    {
        var request = new RegisterAgentRequest("a", "A", null, ["s"], ["https://a.internal"], TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(5), 1, null, "https://jira-triage.example/jwks.json", null);

        Assert.Empty(request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));
        Assert.NotNull(agent);
        Assert.True(agent.SponsorRequired);
        Assert.Empty(agent.HighRiskAudiences);
        // The key source is required and is kept exactly as given.
        Assert.Equal(new Uri("https://jira-triage.example/jwks.json"), agent.JwksUri);
        Assert.Null(agent.Jwks);
    }

    [Fact]
    public void An_empty_payload_reports_every_required_field()
    {
        var request = JsonSerializer.Deserialize<RegisterAgentRequest>("{}", SubactIdJson.CreateOptions());

        Assert.NotNull(request);
        var errors = request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Null(agent);
        Assert.Equal(
            ["agent_id", "display_name", "allowed_scopes", "allowed_audiences", "max_delegation_depth"],
            errors.Select(e => e.Field));
        Assert.All(errors, e => Assert.Equal("is required.", e.Message));
    }

    [Fact]
    public void A_registration_that_names_no_lifetimes_is_given_the_servers()
    {
        var request = new RegisterAgentRequest("a", "A", null, ["s"], ["https://a.internal"], null, null, 1, null, "https://jira-triage.example/jwks.json", null);

        Assert.Empty(request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));
        Assert.NotNull(agent);
        Assert.Equal(AgentRegistrationLimits.Default.DefaultTaskTtl, agent.MaxTaskTtl);
        Assert.Equal(AgentRegistrationLimits.Default.DefaultTokenTtl, agent.MaxTokenTtl);
    }

    [Fact]
    public void A_registration_that_names_its_own_lifetimes_keeps_them()
    {
        // A long job is registered as such and is not cut back to the server's default.
        var request = new RegisterAgentRequest("a", "A", null, ["s"], ["https://a.internal"], TimeSpan.FromHours(6), TimeSpan.FromMinutes(5), 1, null, "https://jira-triage.example/jwks.json", null);

        Assert.Empty(request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));
        Assert.Equal(TimeSpan.FromHours(6), agent!.MaxTaskTtl);
        Assert.Equal(TimeSpan.FromMinutes(5), agent.MaxTokenTtl);
    }

    [Fact]
    public void A_default_token_lifetime_is_cut_to_a_shorter_task_rather_than_refused()
    {
        // The registration named a one-minute task and no token lifetime. The five-minute default
        // would fail validation, and extending the task to fit it would widen it.
        var request = new RegisterAgentRequest("a", "A", null, ["s"], ["https://a.internal"], TimeSpan.FromMinutes(1), null, 1, null, "https://jira-triage.example/jwks.json", null);

        Assert.Empty(request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));
        Assert.Equal(TimeSpan.FromMinutes(1), agent!.MaxTaskTtl);
        Assert.Equal(TimeSpan.FromMinutes(1), agent.MaxTokenTtl);
    }

    [Fact]
    public void A_lifetime_outside_the_servers_bounds_is_still_refused()
    {
        var request = new RegisterAgentRequest("a", "A", null, ["s"], ["https://a.internal"], TimeSpan.FromDays(2), null, 1, null, "https://jira-triage.example/jwks.json", null);

        var errors = request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Null(agent);
        Assert.Equal(["max_task_ttl"], errors.Select(e => e.Field));
    }

    [Fact]
    public void Domain_rules_run_once_required_fields_are_present()
    {
        var request = new RegisterAgentRequest("jira-triage", "Jira", true, [], ["https://jira.internal"], TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(6), 9, null, "not a url", null);

        var errors = request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Null(agent);
        Assert.Equal(["jwks_uri"], errors.Select(e => e.Field));

        var withUrl = request with { JwksUri = "https://subactid.internal/jwks.json" };
        errors = withUrl.TryToAgent(AgentRegistrationLimits.Default, Now, out agent);

        Assert.Null(agent);
        Assert.Equal(["allowed_scopes", "max_token_ttl", "max_delegation_depth"], errors.Select(e => e.Field));
    }

    [Fact]
    public void A_malformed_duration_is_a_json_error_that_names_the_field()
    {
        var json = SpecExample.Replace("\"PT30M\"", "\"30 minutes\"", StringComparison.Ordinal);

        var exception = Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<RegisterAgentRequest>(json, SubactIdJson.CreateOptions()));

        Assert.Equal("$.max_task_ttl", exception.Path);
    }

    [Fact]
    public async Task Validation_errors_become_a_400_with_per_field_errors()
    {
        var request = new RegisterAgentRequest("jira-triage", "Jira", true, [], ["https://jira.internal"], TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(6), 2, null, "https://jira-triage.example/jwks.json", null);
        var errors = request.TryToAgent(AgentRegistrationLimits.Default, Now, out _);

        var context = new DefaultHttpContext { RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider() };
        context.Response.Body = new MemoryStream();
        await ValidationProblems.ToResult(errors).ExecuteAsync(context);

        Assert.Equal(StatusCodes.Status400BadRequest, context.Response.StatusCode);
        Assert.StartsWith("application/problem+json", context.Response.ContentType, StringComparison.Ordinal);
        context.Response.Body.Position = 0;
        using var body = await JsonDocument.ParseAsync(context.Response.Body);
        var problemErrors = body.RootElement.GetProperty("errors");
        Assert.Equal("must contain at least one scope.", problemErrors.GetProperty("allowed_scopes")[0].GetString());
        Assert.Equal("must not exceed max_task_ttl.", problemErrors.GetProperty("max_token_ttl")[0].GetString());
        Assert.Equal(2, problemErrors.EnumerateObject().Count());
    }

    [Fact]
    public void An_empty_error_list_cannot_become_a_response()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ValidationProblems.ToResult([]));
    }
}
