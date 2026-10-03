using SubactId.Core.Agents;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class UpdateAgentRequestTests
{
    private static readonly DateTimeOffset Created = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Now = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

    private static readonly Agent Existing = new(
        "jira-triage", "Jira triage agent", true, ["jira:read", "jira:comment"], ["https://jira.internal"],
        TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(5), 2, ["https://db.internal"],
        new Uri("https://subactid.internal/jwks.json"), Jwks: null, Enabled: true, CreatedAt: Created, UpdatedAt: Created);

    private static readonly UpdateAgentRequest Empty = new(null, null, null, null, null, null, null, null, null, null, null);

    [Fact]
    public void An_empty_patch_changes_nothing_but_the_update_time()
    {
        Assert.Empty(Empty.TryApplyTo(Existing, AgentRegistrationLimits.Default, Now, out var updated));

        Assert.Equal(Existing with { UpdatedAt = Now }, updated);
        Assert.Empty(Empty.ChangedFields());
    }

    [Fact]
    public void Only_present_fields_change_and_are_reported()
    {
        var patch = Empty with { Enabled = false, AllowedScopes = ["jira:read"], MaxTokenTtl = TimeSpan.FromMinutes(2) };

        Assert.Empty(patch.TryApplyTo(Existing, AgentRegistrationLimits.Default, Now, out var updated));

        Assert.NotNull(updated);
        Assert.False(updated.Enabled);
        Assert.Equal(["jira:read"], updated.AllowedScopes);
        Assert.Equal(TimeSpan.FromMinutes(2), updated.MaxTokenTtl);
        Assert.Equal(Existing.DisplayName, updated.DisplayName);
        Assert.Equal(Existing.AgentId, updated.AgentId);
        Assert.Equal(Created, updated.CreatedAt);
        Assert.Equal(Now, updated.UpdatedAt);
        Assert.Equal(["allowed_scopes", "max_token_ttl", "enabled"], patch.ChangedFields());
    }

    [Fact]
    public void The_merged_registration_is_validated_as_a_whole()
    {
        var patch = Empty with { MaxTaskTtl = TimeSpan.FromMinutes(1) };

        var errors = patch.TryApplyTo(Existing, AgentRegistrationLimits.Default, Now, out var updated);

        Assert.Null(updated);
        var error = Assert.Single(errors);
        Assert.Equal("max_token_ttl", error.Field);
        Assert.Equal("must not exceed max_task_ttl.", error.Message);
    }

    [Fact]
    public void A_relative_jwks_uri_is_a_field_error_not_an_exception()
    {
        var errors = (Empty with { JwksUri = "/jwks.json" }).TryApplyTo(Existing, AgentRegistrationLimits.Default, Now, out var updated);

        Assert.Null(updated);
        Assert.Equal("jwks_uri", Assert.Single(errors).Field);
    }
}
