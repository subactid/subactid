using SubactId.Core.Agents;
using Xunit;

namespace SubactId.UnitTests.Core;

public class AgentValidatorTests
{
    private static readonly AgentRegistrationLimits Limits = AgentRegistrationLimits.Default;

    private static readonly Agent Valid = new(
        "jira-triage",
        "Jira triage agent",
        SponsorRequired: true,
        AllowedScopes: ["jira:read", "jira:comment", "confluence:read"],
        AllowedAudiences: ["https://jira.internal", "https://confluence.internal"],
        MaxTaskTtl: TimeSpan.FromMinutes(30),
        MaxTokenTtl: TimeSpan.FromMinutes(5),
        MaxDelegationDepth: 2,
        HighRiskAudiences: ["https://db.internal"],
        JwksUri: new Uri("https://jira-triage.agents.internal/.well-known/jwks.json"),
        Jwks: null,
        Enabled: true,
        CreatedAt: DateTimeOffset.UnixEpoch,
        UpdatedAt: DateTimeOffset.UnixEpoch);

    [Fact]
    public void The_spec_example_is_valid()
    {
        Assert.Empty(AgentValidator.Validate(Valid, Limits));
    }

    /// <summary>
    /// Every exchange requires a human subject token, so a registration asking otherwise describes a
    /// grant the server does not have, and is refused.
    /// </summary>
    [Fact]
    public void Sponsor_required_must_be_true()
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { SponsorRequired = false }, Limits));

        Assert.Equal("sponsor_required", error.Field);
    }

    [Fact]
    public void A_registration_without_high_risk_audiences_is_valid()
    {
        Assert.Empty(AgentValidator.Validate(Valid with { HighRiskAudiences = [] }, Limits));
    }

    [Fact]
    public void A_registration_may_hold_its_keys_inline_instead_of_naming_a_url()
    {
        var inline = new AgentJwks([new AgentJwk { Kid = "a", Kty = "EC", Crv = "P-256", X = "x", Y = "y" }]);

        Assert.Empty(AgentValidator.Validate(Valid with { JwksUri = null, Jwks = inline }, Limits));
    }

    [Fact]
    public void A_registration_that_names_no_source_of_keys_is_refused()
    {
        // Such an agent could never authenticate, and every attempt would be refused before its key
        // was checked. Refused at registration instead.
        var error = Assert.Single(AgentValidator.Validate(Valid with { JwksUri = null, Jwks = null }, Limits));

        Assert.Equal("jwks_uri", error.Field);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Jira-Triage")]
    [InlineData("-jira")]
    [InlineData("agent:jira")]
    [InlineData("jira triage")]
    [InlineData("jira\n")]
    public void Agent_id_must_be_a_lowercase_slug(string agentId)
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { AgentId = agentId }, Limits));
        Assert.Equal("agent_id", error.Field);
    }

    [Fact]
    public void Agent_id_length_is_bounded()
    {
        Assert.Empty(AgentValidator.Validate(Valid with { AgentId = new string('a', 128) }, Limits));
        Assert.Single(AgentValidator.Validate(Valid with { AgentId = new string('a', 129) }, Limits));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Display_name_is_required(string displayName)
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { DisplayName = displayName }, Limits));
        Assert.Equal("display_name", error.Field);
    }

    [Fact]
    public void Allowed_scopes_must_be_non_empty()
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { AllowedScopes = [] }, Limits));
        Assert.Equal("allowed_scopes", error.Field);
        Assert.Contains("at least one", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("jira read")]
    [InlineData("")]
    [InlineData("jira\"read")]
    [InlineData("jira:read\n")]
    [InlineData("jira\\read")]
    [InlineData("čitanje")]
    public void Scopes_must_be_rfc_6749_scope_tokens(string scope)
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { AllowedScopes = ["jira:read", scope] }, Limits));
        Assert.Equal("allowed_scopes", error.Field);
    }

    [Fact]
    public void Duplicate_scopes_and_audiences_are_rejected()
    {
        var errors = AgentValidator.Validate(
            Valid with { AllowedScopes = ["jira:read", "jira:read"], AllowedAudiences = ["https://jira.internal", "https://jira.internal"] },
            Limits);

        Assert.Equal(["allowed_scopes", "allowed_audiences"], errors.Select(e => e.Field));
        Assert.All(errors, e => Assert.Contains("duplicates", e.Message, StringComparison.Ordinal));
    }

    [Fact]
    public void At_least_one_allowed_audience_is_required()
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { AllowedAudiences = [] }, Limits));
        Assert.Equal("allowed_audiences", error.Field);
    }

    [Theory]
    [InlineData("jira.internal")]
    [InlineData("ftp://jira.internal")]
    [InlineData("")]
    public void Audiences_must_be_absolute_http_urls(string audience)
    {
        var errors = AgentValidator.Validate(Valid with { AllowedAudiences = [audience], HighRiskAudiences = [audience] }, Limits);

        Assert.Equal(["allowed_audiences", "high_risk_audiences"], errors.Select(e => e.Field));
    }

    [Theory]
    [InlineData(59, "max_task_ttl")]
    [InlineData(86_401, "max_task_ttl")]
    public void Task_ttl_must_be_within_the_limits(int seconds, string field)
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { MaxTaskTtl = TimeSpan.FromSeconds(seconds), MaxTokenTtl = TimeSpan.FromSeconds(30) }, Limits));
        Assert.Equal(field, error.Field);
    }

    [Theory]
    [InlineData(29)]
    [InlineData(3_601)]
    public void Token_ttl_must_be_within_the_limits(int seconds)
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { MaxTaskTtl = TimeSpan.FromHours(2), MaxTokenTtl = TimeSpan.FromSeconds(seconds) }, Limits));
        Assert.Equal("max_token_ttl", error.Field);
    }

    [Fact]
    public void Token_ttl_may_not_exceed_task_ttl()
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { MaxTaskTtl = TimeSpan.FromMinutes(5), MaxTokenTtl = TimeSpan.FromMinutes(6) }, Limits));

        Assert.Equal("max_token_ttl", error.Field);
        Assert.Equal("must not exceed max_task_ttl.", error.Message);
    }

    [Fact]
    public void Token_ttl_equal_to_task_ttl_is_allowed()
    {
        Assert.Empty(AgentValidator.Validate(Valid with { MaxTaskTtl = TimeSpan.FromMinutes(5), MaxTokenTtl = TimeSpan.FromMinutes(5) }, Limits));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(6)]
    [InlineData(-1)]
    public void Delegation_depth_must_be_between_one_and_five(int depth)
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { MaxDelegationDepth = depth }, Limits));
        Assert.Equal("max_delegation_depth", error.Field);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    public void Delegation_depth_bounds_are_inclusive(int depth)
    {
        Assert.Empty(AgentValidator.Validate(Valid with { MaxDelegationDepth = depth }, Limits));
    }

    [Theory]
    [InlineData("http://subactid.internal/jwks.json")]
    [InlineData("/agents/jira-triage/jwks.json")]
    public void Jwks_uri_must_be_https(string jwks)
    {
        var error = Assert.Single(AgentValidator.Validate(Valid with { JwksUri = new Uri(jwks, UriKind.RelativeOrAbsolute) }, Limits));
        Assert.Equal("jwks_uri", error.Field);
    }

    [Fact]
    public void Every_problem_is_reported_at_once()
    {
        var broken = Valid with
        {
            AgentId = "",
            DisplayName = "",
            AllowedScopes = [],
            AllowedAudiences = [],
            MaxTaskTtl = TimeSpan.Zero,
            MaxTokenTtl = TimeSpan.Zero,
            MaxDelegationDepth = 0,
            JwksUri = new Uri("http://insecure.example"),
        };

        var fields = AgentValidator.Validate(broken, Limits).Select(e => e.Field).ToList();

        Assert.Equal(
            ["agent_id", "display_name", "allowed_scopes", "allowed_audiences", "max_task_ttl", "max_token_ttl", "max_delegation_depth", "jwks_uri"],
            fields);
    }
}
