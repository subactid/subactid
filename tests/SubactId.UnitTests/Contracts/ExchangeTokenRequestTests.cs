using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class ExchangeTokenRequestTests
{
    private static readonly Dictionary<string, StringValues> SpecExample = new(StringComparer.Ordinal)
    {
        ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
        ["subject_token"] = "eyJ.subject.token",
        ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        ["actor_token"] = "eyJ.actor.token",
        ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
        ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        ["resource"] = "https://jira.internal",
        ["scope"] = "jira:read jira:comment",
    };

    private static ExchangeTokenRequest Parse(Dictionary<string, StringValues> form, out IReadOnlyList<SubactId.Core.Validation.ValidationError> repeated) =>
        ExchangeTokenRequest.FromForm(new FormCollection(form), out repeated);

    private static ExchangeTokenRequest With(params (string Name, StringValues Value)[] changes)
    {
        var form = new Dictionary<string, StringValues>(SpecExample, StringComparer.Ordinal);
        foreach (var (name, value) in changes)
        {
            if (value.Count == 0) form.Remove(name);
            else form[name] = value;
        }

        return Parse(form, out _);
    }

    [Fact]
    public void The_spec_example_parses_and_is_valid()
    {
        var request = Parse(SpecExample, out var repeated);

        Assert.Empty(repeated);
        Assert.Empty(request.Validate());
        Assert.Equal("eyJ.subject.token", request.SubjectToken);
        Assert.Equal("eyJ.actor.token", request.ActorToken);
        Assert.Equal("https://jira.internal", request.Resource);
        Assert.Equal(["jira:read", "jira:comment"], request.Scopes);
        Assert.Null(request.ClientId);
    }

    [Fact]
    public void Requested_token_type_and_client_id_are_optional()
    {
        var request = With(("requested_token_type", default), ("client_id", "jira-triage"));

        Assert.Empty(request.Validate());
        Assert.Equal("jira-triage", request.ClientId);
    }

    [Theory]
    [InlineData("grant_type", "refresh_token")]
    [InlineData("grant_type", "")]
    [InlineData("grant_type", null)]
    [InlineData("subject_token", "")]
    [InlineData("subject_token", null)]
    [InlineData("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")]
    [InlineData("subject_token_type", null)]
    [InlineData("actor_token", null)]
    [InlineData("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")]
    [InlineData("actor_token_type", null)]
    [InlineData("requested_token_type", "urn:ietf:params:oauth:token-type:id_token")]
    [InlineData("resource", null)]
    [InlineData("resource", "jira.internal")]
    [InlineData("resource", "ftp://jira.internal")]
    [InlineData("resource", "/relative")]
    [InlineData("scope", null)]
    [InlineData("scope", "")]
    [InlineData("scope", "   ")]
    [InlineData("scope", "jira:read jira:\"comment\"")]
    [InlineData("scope", "jira:read\\x")]
    [InlineData("scope", "jira:řead")]
    [InlineData("actor_token", "")]
    public void Each_parameter_is_checked_and_named_in_the_error(string name, string? value)
    {
        var request = With((name, value is null ? default : new StringValues(value)));

        var error = Assert.Single(request.Validate());
        Assert.Equal(name, error.Field);
    }

    [Fact]
    public void A_subject_token_may_be_larger_than_one_of_ours()
    {
        // The subject token comes from the identity provider, and its size grows with the realm's
        // roles, groups and mappers, so it is allowed to be larger.
        var request = With(("subject_token", new string('a', 12_000)));
        Assert.Empty(request.Validate());

        // The agent's own assertion is small and fixed in shape, so it keeps the tighter limit.
        var oversizedActor = With(("actor_token", new string('b', 12_000)));
        var error = Assert.Single(oversizedActor.Validate());
        Assert.Equal("actor_token", error.Field);
        Assert.Contains("at most 8192", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Oversized_tokens_and_values_are_rejected_without_being_echoed()
    {
        var request = With(("subject_token", new string('a', 16385)), ("resource", "https://" + new string('a', 2048)), ("scope", string.Join(' ', Enumerable.Range(0, 65).Select(i => $"s{i}"))), ("client_id", new string('c', 2049)));

        var errors = request.Validate();

        Assert.Equal(["subject_token", "resource", "scope", "client_id"], errors.Select(e => e.Field));
        Assert.All(errors, e => Assert.DoesNotContain("aaaa", e.Message, StringComparison.Ordinal));
        Assert.All(errors.Where(e => e.Field != "scope"), e => Assert.Contains("at most", e.Message, StringComparison.Ordinal));
    }

    [Fact]
    public void Values_exactly_at_the_limits_are_accepted()
    {
        var request = With(("subject_token", new string('a', 16384)), ("actor_token", new string('b', 8192)), ("resource", "https://jira.internal/" + new string('a', 2048 - "https://jira.internal/".Length)), ("scope", string.Join(' ', Enumerable.Range(0, 64).Select(i => $"s{i}"))), ("client_id", new string('c', 2048)));

        Assert.Empty(request.Validate());
        Assert.Equal(64, request.Scopes.Count);
    }

    [Fact]
    public void A_parameter_sent_without_a_value_counts_as_omitted()
    {
        Assert.Empty(With(("client_id", ""), ("requested_token_type", "")).Validate());
        Assert.Null(With(("client_id", "")).ClientId);
        Assert.Equal("subject_token", Assert.Single(With(("subject_token", "")).Validate()).Field);
    }

    [Fact]
    public void A_repeated_parameter_is_an_error_and_its_value_is_not_used()
    {
        var form = new Dictionary<string, StringValues>(SpecExample, StringComparer.Ordinal) { ["scope"] = new StringValues(["jira:read", "jira:admin"]) };

        var request = Parse(form, out var repeated);

        Assert.Equal("scope", Assert.Single(repeated).Field);
        Assert.Null(request.Scope);
        Assert.Empty(request.Scopes);
    }

    [Fact]
    public void Every_problem_is_reported_at_once_for_an_empty_form()
    {
        var request = Parse([], out var repeated);

        Assert.Empty(repeated);
        Assert.Equal(["grant_type", "subject_token", "subject_token_type", "actor_token", "actor_token_type", "resource", "scope"], request.Validate().Select(e => e.Field));
    }

    [Fact]
    public void Scopes_are_split_on_spaces_with_empty_entries_dropped()
    {
        Assert.Equal(["a", "b"], With(("scope", "a  b ")).Scopes);
    }
}

public class TokenResponseTests
{
    [Fact]
    public void Serialises_exactly_the_spec_section_3_response()
    {
        var response = new TokenResponse("eyJhbGciOi...", ExchangeTokenRequest.AccessTokenType, TokenResponse.Bearer, 300, "jira:read jira:comment", "task_grant_8f2c...", "task_01HQZX9K4M", new DateTimeOffset(2026, 9, 9, 14, 32, 0, TimeSpan.Zero));

        var json = JsonSerializer.Serialize(response, SubactIdJson.CreateOptions());

        Assert.Equal("""{"access_token":"eyJhbGciOi...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":300,"scope":"jira:read jira:comment","refresh_token":"task_grant_8f2c...","task_id":"task_01HQZX9K4M","task_expires_at":"2026-09-09T14:32:00Z"}""", json);
    }
}

public class OAuthErrorResponseTests
{
    [Fact]
    public void Serialises_the_rfc_6749_error_body()
    {
        var json = JsonSerializer.Serialize(new OAuthErrorResponse(OAuthErrorResponse.InvalidScope, "No requested scope is allowed."), SubactIdJson.CreateOptions());

        Assert.Equal("""{"error":"invalid_scope","error_description":"No requested scope is allowed."}""", json);
    }

    [Fact]
    public void An_access_denied_body_carries_its_reason_as_an_extension_member()
    {
        var body = new OAuthErrorResponse(OAuthErrorResponse.AccessDenied, "The task has been revoked.", "task_revoked");

        Assert.Equal("""{"error":"access_denied","error_description":"The task has been revoked.","reason":"task_revoked"}""", JsonSerializer.Serialize(body, SubactIdJson.CreateOptions()));
        Assert.Equal("""{"error":"access_denied","error_description":"The task has been revoked.","reason":"task_revoked"}""", JsonSerializer.Serialize(body));
    }

    [Fact]
    public void A_reason_is_refused_on_any_error_but_access_denied()
    {
        Assert.Throws<ArgumentException>(() => new OAuthErrorResponse(OAuthErrorResponse.InvalidClient, "Client authentication failed.", "actor_invalid_signature"));
    }

    [Theory]
    [InlineData(nameof(OAuthErrorResponse.Error))]
    [InlineData(nameof(OAuthErrorResponse.Reason))]
    public void Neither_the_code_nor_the_reason_can_be_changed_once_the_body_is_built(string property)
    {
        // A with-expression or initializer could otherwise move a reason onto another error code.
        Assert.False(typeof(OAuthErrorResponse).GetProperty(property)!.CanWrite);
    }

    [Theory]
    [InlineData(OAuthErrorResponse.InvalidClient, 401)]
    [InlineData(OAuthErrorResponse.InvalidRequest, 400)]
    [InlineData(OAuthErrorResponse.InvalidGrant, 400)]
    [InlineData(OAuthErrorResponse.InvalidScope, 400)]
    [InlineData(OAuthErrorResponse.InvalidTarget, 400)]
    [InlineData(OAuthErrorResponse.AccessDenied, 400)]
    [InlineData(OAuthErrorResponse.UnsupportedGrantType, 400)]
    [InlineData(OAuthErrorResponse.TemporarilyUnavailable, 503)]
    public void Only_invalid_client_is_a_401(string error, int status)
    {
        Assert.Equal(status, OAuthErrorResponse.StatusCodeFor(error));
    }
}
