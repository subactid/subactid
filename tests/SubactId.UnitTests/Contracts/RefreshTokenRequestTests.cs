using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class RefreshTokenRequestTests
{
    private static readonly Dictionary<string, StringValues> SpecExample = new(StringComparer.Ordinal)
    {
        ["grant_type"] = "refresh_token",
        ["refresh_token"] = "task_grant_8f2c",
        ["resource"] = "https://jira.internal",
        ["scope"] = "jira:read",
        ["client_assertion"] = "eyJ.actor.token",
        ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    };

    private static RefreshTokenRequest With(params (string Name, StringValues Value)[] changes)
    {
        var form = new Dictionary<string, StringValues>(SpecExample, StringComparer.Ordinal);
        foreach (var (name, value) in changes)
        {
            if (value.Count == 0) form.Remove(name);
            else form[name] = value;
        }

        return RefreshTokenRequest.FromForm(new FormCollection(form), out _);
    }

    [Fact]
    public void The_spec_example_with_a_client_assertion_parses_and_is_valid()
    {
        var request = RefreshTokenRequest.FromForm(new FormCollection(SpecExample), out var repeated);

        Assert.Empty(repeated);
        Assert.Empty(request.Validate());
        Assert.Equal("task_grant_8f2c", request.RefreshToken);
        Assert.Equal(["jira:read"], request.Scopes);
        Assert.Null(request.ClientId);
    }

    [Theory]
    [InlineData("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")]
    [InlineData("grant_type", null)]
    [InlineData("refresh_token", null)]
    [InlineData("refresh_token", "")]
    [InlineData("resource", null)]
    [InlineData("resource", "jira.internal")]
    [InlineData("scope", null)]
    [InlineData("scope", "jira:\"read\"")]
    [InlineData("client_assertion", null)]
    [InlineData("client_assertion_type", null)]
    [InlineData("client_assertion_type", "urn:ietf:params:oauth:token-type:jwt")]
    public void Each_parameter_is_checked_and_named_in_the_error(string name, string? value)
    {
        var request = With((name, value is null ? default : new StringValues(value)));

        var error = Assert.Single(request.Validate());
        Assert.Equal(name, error.Field);
    }

    [Fact]
    public void Oversized_values_are_rejected_without_being_echoed()
    {
        var request = With(("refresh_token", new string('g', 513)), ("client_assertion", new string('a', 8193)), ("client_id", new string('c', 2049)));

        var errors = request.Validate();

        Assert.Equal(["refresh_token", "client_assertion", "client_id"], errors.Select(e => e.Field));
        Assert.All(errors, e => Assert.Contains("at most", e.Message, StringComparison.Ordinal));
        Assert.All(errors, e => Assert.DoesNotContain("ggg", e.Message, StringComparison.Ordinal));
    }

    [Fact]
    public void A_repeated_parameter_is_an_error_and_an_empty_form_reports_everything()
    {
        var form = new Dictionary<string, StringValues>(SpecExample, StringComparer.Ordinal) { ["refresh_token"] = new StringValues(["a", "b"]) };
        RefreshTokenRequest.FromForm(new FormCollection(form), out var repeated);
        Assert.Equal("refresh_token", Assert.Single(repeated).Field);

        var empty = RefreshTokenRequest.FromForm(new FormCollection([]), out _);
        Assert.Equal(["grant_type", "refresh_token", "resource", "scope", "client_assertion", "client_assertion_type"], empty.Validate().Select(e => e.Field));
    }
}
