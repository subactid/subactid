using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using SubactId.Core.Tokens;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using Xunit;

namespace SubactId.UnitTests.Tokens.Issuance;

public class TaskTokenSerializerTests
{
    private const string Sponsor = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private static readonly TaskTokenClaims SpecExample = new(
        new Uri("https://subactid.internal.example.com"),
        Sponsor,
        "https://jira.internal",
        DateTimeOffset.FromUnixTimeSeconds(1757426520),
        DateTimeOffset.FromUnixTimeSeconds(1757426220),
        "tok_01HQZX9K5P",
        ["jira:read", "jira:comment"],
        new ActorClaim("agent:jira-triage", "pod-7f9c4b", 1, null),
        new TaskClaim("task_01HQZX9K4M", DateTimeOffset.FromUnixTimeSeconds(1757428020), Sponsor));

    [Fact]
    public void Writes_exactly_the_spec_section_4_example()
    {
        const string expected = """{"iss":"https://subactid.internal.example.com","sub":"f47ac10b-58cc-4372-a567-0e02b2c3d479","aud":"https://jira.internal","exp":1757426520,"iat":1757426220,"jti":"tok_01HQZX9K5P","scope":"jira:read jira:comment","client_id":"agent:jira-triage","act":{"sub":"agent:jira-triage","instance":"pod-7f9c4b","depth":1},"task":{"id":"task_01HQZX9K4M","exp":1757428020,"sponsor":"f47ac10b-58cc-4372-a567-0e02b2c3d479"}}""";

        Assert.Equal(expected, Encoding.UTF8.GetString(TaskTokenSerializer.ToJson(SpecExample)));
    }

    [Fact]
    public void Writes_a_nested_act_chain_as_in_spec_section_4_1_with_instance_omitted_when_absent()
    {
        var inner = new ActorClaim("agent:jira-triage", "pod-7f9c4b", 1, null);
        var claims = SpecExample with { Actor = new ActorClaim("agent:db-reader", null, 2, inner) };

        using var json = JsonDocument.Parse(TaskTokenSerializer.ToJson(claims));
        var act = json.RootElement.GetProperty("act");

        Assert.Equal("""{"sub":"agent:db-reader","depth":2,"act":{"sub":"agent:jira-triage","instance":"pod-7f9c4b","depth":1}}""", act.GetRawText());
        Assert.Equal(Sponsor, json.RootElement.GetProperty("sub").GetString());
        Assert.Equal("agent:db-reader", json.RootElement.GetProperty("client_id").GetString());
    }

    /// <summary>
    /// The claim carries the operator's decision to the tool server in the token itself. It is
    /// written only when true, so an ordinary token is unchanged.
    /// </summary>
    [Fact]
    public void Writes_introspect_required_only_for_a_high_risk_audience()
    {
        using var ordinary = JsonDocument.Parse(TaskTokenSerializer.ToJson(SpecExample));
        Assert.False(ordinary.RootElement.TryGetProperty("introspect_required", out _));

        using var highRisk = JsonDocument.Parse(
            TaskTokenSerializer.ToJson(SpecExample with { IntrospectRequired = true }));
        Assert.True(highRisk.RootElement.GetProperty("introspect_required").GetBoolean());
    }

    [Fact]
    public void Trailing_slash_on_the_issuer_is_not_written_and_timestamps_are_whole_seconds()
    {
        var claims = SpecExample with { Issuer = new Uri("https://subactid.internal.example.com/"), ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(1757426520).AddMilliseconds(999) };

        using var json = JsonDocument.Parse(TaskTokenSerializer.ToJson(claims));

        Assert.Equal("https://subactid.internal.example.com", json.RootElement.GetProperty("iss").GetString());
        Assert.Equal(1757426520, json.RootElement.GetProperty("exp").GetInt64());
    }

    [Fact]
    public void Signs_with_the_active_key_as_an_access_token_and_the_payload_is_the_claim_json()
    {
        using var keys = SigningKeySet.CreateEphemeral();

        var token = TaskTokenSerializer.Sign(keys, SpecExample);

        Assert.True(Jws.TryVerify(keys, token, out var header, out var payload));
        Assert.Equal("at+jwt", header!.Typ);
        Assert.Equal(keys.Active.Kid, header.Kid);
        Assert.Equal(TaskTokenSerializer.ToJson(SpecExample), payload);
        Assert.Equal(TaskTokenSerializer.ToJson(SpecExample), Base64Url.DecodeFromChars(token.Split('.')[1]));
    }
}
