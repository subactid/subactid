using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text.Json;
using SubactId.Core.Agents;
using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class AgentJwksContractTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 12, 12, 0, 0, TimeSpan.Zero);
    private static readonly (string X, string Y) Point = NewPoint();

    private static JsonElement KeySet(string kid = "a") =>
        JsonSerializer.Deserialize<JsonElement>(
            $$"""{"keys":[{"kid":"{{kid}}","kty":"EC","crv":"P-256","x":"{{Point.X}}","y":"{{Point.Y}}","alg":"ES256","use":"sig"}]}""");

    private static RegisterAgentRequest Request(string? jwksUri = null, JsonElement? jwks = null) => new(
        "jira-triage", "Jira triage agent", true, ["jira:read"], ["https://jira.internal"],
        TimeSpan.FromMinutes(30), TimeSpan.FromMinutes(5), 1, null, jwksUri, jwks);

    [Fact]
    public void An_inline_key_set_is_accepted_and_stored_on_the_agent()
    {
        Assert.Empty(Request(jwks: KeySet()).TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));

        Assert.NotNull(agent);
        Assert.Null(agent.JwksUri);
        Assert.Equal("a", Assert.Single(agent.Jwks!.Keys).Kid);
    }

    [Fact]
    public void A_url_alone_is_still_accepted()
    {
        Assert.Empty(Request(jwksUri: "https://jira-triage.example/jwks.json").TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));

        Assert.NotNull(agent);
        Assert.Null(agent.Jwks);
        Assert.Equal(new Uri("https://jira-triage.example/jwks.json"), agent.JwksUri);
    }

    [Fact]
    public void Both_at_once_is_refused_because_an_agents_keys_come_from_one_place()
    {
        var errors = Request("https://jira-triage.example/jwks.json", KeySet()).TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Null(agent);
        Assert.Contains(errors, e => e.Field == "jwks" && e.Message.Contains("jwks_uri", StringComparison.Ordinal));
    }

    [Fact]
    public void A_private_member_is_refused_per_field_and_never_echoed()
    {
        var withPrivate = JsonSerializer.Deserialize<JsonElement>(
            $$"""{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"{{Point.X}}","y":"{{Point.Y}}","d":"SENTINEL-PRIVATE"}]}""");

        var errors = Request(jwks: withPrivate).TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Null(agent);
        Assert.NotEmpty(errors);
        Assert.DoesNotContain("SENTINEL-PRIVATE", string.Join("\n", errors.Select(e => e.Message)), StringComparison.Ordinal);
    }

    [Fact]
    public void A_key_set_this_server_could_not_verify_with_is_refused_at_registration()
    {
        // Well-formed, but not a point on the curve, so no assertion signed by it could verify.
        // Refused at registration instead of on every exchange.
        var unusable = JsonSerializer.Deserialize<JsonElement>(
            """{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","alg":"ES256"}]}""");

        var errors = Request(jwks: unusable).TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Null(agent);
        Assert.Equal("jwks.keys[0]", Assert.Single(errors).Field);
    }

    [Fact]
    public void A_key_set_with_one_unusable_key_among_usable_ones_is_refused_naming_that_key()
    {
        // The first key is fine. The second is on a curve this server does not verify with, so an
        // assertion naming it would be refused as an unknown key with no reason given.
        var mixed = JsonSerializer.Deserialize<JsonElement>(
            $$"""{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"{{Point.X}}","y":"{{Point.Y}}"},{"kid":"b","kty":"EC","crv":"P-384","x":"AQAB","y":"AQAB"}]}""");

        var errors = Request(jwks: mixed).TryToAgent(AgentRegistrationLimits.Default, Now, out var agent);

        Assert.Null(agent);
        Assert.Equal("jwks.keys[1]", Assert.Single(errors).Field);
    }

    [Fact]
    public void Patching_in_a_key_set_moves_the_agent_off_its_url_in_one_step()
    {
        Assert.Empty(Request(jwksUri: "https://jira-triage.example/jwks.json").TryToAgent(AgentRegistrationLimits.Default, Now, out var existing));

        var patch = new UpdateAgentRequest(null, null, null, null, null, null, null, null, null, KeySet("b"), null);
        Assert.Empty(patch.TryApplyTo(existing!, AgentRegistrationLimits.Default, Now, out var updated));

        Assert.NotNull(updated);
        Assert.Null(updated.JwksUri);
        Assert.Equal("b", Assert.Single(updated.Jwks!.Keys).Kid);
        Assert.Contains("jwks", patch.ChangedFields());
    }

    [Fact]
    public void Patching_in_a_url_moves_the_agent_off_its_held_keys_in_one_step()
    {
        Assert.Empty(Request(jwks: KeySet()).TryToAgent(AgentRegistrationLimits.Default, Now, out var existing));

        var patch = new UpdateAgentRequest(null, null, null, null, null, null, null, null, "https://jira-triage.example/jwks.json", null, null);
        Assert.Empty(patch.TryApplyTo(existing!, AgentRegistrationLimits.Default, Now, out var updated));

        Assert.NotNull(updated);
        Assert.Null(updated.Jwks);
        Assert.Equal(new Uri("https://jira-triage.example/jwks.json"), updated.JwksUri);
    }

    [Fact]
    public void A_patch_may_not_set_both_either()
    {
        Assert.Empty(Request(jwks: KeySet()).TryToAgent(AgentRegistrationLimits.Default, Now, out var existing));

        var patch = new UpdateAgentRequest(null, null, null, null, null, null, null, null, "https://a.example/jwks.json", KeySet(), null);

        Assert.NotEmpty(patch.TryApplyTo(existing!, AgentRegistrationLimits.Default, Now, out var updated));
        Assert.Null(updated);
    }

    [Fact]
    public void The_response_publishes_the_key_set_and_survives_a_round_trip_back_to_an_agent()
    {
        Assert.Empty(Request(jwks: KeySet()).TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));

        var response = AgentResponse.From(agent!);
        var json = JsonSerializer.Serialize(response, SubactIdJson.Options);

        Assert.Contains("\"jwks\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"d\"", json, StringComparison.Ordinal);

        var back = JsonSerializer.Deserialize<AgentResponse>(json, SubactIdJson.Options)!.ToAgent();
        Assert.Equal(agent!.Jwks, back.Jwks);
    }

    [Fact]
    public void An_agent_with_a_jwks_uri_answers_jwks_as_an_explicit_null()
    {
        // Both key sources are always present and exactly one is non-null, as every other absent
        // value in a response is written (spec section 2).
        Assert.Empty(Request(jwksUri: "https://jira-triage.example/jwks.json").TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(AgentResponse.From(agent!), SubactIdJson.Options));

        Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("jwks").ValueKind);
        Assert.Equal("https://jira-triage.example/jwks.json", json.RootElement.GetProperty("jwks_uri").GetString());
    }

    private static (string X, string Y) NewPoint()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var q = key.ExportParameters(false).Q;
        return (Base64Url.EncodeToString(q.X!), Base64Url.EncodeToString(q.Y!));
    }
}
