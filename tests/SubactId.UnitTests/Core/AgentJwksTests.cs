using System.Text.Json;
using SubactId.Core.Agents;
using Xunit;

namespace SubactId.UnitTests.Core;

public class AgentJwksTests
{
    private const string Ec = """{"kid":"a","kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","alg":"ES256","use":"sig"}""";
    private const string Rsa = """{"kid":"b","kty":"RSA","n":"AQAB","e":"AQAB","alg":"RS256"}""";

    private static string Set(params string[] keys) => $$"""{"keys":[{{string.Join(",", keys)}}]}""";

    [Fact]
    public void A_public_key_set_parses_and_round_trips_through_its_canonical_json()
    {
        Assert.Empty(AgentJwks.TryParse(Set(Ec, Rsa), "jwks", out var jwks));

        Assert.NotNull(jwks);
        Assert.Equal(["a", "b"], jwks.Keys.Select(k => k.Kid));

        Assert.Empty(AgentJwks.TryParse(jwks.ToJson(), "jwks", out var again));
        Assert.Equal(jwks, again);
    }

    [Theory]
    [InlineData("d")]
    [InlineData("p")]
    [InlineData("q")]
    [InlineData("dp")]
    [InlineData("dq")]
    [InlineData("qi")]
    [InlineData("k")]
    [InlineData("oth")]
    public void A_key_carrying_any_private_member_is_refused_and_the_value_is_never_echoed(string member)
    {
        var json = $$"""{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","{{member}}":"SENTINEL-PRIVATE"}]}""";

        var errors = AgentJwks.TryParse(json, "jwks", out var jwks);

        Assert.Null(jwks);
        var error = Assert.Single(errors);
        Assert.Equal("jwks.keys[0]", error.Field);
        Assert.Contains($"private member '{member}'", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("SENTINEL-PRIVATE", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_member_that_is_not_modelled_is_dropped_rather_than_stored()
    {
        var json = """{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","x5c":["MIIC"],"surprise":"value"}]}""";

        Assert.Empty(AgentJwks.TryParse(json, "jwks", out var jwks));

        var canonical = jwks!.ToJson();
        Assert.DoesNotContain("x5c", canonical, StringComparison.Ordinal);
        Assert.DoesNotContain("surprise", canonical, StringComparison.Ordinal);
        Assert.Contains("\"kid\":\"a\"", canonical, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"keys":[]}""", "jwks")]
    [InlineData("""{"keys":{}}""", "jwks")]
    [InlineData("""[]""", "jwks")]
    [InlineData("""{"keys":[{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}]}""", "jwks.keys[0]")]
    [InlineData("""{"keys":[{"kid":"a","kty":"EC","x":"AQAB","y":"AQAB"}]}""", "jwks.keys[0]")]
    [InlineData("""{"keys":[{"kid":"a","kty":"RSA","n":"AQAB"}]}""", "jwks.keys[0]")]
    [InlineData("""{"keys":[{"kid":"a","kty":"oct","k":"AQAB"}]}""", "jwks.keys[0]")]
    [InlineData("""{"keys":[{"kid":"a","kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","use":"enc"}]}""", "jwks.keys[0]")]
    [InlineData("""{"keys":[{"kid":1,"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}]}""", "jwks.keys[0]")]
    public void A_malformed_key_set_is_reported_against_the_field_that_is_wrong(string json, string field)
    {
        var errors = AgentJwks.TryParse(json, "jwks", out var jwks);

        Assert.Null(jwks);
        Assert.NotEmpty(errors);
        Assert.Contains(errors, e => e.Field == field);
    }

    [Fact]
    public void Two_keys_may_not_share_a_kid()
    {
        var errors = AgentJwks.TryParse(Set(Ec, Ec), "jwks", out var jwks);

        Assert.Null(jwks);
        Assert.Contains("repeats the kid", Assert.Single(errors).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void More_keys_than_the_cap_are_refused()
    {
        var keys = Enumerable.Range(0, AgentJwks.MaxKeys + 1)
            .Select(i => $$"""{"kid":"k{{i}}","kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}""");

        var errors = AgentJwks.TryParse(Set([.. keys]), "jwks", out var jwks);

        Assert.Null(jwks);
        Assert.Contains($"at most {AgentJwks.MaxKeys}", Assert.Single(errors).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Text_that_is_not_json_is_reported_rather_than_thrown()
    {
        var errors = AgentJwks.TryParse("not json", "jwks", out var jwks);

        Assert.Null(jwks);
        Assert.Equal("must be valid JSON.", Assert.Single(errors).Message);
    }

    [Fact]
    public void An_oversized_member_is_refused()
    {
        var json = $$"""{"keys":[{"kid":"a","kty":"RSA","n":"{{new string('A', AgentJwks.MaxMemberLength + 1)}}","e":"AQAB"}]}""";

        Assert.NotEmpty(AgentJwks.TryParse(json, "jwks", out var jwks));
        Assert.Null(jwks);
    }

    [Fact]
    public void The_canonical_json_is_what_the_endpoint_and_storage_both_hold()
    {
        Assert.Empty(AgentJwks.TryParse(Set(Ec), "jwks", out var jwks));

        using var document = JsonDocument.Parse(jwks!.ToJson());
        var key = Assert.Single(document.RootElement.GetProperty("keys").EnumerateArray());
        Assert.Equal("a", key.GetProperty("kid").GetString());
        Assert.Equal("EC", key.GetProperty("kty").GetString());
        Assert.False(key.TryGetProperty("n", out _));
    }
}
