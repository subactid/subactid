using Microsoft.Extensions.Configuration;
using SubactId.Server.Configuration;
using SubactId.Tokens.Signing;
using SubactId.UnitTests.Tokens;
using Xunit;

namespace SubactId.UnitTests.Configuration;

public class SigningConfigurationTests
{
    private static readonly Dictionary<string, string?> Base = new()
    {
        ["SubactId:Issuer"] = "https://subactid.example.test",
        ["SubactId:UpstreamIdp:MetadataUrl"] = "https://idp.example.test/.well-known/openid-configuration",
        ["SubactId:UpstreamIdp:Audience"] = "subactid",
        ["SubactId:UpstreamIdp:SponsorCheck:UsersUrl"] = "https://idp.example.test/admin/realms/main/users",
        ["SubactId:UpstreamIdp:SponsorCheck:TokenUrl"] = "https://idp.example.test/realms/main/protocol/openid-connect/token",
        ["SubactId:UpstreamIdp:SponsorCheck:ClientId"] = "subactid",
        ["SubactId:Database:ConnectionString"] = "Host=db",
    };

    [Fact]
    public void No_signing_configuration_yields_an_empty_key_list()
    {
        var result = SubactIdOptionsLoader.Load(Build([]));

        Assert.True(result.IsValid);
        Assert.Empty(result.Options!.Signing.Keys);
        Assert.Null(result.Options.Signing.ActiveKid);
    }

    [Fact]
    public void Keys_are_read_in_numeric_order_with_kid_pem_path_and_active_kid()
    {
        var result = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>
        {
            ["SubactId:Signing:Keys:10:Kid"] = "third",
            ["SubactId:Signing:Keys:10:Path"] = "/run/secrets/third.pem",
            ["SubactId:Signing:Keys:2:Kid"] = "second",
            ["SubactId:Signing:Keys:2:Pem"] = "pem-for-second",
            ["SubactId:Signing:Keys:0:Pem"] = "pem-for-first",
            ["SubactId:Signing:ActiveKid"] = "second",
        }));

        Assert.True(result.IsValid);
        var signing = result.Options!.Signing;
        Assert.Equal("second", signing.ActiveKid);
        Assert.Equal(
            [new SigningKeySource(null, "pem-for-first", null), new SigningKeySource("second", "pem-for-second", null), new SigningKeySource("third", null, "/run/secrets/third.pem")],
            signing.Sources);

        // The numbers survive reading: a rotation leaves gaps, and the next one must not reuse a
        // number still in the configuration.
        Assert.Equal([0, 2, 10], [.. signing.Keys.Select(k => k.Index)]);
    }

    [Fact]
    public void A_key_with_both_or_neither_source_is_an_error_that_never_echoes_the_pem()
    {
        var result = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?>
        {
            ["SubactId:Signing:Keys:0:Pem"] = "SENTINEL-PEM",
            ["SubactId:Signing:Keys:0:Path"] = "/run/secrets/key.pem",
            ["SubactId:Signing:Keys:1:Kid"] = "empty",
        }));

        Assert.False(result.IsValid);
        Assert.Collection(
            result.Errors,
            e => Assert.StartsWith("SubactId:Signing:Keys:0 (environment variable SubactId__Signing__Keys__0) must set exactly one of Pem or Path.", e, StringComparison.Ordinal),
            e => Assert.StartsWith("SubactId:Signing:Keys:1 (environment variable SubactId__Signing__Keys__1) must set exactly one of Pem or Path.", e, StringComparison.Ordinal));
        Assert.All(result.Errors, e => Assert.DoesNotContain("SENTINEL", e, StringComparison.Ordinal));
    }

    [Fact]
    public void A_non_numeric_key_index_is_an_error()
    {
        var result = SubactIdOptionsLoader.Load(Build(new Dictionary<string, string?> { ["SubactId:Signing:Keys:primary:Pem"] = "x" }));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("'primary' is not a number", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Bootstrap_refuses_to_start_without_a_key_outside_development()
    {
        var exception = Assert.Throws<SigningKeyException>(() => SigningKeyBootstrap.Load(new SigningOptions { Keys = [] }, isDevelopment: false, out _));

        Assert.Contains("SubactId:Signing:Keys:0:Path", exception.Message, StringComparison.Ordinal);
        Assert.Contains("never generated automatically", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Bootstrap_generates_an_ephemeral_key_only_in_development_and_only_when_none_is_configured()
    {
        using var generated = SigningKeyBootstrap.Load(new SigningOptions { Keys = [] }, isDevelopment: true, out var ephemeral);
        Assert.True(ephemeral);
        Assert.Single(generated.Keys);

        using var configured = SigningKeyBootstrap.Load(
            new SigningOptions { Keys = [new ConfiguredSigningKey(0, new SigningKeySource("k", TestKeys.Pkcs8Pem(), null))] }, isDevelopment: true, out ephemeral);
        Assert.False(ephemeral);
        Assert.Equal("k", configured.Active.Kid);
    }

    [Fact]
    public void Bootstrap_surfaces_key_loading_errors_in_every_environment()
    {
        var options = new SigningOptions { Keys = [new ConfiguredSigningKey(0, new SigningKeySource("k", TestKeys.PublicOnlyPem(), null))] };

        Assert.Throws<SigningKeyException>(() => SigningKeyBootstrap.Load(options, isDevelopment: true, out _));
        Assert.Throws<SigningKeyException>(() => SigningKeyBootstrap.Load(options, isDevelopment: false, out _));
    }

    private static IConfiguration Build(Dictionary<string, string?> extra)
    {
        var values = new Dictionary<string, string?>(Base);
        foreach (var (key, value) in extra)
        {
            values[key] = value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }
}
