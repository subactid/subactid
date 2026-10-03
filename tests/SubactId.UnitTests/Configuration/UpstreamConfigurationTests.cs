using Microsoft.Extensions.Configuration;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Configuration;

public class UpstreamConfigurationTests
{
    private static readonly Dictionary<string, string?> Base = new()
    {
        ["SubactId:Issuer"] = "https://subactid.example.test",
        ["SubactId:UpstreamIdp:Audience"] = "subactid",
        ["SubactId:UpstreamIdp:SponsorCheck:UsersUrl"] = "https://idp.example.test/admin/realms/main/users",
        ["SubactId:UpstreamIdp:SponsorCheck:TokenUrl"] = "https://idp.example.test/realms/main/protocol/openid-connect/token",
        ["SubactId:UpstreamIdp:SponsorCheck:ClientId"] = "subactid",
        ["SubactId:Database:ConnectionString"] = "Host=db",
    };

    [Theory]
    [InlineData("https://idp.example.test/realms/main", "https://idp.example.test/realms/main/.well-known/openid-configuration")]
    [InlineData("https://idp.example.test/realms/main/", "https://idp.example.test/realms/main/.well-known/openid-configuration")]
    [InlineData("http://keycloak:8080/realms/main", "http://keycloak:8080/realms/main/.well-known/openid-configuration")]
    [InlineData("https://idp.example.test/auth/realms/a-b_c", "https://idp.example.test/auth/realms/a-b_c/.well-known/openid-configuration")]
    public void The_realm_url_derives_the_discovery_url(string issuer, string expected)
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:Issuer", issuer), ("SubactId:AllowInsecureHttp", "true")));

        Assert.True(result.IsValid);
        Assert.Equal(new Uri(expected), result.Options!.UpstreamIdp.MetadataUrl);
    }

    [Fact]
    public void The_full_metadata_url_is_still_accepted()
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:MetadataUrl", "https://idp.example.test/realms/main/.well-known/openid-configuration")));

        Assert.True(result.IsValid);
        Assert.Equal(new Uri("https://idp.example.test/realms/main/.well-known/openid-configuration"), result.Options!.UpstreamIdp.MetadataUrl);
    }

    [Fact]
    public void Setting_both_is_an_error_rather_than_a_precedence_rule()
    {
        var result = SubactIdOptionsLoader.Load(Build(
            ("SubactId:UpstreamIdp:Issuer", "https://idp.example.test/realms/main"),
            ("SubactId:UpstreamIdp:MetadataUrl", "https://idp.example.test/realms/main/.well-known/openid-configuration")));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("must not both be set", error, StringComparison.Ordinal);
        Assert.Contains("SubactId__UpstreamIdp__Issuer", error, StringComparison.Ordinal);
        Assert.Contains("SubactId__UpstreamIdp__MetadataUrl", error, StringComparison.Ordinal);
    }

    [Fact]
    public void A_metadata_url_without_the_well_known_suffix_is_a_configuration_error_not_a_startup_crash()
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:MetadataUrl", "https://idp.example.test/realms/main")));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("/.well-known/openid-configuration", error, StringComparison.Ordinal);
        Assert.Contains("SubactId__UpstreamIdp__Issuer", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("idp.example.test/realms/main")]
    [InlineData("ftp://idp.example.test/realms/main")]
    [InlineData("/realms/main")]
    public void A_realm_url_that_is_not_an_absolute_http_url_is_reported(string issuer)
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:Issuer", issuer)));

        Assert.False(result.IsValid);
        Assert.Contains("SubactId:UpstreamIdp:Issuer", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("https://idp.example.test/realms/main?x=1")]
    [InlineData("https://idp.example.test/realms/main#frag")]
    public void A_realm_url_with_a_query_or_fragment_is_reported(string issuer)
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:Issuer", issuer)));

        Assert.False(result.IsValid);
        Assert.Contains("plain realm URL", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Neither_set_asks_for_the_realm_url_and_never_echoes_a_value()
    {
        var result = SubactIdOptionsLoader.Load(Build());

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Contains("SubactId:UpstreamIdp:Issuer", error, StringComparison.Ordinal);
        Assert.Contains("realm URL", error, StringComparison.Ordinal);
    }

    [Fact]
    public void An_upstream_error_never_echoes_the_configured_value()
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:Issuer", "SENTINEL-UPSTREAM")));

        Assert.False(result.IsValid);
        Assert.DoesNotContain("SENTINEL-UPSTREAM", string.Join("\n", result.Errors), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SubactId:Issuer", "http://subactid.example.test")]
    [InlineData("SubactId:UpstreamIdp:Issuer", "http://keycloak:8080/realms/main")]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:UsersUrl", "http://idp.example.test/admin/realms/main/users")]
    [InlineData("SubactId:UpstreamIdp:SponsorCheck:TokenUrl", "http://idp.example.test/realms/main/protocol/openid-connect/token")]
    [InlineData("SubactId:Audit:Sink:Url", "http://siem.example.test/subactid")]
    public void Plain_http_to_a_host_that_is_not_loopback_is_refused_and_named(string key, string url)
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:Issuer", "https://idp.example.test/realms/main"), (key, url)));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.StartsWith(key + " ", error, StringComparison.Ordinal);
        Assert.Contains("SubactId:AllowInsecureHttp", error, StringComparison.Ordinal);
        Assert.DoesNotContain(url, error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("http://127.0.0.1:5100")]
    [InlineData("http://localhost:5100")]
    [InlineData("http://[::1]:5100")]
    [InlineData("http://127.10.0.1")]
    public void Plain_http_on_loopback_is_accepted(string issuer)
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:Issuer", issuer), ("SubactId:UpstreamIdp:Issuer", "http://127.0.0.1:8080/realms/main")));

        Assert.True(result.IsValid, string.Join("\n", result.Errors));
        Assert.False(result.Options!.AllowInsecureHttp);
    }

    [Fact]
    public void Plain_http_elsewhere_is_accepted_when_the_deployment_says_so()
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:Issuer", "http://subactid:5100"), ("SubactId:UpstreamIdp:Issuer", "http://keycloak:8080/realms/main"), ("SubactId:AllowInsecureHttp", "true")));

        Assert.True(result.IsValid, string.Join("\n", result.Errors));
        Assert.True(result.Options!.AllowInsecureHttp);
    }

    [Fact]
    public void A_metadata_url_set_in_full_is_the_one_named()
    {
        var result = SubactIdOptionsLoader.Load(Build(("SubactId:UpstreamIdp:MetadataUrl", "http://keycloak:8080/realms/main/.well-known/openid-configuration")));

        Assert.StartsWith("SubactId:UpstreamIdp:MetadataUrl ", Assert.Single(result.Errors), StringComparison.Ordinal);
    }

    private static IConfiguration Build(params (string Key, string Value)[] extra)
    {
        var settings = new Dictionary<string, string?>(Base);
        foreach (var (key, value) in extra)
        {
            settings[key] = value;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
    }
}
