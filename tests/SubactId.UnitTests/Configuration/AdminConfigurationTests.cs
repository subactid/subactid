using Microsoft.Extensions.Configuration;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Configuration;

public class AdminConfigurationTests
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
    public void The_admin_key_is_optional_and_absent_by_default()
    {
        var result = SubactIdOptionsLoader.Load(Build(null));

        Assert.True(result.IsValid);
        Assert.Null(result.Options!.Admin.ApiKey);
        Assert.Equal("AdminOptions { ApiKey = <none> }", result.Options.Admin.ToString());
    }

    [Fact]
    public void A_key_of_at_least_32_characters_is_accepted_and_never_shown()
    {
        var key = "SENTINEL-" + new string('k', 40);

        var result = SubactIdOptionsLoader.Load(Build(key));

        Assert.True(result.IsValid);
        Assert.Equal(key, result.Options!.Admin.ApiKey);
        Assert.DoesNotContain("SENTINEL", result.Options.Admin.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SENTINEL-short")]
    [InlineData("SENTINEL-0123456789012345678901")]
    public void A_short_key_is_rejected_without_being_echoed(string key)
    {
        var result = SubactIdOptionsLoader.Load(Build(key));

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.StartsWith("SubactId:Admin:ApiKey (environment variable SubactId__Admin__ApiKey) must be at least 32 characters.", error, StringComparison.Ordinal);
        Assert.DoesNotContain("SENTINEL", error, StringComparison.Ordinal);
    }

    private static IConfiguration Build(string? apiKey)
    {
        var values = new Dictionary<string, string?>(Base);
        if (apiKey is not null)
        {
            values["SubactId:Admin:ApiKey"] = apiKey;
        }

        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }
}
