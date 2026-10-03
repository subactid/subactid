using Microsoft.Extensions.Configuration;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Configuration;

public class DatabaseConfigurationTests
{
    private const string ConnectionStringSentinel = "Host=db;Password=SENTINEL-DO-NOT-LEAK";
    private const string PathSentinel = "/var/lib/subactid/SENTINEL-DO-NOT-LEAK.db";

    private static readonly Dictionary<string, string?> Required = new()
    {
        ["SubactId:Issuer"] = "https://subactid.example.test",
        ["SubactId:UpstreamIdp:MetadataUrl"] = "https://idp.example.test/realms/main/.well-known/openid-configuration",
        ["SubactId:UpstreamIdp:Audience"] = "subactid",
        ["SubactId:UpstreamIdp:SponsorCheck:UsersUrl"] = "https://idp.example.test/admin/realms/main/users",
        ["SubactId:UpstreamIdp:SponsorCheck:TokenUrl"] = "https://idp.example.test/realms/main/protocol/openid-connect/token",
        ["SubactId:UpstreamIdp:SponsorCheck:ClientId"] = "subactid",
    };

    [Fact]
    public void Postgres_is_the_provider_when_none_is_named()
    {
        var result = Load(new() { ["SubactId:Database:ConnectionString"] = ConnectionStringSentinel });

        Assert.True(result.IsValid);
        Assert.Equal(StorageProvider.Postgres, result.Options!.Database.Provider);
        Assert.Equal(ConnectionStringSentinel, result.Options.Database.ConnectionString);
        Assert.Null(result.Options.Database.Path);
    }

    [Theory]
    [InlineData("sqlite")]
    [InlineData("Sqlite")]
    [InlineData("SQLITE")]
    public void The_embedded_provider_is_named_without_regard_to_case_and_takes_a_path(string name)
    {
        var result = Load(new() { ["SubactId:Database:Provider"] = name, ["SubactId:Database:Path"] = PathSentinel });

        Assert.True(result.IsValid);
        Assert.Equal(StorageProvider.Sqlite, result.Options!.Database.Provider);
        Assert.Equal(PathSentinel, result.Options.Database.Path);
        Assert.Null(result.Options.Database.ConnectionString);
    }

    [Fact]
    public void An_unknown_provider_is_refused_and_the_supported_ones_are_named()
    {
        var result = Load(new() { ["SubactId:Database:Provider"] = "mysql" });

        Assert.False(result.IsValid);
        var error = Assert.Single(result.Errors);
        Assert.Equal("SubactId:Database:Provider (environment variable SubactId__Database__Provider) must be one of: postgres, sqlite.", error);
    }

    [Fact]
    public void The_embedded_provider_without_a_path_is_refused()
    {
        var result = Load(new() { ["SubactId:Database:Provider"] = "sqlite" });

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Errors,
            e => e.StartsWith("SubactId:Database:Path (environment variable SubactId__Database__Path) is required", StringComparison.Ordinal));
    }

    [Fact]
    public void Postgres_without_a_connection_string_is_refused()
    {
        var result = Load([]);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Errors,
            e => e.StartsWith("SubactId:Database:ConnectionString (environment variable SubactId__Database__ConnectionString) is required.", StringComparison.Ordinal));
    }

    [Fact]
    public void A_setting_the_chosen_provider_does_not_use_is_refused_rather_than_ignored()
    {
        var sqlite = Load(new()
        {
            ["SubactId:Database:Provider"] = "sqlite",
            ["SubactId:Database:Path"] = PathSentinel,
            ["SubactId:Database:ConnectionString"] = ConnectionStringSentinel,
            ["SubactId:Database:MigrationConnectionString"] = ConnectionStringSentinel,
        });

        Assert.False(sqlite.IsValid);
        Assert.Equal(2, sqlite.Errors.Count);
        Assert.All(sqlite.Errors, e => Assert.EndsWith("is only used when SubactId:Database:Provider (environment variable SubactId__Database__Provider) is postgres.", e, StringComparison.Ordinal));

        var postgres = Load(new()
        {
            ["SubactId:Database:ConnectionString"] = ConnectionStringSentinel,
            ["SubactId:Database:Path"] = PathSentinel,
        });

        Assert.False(postgres.IsValid);
        var error = Assert.Single(postgres.Errors);
        Assert.EndsWith("is only used when SubactId:Database:Provider (environment variable SubactId__Database__Provider) is sqlite.", error, StringComparison.Ordinal);
    }

    [Fact]
    public void No_error_repeats_what_was_configured()
    {
        var result = Load(new()
        {
            ["SubactId:Database:Provider"] = "sqlite",
            ["SubactId:Database:ConnectionString"] = ConnectionStringSentinel,
            ["SubactId:Database:MigrationConnectionString"] = ConnectionStringSentinel,
        });

        Assert.False(result.IsValid);
        Assert.All(result.Errors, e => Assert.DoesNotContain("SENTINEL-DO-NOT-LEAK", e, StringComparison.Ordinal));
    }

    [Fact]
    public void The_options_never_print_what_they_hold()
    {
        var result = Load(new() { ["SubactId:Database:Provider"] = "sqlite", ["SubactId:Database:Path"] = PathSentinel });

        var printed = result.Options!.Database.ToString();

        Assert.DoesNotContain("SENTINEL-DO-NOT-LEAK", printed, StringComparison.Ordinal);
        Assert.Contains("Sqlite", printed, StringComparison.Ordinal);
    }

    private static SubactIdOptionsResult Load(Dictionary<string, string?> database)
    {
        var settings = new Dictionary<string, string?>(Required);
        foreach (var (key, value) in database)
        {
            settings[key] = value;
        }

        return SubactIdOptionsLoader.Load(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
    }
}
