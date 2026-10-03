using Npgsql;
using SubactId.Storage.Postgres;
using Xunit;

namespace SubactId.UnitTests.Storage;

/// <summary>
/// GSS encryption is off unless the connection string asks for it, so no connection probes for a
/// Kerberos library the runtime image does not have and writes plain text to stderr.
/// </summary>
public class PostgresConnectionStringTests
{
    [Fact]
    public void A_string_that_says_nothing_about_gss_gets_it_disabled_and_keeps_everything_else()
    {
        var result = new NpgsqlConnectionStringBuilder(PostgresConnectionString.WithDefaults("Host=db;Username=subactid;Password=secret;Maximum Pool Size=7"));

        Assert.Equal(GssEncryptionMode.Disable, result.GssEncryptionMode);
        Assert.Equal(("db", "subactid", "secret", 7), (result.Host, result.Username, result.Password, result.MaxPoolSize));
    }

    [Theory]
    [InlineData("Host=db;GssEncryptionMode=Require", GssEncryptionMode.Require)]
    [InlineData("Host=db;GSS Encryption Mode=Prefer", GssEncryptionMode.Prefer)]
    [InlineData("Host=db;gss encryption mode=disable", GssEncryptionMode.Disable)]
    public void A_string_that_names_gss_encryption_keeps_what_it_named(string connectionString, GssEncryptionMode expected)
    {
        Assert.Equal(expected, new NpgsqlConnectionStringBuilder(PostgresConnectionString.WithDefaults(connectionString)).GssEncryptionMode);
    }

    [Fact]
    public void A_pggssencmode_environment_variable_is_left_for_npgsql_to_honour()
    {
        var result = new NpgsqlConnectionStringBuilder(PostgresConnectionString.WithDefaults("Host=db", name => name == "PGGSSENCMODE" ? "require" : null));

        // Nothing written into the string, so Npgsql falls back to the variable.
        Assert.DoesNotContain("GSS", result.ConnectionString, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void An_unset_or_empty_pggssencmode_still_gets_gss_disabled(string? variable)
    {
        var result = new NpgsqlConnectionStringBuilder(PostgresConnectionString.WithDefaults("Host=db", _ => variable));

        Assert.Equal(GssEncryptionMode.Disable, result.GssEncryptionMode);
    }

    [Fact]
    public void The_string_wins_over_pggssencmode()
    {
        var result = new NpgsqlConnectionStringBuilder(PostgresConnectionString.WithDefaults("Host=db;GSS Encryption Mode=Prefer", _ => "disable"));

        Assert.Equal(GssEncryptionMode.Prefer, result.GssEncryptionMode);
    }
}
