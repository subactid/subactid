using System.Data.Common;
using Npgsql;

namespace SubactId.Storage.Postgres;

/// <summary>The defaults Subact ID applies to a configured Postgres connection string.</summary>
public static class PostgresConnectionString
{
    /// <summary>
    /// <paramref name="connectionString"/> with GSS encryption disabled, unless the string sets it
    /// or the <c>PGGSSENCMODE</c> environment variable does.
    /// </summary>
    /// <remarks>
    /// Npgsql's default is to prefer GSS encryption, so every first connection probes for the
    /// system's Kerberos library. Where it is missing, as in the <c>aspnet</c> runtime image, the
    /// runtime prints a plain-text line to stderr that breaks JSON log parsing. A deployment that
    /// uses GSS names it, in the string or in <c>PGGSSENCMODE</c> (which Npgsql honours), and gets
    /// exactly what it named.
    /// </remarks>
    /// <param name="connectionString">The configured connection string. A secret, never logged.</param>
    public static string WithDefaults(string connectionString) =>
        WithDefaults(connectionString, Environment.GetEnvironmentVariable);

    /// <summary>
    /// <paramref name="connectionString"/> with GSS encryption disabled, unless the string sets it
    /// or <paramref name="environment"/> has a non-empty <c>PGGSSENCMODE</c>.
    /// </summary>
    /// <param name="connectionString">The configured connection string. A secret, never logged.</param>
    /// <param name="environment">Reads an environment variable by name.</param>
    public static string WithDefaults(string connectionString, Func<string, string?> environment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        ArgumentNullException.ThrowIfNull(environment);

        var builder = new NpgsqlConnectionStringBuilder(connectionString);

        // Read back through a plain builder, which holds only what the string set. Npgsql's own
        // reports every known keyword as present.
        var set = new DbConnectionStringBuilder { ConnectionString = builder.ConnectionString };
        if (!set.ContainsKey(GssEncryptionModeKeyword) && string.IsNullOrEmpty(environment(GssEncryptionModeVariable)))
        {
            builder.GssEncryptionMode = GssEncryptionMode.Disable;
        }

        return builder.ConnectionString;
    }

    /// <summary>The keyword Npgsql writes GSS encryption under, whichever synonym the string used.</summary>
    private const string GssEncryptionModeKeyword = "GSS Encryption Mode";

    /// <summary>The environment variable Npgsql reads GSS encryption from when the string is silent.</summary>
    private const string GssEncryptionModeVariable = "PGGSSENCMODE";
}
