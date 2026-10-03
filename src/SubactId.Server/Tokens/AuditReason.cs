using System.Text.Json;

namespace SubactId.Server.Tokens;

/// <summary>Turns a rejection enum into the stable snake_case reason written to the ledger, for example <c>actor_invalid_signature</c>.</summary>
public static class AuditReason
{
    /// <summary>The reason for <paramref name="rejection"/> under <paramref name="prefix"/>.</summary>
    /// <param name="prefix">What was rejected, for example <c>actor</c> or <c>subject</c>.</param>
    /// <param name="rejection">The rejection value; its name is converted to snake_case.</param>
    public static string Of<T>(string prefix, T rejection)
        where T : struct, Enum
    {
        ArgumentException.ThrowIfNullOrEmpty(prefix);

        return prefix + "_" + JsonNamingPolicy.SnakeCaseLower.ConvertName(rejection.ToString());
    }
}
