namespace SubactId.Server.Contracts;

/// <summary>How a credential appears when a contract is printed: whether it was there, never what it was.</summary>
internal static class Redacted
{
    /// <summary><c>&lt;none&gt;</c> when absent, <c>&lt;redacted&gt;</c> otherwise.</summary>
    /// <param name="value">The credential.</param>
    public static string Of(string? value) => value is null ? "<none>" : "<redacted>";
}
