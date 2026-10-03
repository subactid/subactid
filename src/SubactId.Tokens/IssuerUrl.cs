namespace SubactId.Tokens;

/// <summary>
/// The canonical issuer string, used in the discovery document, every token's <c>iss</c> and the
/// <c>aud</c> of agent assertions. These must match byte for byte.
/// </summary>
public static class IssuerUrl
{
    /// <summary>The issuer as a string without a trailing slash.</summary>
    /// <param name="issuer">The configured issuer URL.</param>
    public static string Canonical(Uri issuer)
    {
        ArgumentNullException.ThrowIfNull(issuer);

        return issuer.ToString().TrimEnd('/');
    }
}
