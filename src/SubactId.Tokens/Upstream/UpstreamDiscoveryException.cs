namespace SubactId.Tokens.Upstream;

/// <summary>
/// What is wrong with an upstream document. Stable, so operator tooling can name the cause.
/// </summary>
public enum UpstreamDiscoveryFault
{
    /// <summary>Unclassified.</summary>
    Unusable,

    /// <summary>The document is larger than the cap.</summary>
    TooLarge,

    /// <summary>The document is not valid JSON.</summary>
    NotJson,

    /// <summary>The discovery document has no usable <c>issuer</c>.</summary>
    NoIssuer,

    /// <summary>The <c>issuer</c> is not the URL the document was fetched from.</summary>
    IssuerMismatch,

    /// <summary>The discovery document has no absolute <c>jwks_uri</c>.</summary>
    NoJwksUri,

    /// <summary>The <c>jwks_uri</c> downgrades to http.</summary>
    JwksNotHttps,

    /// <summary>The JWKS has no <c>keys</c> array.</summary>
    NoKeysArray,
}

/// <summary>The upstream identity provider's discovery document or JWKS is unusable. Messages never include token or key material.</summary>
/// <param name="message">What is wrong, in words.</param>
/// <param name="inner">The underlying failure, when there is one.</param>
/// <param name="fault">Which failure this is, for tooling that names a cause.</param>
public sealed class UpstreamDiscoveryException(string message, Exception? inner = null, UpstreamDiscoveryFault fault = UpstreamDiscoveryFault.Unusable)
    : Exception(message, inner)
{
    /// <summary>Which failure this is.</summary>
    public UpstreamDiscoveryFault Fault { get; } = fault;
}
