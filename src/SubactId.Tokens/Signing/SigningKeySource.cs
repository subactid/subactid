namespace SubactId.Tokens.Signing;

/// <summary>
/// Where one signing key comes from: an inline PEM or a file path (exactly one). The PEM is an
/// unencrypted P-256 private key in PKCS#8 (<c>BEGIN PRIVATE KEY</c>) or SEC 1
/// (<c>BEGIN EC PRIVATE KEY</c>) form, as written by <c>SubactId.Server keys generate</c>.
/// See <c>docs/keys.md</c>.
/// </summary>
/// <param name="Kid">Explicit key identifier, or <c>null</c> to use the RFC 7638 thumbprint.</param>
/// <param name="Pem">Inline PEM text. A secret.</param>
/// <param name="Path">Path to a PEM file, typically a mounted secret.</param>
public sealed record SigningKeySource(string? Kid, string? Pem, string? Path)
{
    /// <summary>Returns a fixed placeholder so the PEM cannot leak through formatting.</summary>
    public override string ToString() => $"SigningKeySource {{ Kid = {Kid ?? "<thumbprint>"}, Pem = {(Pem is null ? "<none>" : "<redacted>")}, Path = {Path ?? "<none>"} }}";
}
