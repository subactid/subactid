using SubactId.Core.Audit;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Audit;

/// <summary>
/// Checks a checkpoint's signature against the keys this control plane publishes in JWKS.
/// A checkpoint naming a key that is not in the set does not verify.
/// </summary>
/// <param name="signingKeys">The published key set.</param>
public sealed class SigningKeyCheckpointSignatures(SigningKeySet signingKeys) : IAuditCheckpointSignatures
{
    /// <inheritdoc />
    public bool Verify(string kid, ReadOnlySpan<byte> signedBytes, ReadOnlySpan<byte> signature) =>
        signingKeys.Find(kid) is { } key && key.Verify(signedBytes, signature);
}
