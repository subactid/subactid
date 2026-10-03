namespace SubactId.Tokens.Signing;

/// <summary>A signing key could not be loaded or the key set is inconsistent. Messages never include key material.</summary>
public sealed class SigningKeyException(string message) : Exception(message);
