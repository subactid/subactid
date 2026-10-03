using System.Security.Cryptography;

namespace SubactId.Tokens.Signing;

/// <summary>Builds a <see cref="SigningKeySet"/> from configured sources. Errors name the source, never its content.</summary>
public static class SigningKeySetLoader
{
    /// <summary>Loads every source and selects the active key.</summary>
    /// <param name="sources">The configured keys, in publication order.</param>
    /// <param name="activeKid">
    /// The key to sign with. May be <c>null</c> only when there is exactly one key.
    /// </param>
    /// <exception cref="SigningKeyException">A source is unusable or the set is inconsistent.</exception>
    public static SigningKeySet Load(IReadOnlyList<SigningKeySource> sources, string? activeKid)
    {
        ArgumentNullException.ThrowIfNull(sources);

        if (sources.Count == 0)
        {
            throw new SigningKeyException("No signing key is configured.");
        }

        if (sources.Count > 1 && string.IsNullOrWhiteSpace(activeKid))
        {
            throw new SigningKeyException("Several signing keys are configured but no active key is selected; set the active kid explicitly.");
        }

        var keys = new List<SigningKey>(sources.Count);
        try
        {
            for (var i = 0; i < sources.Count; i++)
            {
                keys.Add(LoadOne(sources[i], i));
            }

            return new SigningKeySet(keys, activeKid ?? keys[0].Kid);
        }
        catch
        {
            foreach (var key in keys)
            {
                key.Dispose();
            }

            throw;
        }
    }

    private static SigningKey LoadOne(SigningKeySource source, int index)
    {
        var label = $"signing key {index}" + (source.Kid is null ? string.Empty : $" ('{source.Kid}')");

        if (source.Pem is not null == source.Path is not null)
        {
            throw new SigningKeyException($"{label} must have exactly one of an inline PEM or a file path.");
        }

        string pem;
        if (source.Pem is not null)
        {
            pem = source.Pem;
        }
        else
        {
            try
            {
                pem = File.ReadAllText(source.Path!);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                throw new SigningKeyException($"{label} could not be read from '{source.Path}': {exception.GetType().Name}.");
            }
        }

        if (pem.Contains("ENCRYPTED", StringComparison.Ordinal))
        {
            throw new SigningKeyException($"{label} is an encrypted PEM; only unencrypted PKCS#8 or SEC 1 EC private keys are supported.");
        }

        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException)
        {
            ecdsa.Dispose();
            throw new SigningKeyException($"{label} is not a PEM-encoded EC private key.");
        }

        try
        {
            return SigningKey.FromPrivateKey(ecdsa, source.Kid);
        }
        catch (SigningKeyException exception)
        {
            ecdsa.Dispose();
            throw new SigningKeyException($"{label}: {exception.Message}");
        }
    }
}
