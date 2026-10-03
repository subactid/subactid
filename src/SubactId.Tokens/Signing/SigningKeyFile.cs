using System.Security.Cryptography;

namespace SubactId.Tokens.Signing;

/// <summary>
/// Writes a newly generated signing key to a file, as an explicit operator action. The file is
/// owner-only, an existing file is never overwritten, and the encoded key is cleared from memory
/// after writing.
/// </summary>
public static class SigningKeyFile
{
    /// <summary>
    /// Characters reserved for the encoded key. A P-256 PKCS#8 PEM is about 240. Running out
    /// fails instead of truncating.
    /// </summary>
    private const int PemLength = 1024;

    private const UnixFileMode OwnerOnly = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>
    /// Generates a P-256 private key and writes it to <paramref name="path"/> as unencrypted
    /// PKCS#8 PEM, in the form <see cref="SigningKeySetLoader"/> reads back without changes.
    /// </summary>
    /// <param name="path">Where to write the key. Must not already exist.</param>
    /// <param name="kid">Explicit key identifier, or <c>null</c> for the RFC 7638 thumbprint.</param>
    /// <returns>The generated key; the caller owns it.</returns>
    /// <exception cref="SigningKeyException">The file already exists, or it could not be written.</exception>
    public static SigningKey Create(string path, string? kid = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SigningKey key;
        try
        {
            key = SigningKey.FromPrivateKey(ecdsa, kid);
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }

        try
        {
            // Written only after the key is accepted, so a rejected key never reaches disk.
            Write(path, ecdsa);
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
    }

    private static void Write(string path, ECDsa key)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };

        if (!OperatingSystem.IsWindows())
        {
            // Created owner-only so the key is never world-readable, even briefly.
            options.UnixCreateMode = OwnerOnly;
        }

        var pem = new char[PemLength];
        try
        {
            if (!key.TryExportPkcs8PrivateKeyPem(pem, out var written))
            {
                throw new SigningKeyException("The generated key did not fit the PEM buffer; no file was written.");
            }

            using var stream = new FileStream(path, options);
            using var writer = new StreamWriter(stream);
            writer.Write(pem, 0, written);
            writer.Write('\n');
        }
        catch (IOException) when (File.Exists(path))
        {
            throw new SigningKeyException($"'{path}' already exists; refusing to overwrite a signing key.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw new SigningKeyException($"'{path}' could not be written: {exception.GetType().Name}.");
        }
        finally
        {
            pem.AsSpan().Clear();
        }
    }
}
