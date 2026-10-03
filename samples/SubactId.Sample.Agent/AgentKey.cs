using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SubactId.Sample.Agent;

/// <summary>
/// The agent's ES256 key. The private key never leaves the agent. The public key is published as
/// a JWKS, and each request to the control plane carries a fresh short-lived assertion signed with
/// it (RFC 7523). No shared secret.
/// </summary>
internal sealed class AgentKey
{
    private readonly ECDsa key;

    private AgentKey(ECDsa key, string agentId)
    {
        this.key = key;
        AgentId = agentId;
        var parameters = key.ExportParameters(false);
        var x = Base64Url.EncodeToString(parameters.Q.X!);
        var y = Base64Url.EncodeToString(parameters.Q.Y!);

        // RFC 7638 thumbprint, so the kid is stable for the key.
        Kid = Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")));
        Jwks = $"{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"sig\",\"alg\":\"ES256\",\"kid\":\"{Kid}\",\"x\":\"{x}\",\"y\":\"{y}\"}}]}}";
    }

    /// <summary>The agent this key belongs to.</summary>
    public string AgentId { get; }

    /// <summary>The key's identifier, as it appears in the JWKS and in every assertion header.</summary>
    public string Kid { get; }

    /// <summary>The public half, as the JWKS document the control plane fetches.</summary>
    public string Jwks { get; }

    /// <summary>
    /// Loads the key at <paramref name="path"/>, or creates one there readable only by this user.
    /// Reusing it keeps the control plane's cached JWKS valid across restarts.
    /// </summary>
    public static AgentKey LoadOrCreate(string path, string agentId)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            key.ImportFromPem(File.ReadAllText(path));
            return new AgentKey(key, agentId);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem());
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return new AgentKey(key, agentId);
    }

    /// <summary>A client assertion for <paramref name="audience"/>, valid for one minute, with a random jti.</summary>
    public string Assertion(string audience)
    {
        var now = DateTimeOffset.UtcNow;
        var claims = new Dictionary<string, object>
        {
            ["iss"] = AgentId,
            ["sub"] = AgentId,
            ["aud"] = audience,
            ["jti"] = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16)),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddSeconds(60).ToUnixTimeSeconds(),
        };

        var header = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string> { ["alg"] = "ES256", ["typ"] = "JWT", ["kid"] = Kid }));
        var payload = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(claims));
        var signature = key.SignData(Encoding.ASCII.GetBytes($"{header}.{payload}"), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{header}.{payload}.{Base64Url.EncodeToString(signature)}";
    }
}
