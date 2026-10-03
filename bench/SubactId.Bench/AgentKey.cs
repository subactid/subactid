using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SubactId.Bench;

// The load generator's agent identity: an ES256 key registered inline with the control plane,
// signing a fresh assertion per request. A copy of the sample agent's key class.
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
        Jwks = JsonDocument.Parse($"{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"use\":\"sig\",\"alg\":\"ES256\",\"kid\":\"{Kid}\",\"x\":\"{x}\",\"y\":\"{y}\"}}]}}").RootElement.Clone();
    }

    public string AgentId { get; }

    public string Kid { get; }

    // The public half as an RFC 7517 key set, for the registration's inline "jwks".
    public JsonElement Jwks { get; }

    // Loads the key at the path, or creates and saves one, so later runs reuse the same agent.
    public static AgentKey LoadOrCreate(string path, string agentId)
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        if (File.Exists(path))
        {
            key.ImportFromPem(File.ReadAllText(path));
            return new AgentKey(key, agentId);
        }

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        File.WriteAllText(path, key.ExportPkcs8PrivateKeyPem());
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        return new AgentKey(key, agentId);
    }

    // A client assertion for the token endpoint, valid for one minute. The jti is random, since
    // the control plane rejects replays.
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
        byte[] signature;
        lock (key)
        {
            signature = key.SignData(Encoding.ASCII.GetBytes($"{header}.{payload}"), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        return $"{header}.{payload}.{Base64Url.EncodeToString(signature)}";
    }
}
