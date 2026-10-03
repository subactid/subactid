using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SubactId.Tokens.Upstream;

namespace SubactId.UnitTests.Tokens.Upstream;

/// <summary>Upstream key material, JWKS documents and token minting, all done with the BCL directly.</summary>
internal static class UpstreamTestData
{
    public const string Issuer = "https://idp.example.test/realms/main";
    public const string Audience = "subactid";
    public static readonly DateTimeOffset Now = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

    public static readonly RSA Rsa1 = RSA.Create(2048);
    public static readonly RSA Rsa2 = RSA.Create(2048);
    public static readonly ECDsa Ec1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static string RsaJwk(RSA rsa, string kid, string? alg = "RS256", string? use = "sig", bool includePrivate = false)
    {
        var p = rsa.ExportParameters(includePrivate);
        var members = new List<string> { $"\"kid\":\"{kid}\"", "\"kty\":\"RSA\"", $"\"n\":\"{Base64Url.EncodeToString(p.Modulus!)}\"", $"\"e\":\"{Base64Url.EncodeToString(p.Exponent!)}\"" };
        if (alg is not null) members.Add($"\"alg\":\"{alg}\"");
        if (use is not null) members.Add($"\"use\":\"{use}\"");
        if (includePrivate) members.Add($"\"d\":\"{Base64Url.EncodeToString(p.D!)}\"");
        members.Add("\"x5c\":[\"MIIC\"]");
        return "{" + string.Join(",", members) + "}";
    }

    public static string EcJwk(ECDsa ecdsa, string kid, string? alg = "ES256", string crv = "P-256")
    {
        var q = ecdsa.ExportParameters(false).Q;
        var algMember = alg is null ? string.Empty : $",\"alg\":\"{alg}\"";
        return $"{{\"kid\":\"{kid}\",\"kty\":\"EC\",\"crv\":\"{crv}\",\"x\":\"{Base64Url.EncodeToString(q.X!)}\",\"y\":\"{Base64Url.EncodeToString(q.Y!)}\"{algMember},\"use\":\"sig\"}}";
    }

    public static string Jwks(params string[] jwks) => "{\"keys\":[" + string.Join(",", jwks) + "]}";

    public static UpstreamKeySnapshot Snapshot(string? jwks = null, DateTimeOffset? fetchedAt = null) =>
        new(Issuer, UpstreamJwksParser.Parse(jwks ?? Jwks(RsaJwk(Rsa1, "rsa1"), EcJwk(Ec1, "ec1"))), fetchedAt ?? Now);

    /// <summary>A claim set that validates at <see cref="Now"/> against <see cref="Issuer"/> and <see cref="Audience"/>.</summary>
    public static Dictionary<string, object?> Claims(params (string Key, object? Value)[] overrides)
    {
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["sub"] = "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            ["aud"] = Audience,
            ["exp"] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["iat"] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["scope"] = "openid jira:read jira:comment",
        };
        foreach (var (key, value) in overrides)
        {
            if (value is null && key.StartsWith('-')) claims.Remove(key[1..]);
            else claims[key] = value;
        }

        return claims;
    }

    public static string Mint(string alg, string kid, Dictionary<string, object?> claims, RSA? rsa = null, ECDsa? ecdsa = null, string? headerJson = null)
    {
        headerJson ??= $"{{\"alg\":\"{alg}\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}";
        var input = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(headerJson))}.{Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(claims))}";
        var data = Encoding.ASCII.GetBytes(input);
        var signature = alg switch
        {
            "RS256" or "RS512" or "none" or "HS256" => (rsa ?? Rsa1).SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "PS256" => (rsa ?? Rsa1).SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            "ES256" or "es256" => (ecdsa ?? Ec1).SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
            _ => throw new ArgumentException(alg),
        };
        return $"{input}.{Base64Url.EncodeToString(signature)}";
    }
}

/// <summary>An <see cref="IUpstreamKeys"/> that serves fixed snapshots and counts refreshes.</summary>
internal sealed class StaticUpstreamKeys(UpstreamKeySnapshot current, UpstreamKeySnapshot? afterRefresh = null, Exception? failure = null) : IUpstreamKeys
{
    public int Refreshes { get; private set; }

    public int Gets { get; private set; }

    /// <summary>What the stub holds: the snapshot it was given, or nothing when it is set to fail.</summary>
    public UpstreamKeySnapshot? Current => failure is null ? current : null;

    public Task<UpstreamKeySnapshot> GetAsync(CancellationToken cancellationToken = default)
    {
        Gets++;
        return failure is null ? Task.FromResult(current) : Task.FromException<UpstreamKeySnapshot>(failure);
    }

    public Task<UpstreamKeySnapshot> RefreshForUnknownKidAsync(CancellationToken cancellationToken = default)
    {
        Refreshes++;
        return Task.FromResult(afterRefresh ?? current);
    }
}

/// <summary>An identity provider that serves fixed documents at fixed URLs and counts requests.</summary>
internal sealed class FakeIdp : HttpMessageHandler
{
    private readonly Dictionary<string, string> bodies = new(StringComparer.Ordinal);

    public Dictionary<string, HttpStatusCode> Status { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, int> Requests { get; } = new(StringComparer.Ordinal);

    public string this[string url]
    {
        set => bodies[url] = value;
    }

    public HttpClient CreateClient() => new(this, disposeHandler: false);

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.ToString();
        Requests[url] = Requests.GetValueOrDefault(url) + 1;
        if (!bodies.TryGetValue(url, out var body))
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        return Task.FromResult(new HttpResponseMessage(Status.GetValueOrDefault(url, HttpStatusCode.OK))
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
    }
}
