using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SubactId.Conformance;

/// <summary>
/// Just enough JOSE for the suite, written here on purpose: the suite must not share code with
/// the server it tests. RS256 for what the suite signs (the stub identity provider's subject
/// tokens and the agents' client assertions), ES256 verification for what the server signs.
/// </summary>
internal static class Jwt
{
    /// <summary>A compact RS256 JWS over <paramref name="claims"/>, signed with <paramref name="key"/>.</summary>
    public static string SignRs256(RSA key, string kid, IReadOnlyDictionary<string, object?> claims, string typ = "JWT")
    {
        var header = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string> { ["alg"] = "RS256", ["typ"] = typ, ["kid"] = kid }));
        var payload = Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(claims));
        var signature = key.SignData(Encoding.ASCII.GetBytes($"{header}.{payload}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{payload}.{Base64Url.EncodeToString(signature)}";
    }

    /// <summary>The decoded header of a compact JWS.</summary>
    public static JsonElement Header(string jws) => Part(jws, 0);

    /// <summary>The decoded payload of a compact JWS, without verifying it.</summary>
    public static JsonElement Payload(string jws) => Part(jws, 1);

    /// <summary>Whether <paramref name="jws"/> is an ES256 signature by the key in <paramref name="jwks"/> whose <c>kid</c> matches its header.</summary>
    public static bool VerifyEs256(string jws, JsonElement jwks)
    {
        var parts = jws.Split('.');
        if (parts.Length != 3)
        {
            return false;
        }

        var header = Header(jws);
        if (header.GetProperty("alg").GetString() != "ES256")
        {
            return false;
        }

        var kid = header.GetProperty("kid").GetString();
        foreach (var jwk in jwks.GetProperty("keys").EnumerateArray())
        {
            if (jwk.GetProperty("kid").GetString() != kid || jwk.GetProperty("kty").GetString() != "EC" || jwk.GetProperty("crv").GetString() != "P-256")
            {
                continue;
            }

            using var key = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Base64Url.DecodeFromChars(jwk.GetProperty("x").GetString()!), Y = Base64Url.DecodeFromChars(jwk.GetProperty("y").GetString()!) },
            });
            return key.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), Base64Url.DecodeFromChars(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        return false;
    }

    /// <summary>A JWKS document publishing the public half of <paramref name="key"/>.</summary>
    public static string RsaJwks(RSA key, string kid)
    {
        var parameters = key.ExportParameters(false);
        return JsonSerializer.Serialize(new
        {
            keys = new[]
            {
                new { kty = "RSA", kid, alg = "RS256", use = "sig", n = Base64Url.EncodeToString(parameters.Modulus!), e = Base64Url.EncodeToString(parameters.Exponent!) },
            },
        });
    }

    private static JsonElement Part(string jws, int index)
    {
        var parts = jws.Split('.');
        using var document = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[index]));
        return document.RootElement.Clone();
    }
}
