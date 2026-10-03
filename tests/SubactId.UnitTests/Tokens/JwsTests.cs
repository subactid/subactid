using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using SubactId.Tokens.Signing;
using Xunit;

namespace SubactId.UnitTests.Tokens;

public class JwsTests
{
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("{\"sub\":\"human\",\"act\":{\"sub\":\"agent:jira-triage\"}}");

    [Fact]
    public void Signs_with_the_active_key_and_writes_alg_kid_and_typ()
    {
        using var set = TwoKeySet("old", "new", active: "new");

        var token = Jws.Sign(set, Payload);

        var parts = token.Split('.');
        Assert.Equal(3, parts.Length);
        Assert.All(parts, p => Assert.DoesNotContain(p, c => c is '=' or '+' or '/'));
        using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
        Assert.Equal("ES256", header.RootElement.GetProperty("alg").GetString());
        Assert.Equal("new", header.RootElement.GetProperty("kid").GetString());
        Assert.Equal("at+jwt", header.RootElement.GetProperty("typ").GetString());
        Assert.Equal(Payload, Base64Url.DecodeFromChars(parts[1]));
        Assert.Equal(64, Base64Url.DecodeFromChars(parts[2]).Length);
    }

    [Fact]
    public void Verifies_its_own_tokens()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var token = Jws.Sign(set, Payload, typ: "custom");

        Assert.True(Jws.TryVerify(set, token, out var header, out var payload));
        Assert.Equal("new", header!.Kid);
        Assert.Equal("custom", header.Typ);
        Assert.Equal(Payload, payload);
    }

    [Fact]
    public void Rotation_keeps_old_tokens_verifying_until_the_old_key_is_retired()
    {
        var oldPem = TestKeys.Pkcs8Pem();
        var newPem = TestKeys.Pkcs8Pem();

        // Step 1: only the old key exists and signs.
        using var before = SigningKeySetLoader.Load([Source("old", oldPem)], null);
        var oldToken = Jws.Sign(before, Payload);

        // Step 2: the new key is published alongside the old one and becomes the signer.
        using var during = SigningKeySetLoader.Load([Source("old", oldPem), Source("new", newPem)], "new");
        Assert.True(Jws.TryVerify(during, oldToken, out var oldHeader, out _));
        Assert.Equal("old", oldHeader!.Kid);
        var newToken = Jws.Sign(during, Payload);
        Assert.True(Jws.TryVerify(during, newToken, out var newHeader, out _));
        Assert.Equal("new", newHeader!.Kid);
        Assert.Equal(["old", "new"], during.ToJwks().Keys.Select(k => k.Kid));

        // Step 3: the old key is retired; its tokens stop verifying, the new key's keep working.
        using var after = SigningKeySetLoader.Load([Source("new", newPem)], null);
        Assert.True(Jws.TryVerify(after, newToken, out _, out _));
        Assert.False(Jws.TryVerify(after, oldToken, out _, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a.b")]
    [InlineData("a.b.c.d")]
    [InlineData("..")]
    [InlineData("not base64!.payload.sig")]
    public void Rejects_malformed_tokens_without_throwing(string token)
    {
        using var set = TwoKeySet("old", "new", active: "new");

        Assert.False(Jws.TryVerify(set, token, out var header, out var payload));
        Assert.Null(header);
        Assert.Null(payload);
    }

    [Fact]
    public void Rejects_a_null_token()
    {
        using var set = TwoKeySet("old", "new", active: "new");

        Assert.False(Jws.TryVerify(set, null, out _, out _));
    }

    [Fact]
    public void Rejects_a_tampered_payload_and_a_tampered_signature()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var parts = Jws.Sign(set, Payload).Split('.');

        var otherPayload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{\"sub\":\"agent:jira-triage\"}"));
        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{otherPayload}.{parts[2]}", out _, out _));

        var signature = Base64Url.DecodeFromChars(parts[2]);
        signature[0] ^= 0x01;
        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{parts[1]}.{Base64Url.EncodeToString(signature)}", out _, out _));
    }

    [Theory]
    [InlineData("{\"alg\":\"none\",\"kid\":\"new\"}")]
    [InlineData("{\"alg\":\"RS256\",\"kid\":\"new\"}")]
    [InlineData("{\"alg\":\"HS256\",\"kid\":\"new\"}")]
    [InlineData("{\"alg\":\"es256\",\"kid\":\"new\"}")]
    [InlineData("{\"alg\":\"ES256\"}")]
    [InlineData("{\"alg\":\"ES256\",\"kid\":\"\"}")]
    [InlineData("{\"alg\":\"ES256\",\"kid\":\"unknown\"}")]
    [InlineData("[]")]
    [InlineData("null")]
    public void Rejects_headers_that_do_not_name_es256_and_a_published_key_even_with_a_valid_signature(string headerJson)
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var signingInput = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(headerJson))}.{Base64Url.EncodeToString(Payload)}";
        var signature = set.Active.Sign(Encoding.ASCII.GetBytes(signingInput));

        Assert.False(Jws.TryVerify(set, $"{signingInput}.{Base64Url.EncodeToString(signature)}", out _, out _));
    }

    [Fact]
    public void Rejects_an_alg_none_token_with_an_empty_signature()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var header = Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"kid\":\"new\"}"));

        Assert.False(Jws.TryVerify(set, $"{header}.{Base64Url.EncodeToString(Payload)}.", out _, out _));
    }

    [Fact]
    public void Rejects_a_token_signed_by_a_key_that_is_not_published()
    {
        using var published = TwoKeySet("old", "new", active: "new");
        using var rogue = SigningKeySetLoader.Load([Source("new", TestKeys.Pkcs8Pem())], null);

        // Same kid, different key: the signature does not verify against the published key.
        var token = Jws.Sign(rogue, Payload);

        Assert.False(Jws.TryVerify(published, token, out _, out _));
    }

    [Fact]
    public void Rejects_a_signature_that_is_not_64_bytes()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var parts = Jws.Sign(set, Payload).Split('.');
        var signature = Base64Url.DecodeFromChars(parts[2]);

        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{parts[1]}.{Base64Url.EncodeToString(signature[..63])}", out _, out _));
        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{parts[1]}.{Base64Url.EncodeToString([.. signature, 0])}", out _, out _));
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("\n")]
    [InlineData("=")]
    [InlineData("==")]
    public void Rejects_non_canonical_base64url_even_though_the_decoder_would_accept_it(string decoration)
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var parts = Jws.Sign(set, Payload).Split('.');

        // Pad the payload so a lenient decoder could still read it, and decorate each position in turn.
        Assert.False(Jws.TryVerify(set, $"{parts[0]}{decoration}.{parts[1]}.{parts[2]}", out _, out _));
        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{parts[1]}{decoration}.{parts[2]}", out _, out _));
        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{parts[1]}.{parts[2]}{decoration}", out _, out _));
        Assert.False(Jws.TryVerify(set, $"{decoration}{parts[0]}.{parts[1]}.{parts[2]}", out _, out _));
    }

    [Fact]
    public void Rejects_standard_base64_alphabet_in_any_segment()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var parts = Jws.Sign(set, Payload).Split('.');
        var standard = Convert.ToBase64String(Payload).TrimEnd('=');
        Assert.True(standard.Contains('+') || standard.Contains('/') || standard == parts[1]);

        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{parts[1].Replace('-', '+').Replace('_', '/')}+.{parts[2]}", out _, out _));
        Assert.False(Jws.TryVerify(set, $"{parts[0]}.{parts[1]}.{parts[2]}/", out _, out _));
    }

    [Fact]
    public void Rejects_a_crit_header_even_when_correctly_signed()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var signingInput = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{\"alg\":\"ES256\",\"kid\":\"new\",\"crit\":[\"exp\"],\"exp\":1}"))}.{Base64Url.EncodeToString(Payload)}";
        var signature = set.Active.Sign(Encoding.ASCII.GetBytes(signingInput));

        Assert.False(Jws.TryVerify(set, $"{signingInput}.{Base64Url.EncodeToString(signature)}", out _, out _));
    }

    [Theory]
    [InlineData("{\"alg\":5,\"kid\":\"new\"}")]
    [InlineData("{\"alg\":[\"ES256\"],\"kid\":\"new\"}")]
    [InlineData("{\"alg\":\"ES256\",\"kid\":5}")]
    [InlineData("{\"ALG\":\"ES256\",\"KID\":\"new\"}")]
    [InlineData("{\"alg\":\"ES256\",\"kid\":\"new\"} trailing")]
    [InlineData("{\"alg\":\"ES256 \",\"kid\":\"new\"}")]
    public void Rejects_headers_with_wrong_types_case_or_trailing_content(string headerJson)
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var signingInput = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(headerJson))}.{Base64Url.EncodeToString(Payload)}";
        var signature = set.Active.Sign(Encoding.ASCII.GetBytes(signingInput));

        Assert.False(Jws.TryVerify(set, $"{signingInput}.{Base64Url.EncodeToString(signature)}", out _, out _));
    }

    [Fact]
    public void Ignores_unknown_header_members_that_are_covered_by_the_signature()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var signingInput = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes("{\"alg\":\"ES256\",\"kid\":\"new\",\"jku\":\"https://attacker.example/jwks\",\"jwk\":{}}"))}.{Base64Url.EncodeToString(Payload)}";
        var signature = set.Active.Sign(Encoding.ASCII.GetBytes(signingInput));

        // jku and jwk are ignored, never followed: the signature still had to come from a published key.
        Assert.True(Jws.TryVerify(set, $"{signingInput}.{Base64Url.EncodeToString(signature)}", out var header, out _));
        Assert.Equal("new", header!.Kid);
    }

    [Fact]
    public void Rejects_oversized_tokens_before_decoding_anything()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var huge = Jws.Sign(set, new byte[Jws.MaxTokenLength], typ: "x");

        Assert.True(huge.Length > Jws.MaxTokenLength);
        Assert.False(Jws.TryVerify(set, huge, out _, out _));
        Assert.True(Jws.TryVerify(set, Jws.Sign(set, new byte[4096]), out _, out _));
    }

    [Fact]
    public async Task Signing_and_verifying_concurrently_on_one_key_set_is_safe()
    {
        using var set = TwoKeySet("old", "new", active: "new");
        var failures = 0;

        await Parallel.ForAsync(0, 64, async (worker, cancellationToken) =>
        {
            await Task.Yield();
            for (var i = 0; i < 200; i++)
            {
                var payload = Encoding.UTF8.GetBytes($"{{\"w\":{worker},\"i\":{i}}}");
                var token = Jws.Sign(set, payload);
                if (!Jws.TryVerify(set, token, out _, out var back) || !payload.AsSpan().SequenceEqual(back))
                {
                    Interlocked.Increment(ref failures);
                }
            }
        });

        Assert.Equal(0, failures);
    }

    private static SigningKeySource Source(string kid, string pem) => new(kid, pem, null);

    private static SigningKeySet TwoKeySet(string first, string second, string active) =>
        SigningKeySetLoader.Load([Source(first, TestKeys.Pkcs8Pem()), Source(second, TestKeys.Pkcs8Pem())], active);
}
