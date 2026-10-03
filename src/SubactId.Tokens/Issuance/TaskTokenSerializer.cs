using System.Text.Json;
using SubactId.Core.Tokens;
using SubactId.Tokens;
using SubactId.Tokens.Signing;

namespace SubactId.Tokens.Issuance;

/// <summary>
/// Writes a <see cref="TaskTokenClaims"/> as the exact JSON of spec section 4 and signs it.
/// Claim names and nesting are written by hand, not derived from a type.
/// </summary>
public static class TaskTokenSerializer
{
    /// <summary>The claim set as UTF-8 JSON, in the spec's member order, timestamps as whole Unix seconds.</summary>
    /// <param name="claims">The claims.</param>
    public static byte[] ToJson(TaskTokenClaims claims)
    {
        ArgumentNullException.ThrowIfNull(claims);

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("iss", IssuerUrl.Canonical(claims.Issuer));
            writer.WriteString("sub", claims.Subject);
            writer.WriteString("aud", claims.Audience);
            writer.WriteNumber("exp", claims.ExpiresAt.ToUnixTimeSeconds());
            writer.WriteNumber("iat", claims.IssuedAt.ToUnixTimeSeconds());
            writer.WriteString("jti", claims.Jti);
            writer.WriteString("scope", string.Join(' ', claims.Scopes));
            writer.WriteString("client_id", claims.ClientId);
            writer.WritePropertyName("act");
            WriteActor(writer, claims.Actor);
            if (claims.IntrospectRequired)
            {
                // Written only when true.
                writer.WriteBoolean("introspect_required", true);
            }

            writer.WriteStartObject("task");
            writer.WriteString("id", claims.Task.Id);
            writer.WriteNumber("exp", claims.Task.ExpiresAt.ToUnixTimeSeconds());
            writer.WriteString("sponsor", claims.Task.Sponsor);
            writer.WriteEndObject();
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    /// <summary>The signed compact JWS for <paramref name="claims"/>, using the set's active key and <c>typ: at+jwt</c>.</summary>
    /// <param name="keys">The signing keys.</param>
    /// <param name="claims">The claims.</param>
    public static string Sign(SigningKeySet keys, TaskTokenClaims claims) => Jws.Sign(keys, ToJson(claims));

    private static void WriteActor(Utf8JsonWriter writer, ActorClaim actor)
    {
        writer.WriteStartObject();
        writer.WriteString("sub", actor.Subject);
        if (actor.Instance is not null)
        {
            writer.WriteString("instance", actor.Instance);
        }

        writer.WriteNumber("depth", actor.Depth);
        if (actor.Actor is not null)
        {
            writer.WritePropertyName("act");
            WriteActor(writer, actor.Actor);
        }

        writer.WriteEndObject();
    }
}
