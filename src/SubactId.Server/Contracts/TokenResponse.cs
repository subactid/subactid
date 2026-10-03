using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>The successful response of <c>POST /oauth2/token</c> (spec section 3).</summary>
/// <param name="AccessToken">The signed task token.</param>
/// <param name="IssuedTokenType">Always <see cref="ExchangeTokenRequest.AccessTokenType"/>.</param>
/// <param name="TokenType">Always <c>Bearer</c>.</param>
/// <param name="ExpiresIn">Seconds until the token expires.</param>
/// <param name="Scope">The granted scopes, space-separated.</param>
/// <param name="RefreshToken">The task grant. Shown only here. The server keeps only its hash.</param>
/// <param name="TaskId">The task the token and grant belong to.</param>
/// <param name="TaskExpiresAt">When the task, and with it the grant, expires.</param>
public sealed record TokenResponse(
    [property: JsonPropertyName("access_token")] string AccessToken,
    [property: JsonPropertyName("issued_token_type")] string IssuedTokenType,
    [property: JsonPropertyName("token_type")] string TokenType,
    [property: JsonPropertyName("expires_in")] long ExpiresIn,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("refresh_token")] string RefreshToken,
    [property: JsonPropertyName("task_id")] string TaskId,
    [property: JsonPropertyName("task_expires_at")] DateTimeOffset TaskExpiresAt)
{
    /// <summary>Prints the record with the access token and the task grant redacted, so a log line or exception message that includes it carries no credential.</summary>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"AccessToken = {Redacted.Of(AccessToken)}, IssuedTokenType = {IssuedTokenType}, TokenType = {TokenType}, ExpiresIn = {ExpiresIn}, Scope = {Scope}, RefreshToken = {Redacted.Of(RefreshToken)}, TaskId = {TaskId}, TaskExpiresAt = {TaskExpiresAt:O}");
        return true;
    }


    /// <summary>The <c>token_type</c> every response carries.</summary>
    public const string Bearer = "Bearer";
}
