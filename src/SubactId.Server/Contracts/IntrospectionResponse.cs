using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>
/// The RFC 7662 introspection response as spec section 6 shapes it. An inactive token carries
/// only <c>active</c>, plus <c>revoked_at</c> and <c>revocation_reason</c> when it or its task
/// was revoked. An active token carries its claims, <c>sub</c>, <c>act</c>, <c>scope</c> and
/// <c>task</c> among them, plus <c>task_id</c>. Absent members are omitted, not written as null.
/// </summary>
/// <param name="Active">Whether the token is good right now.</param>
/// <param name="RevokedAt">When the token or its task was revoked.</param>
/// <param name="RevocationReason">Why, for example <c>operator_kill_switch</c>.</param>
/// <param name="Scope">Granted scopes, space-separated.</param>
/// <param name="ClientId">The acting agent, as <c>agent:</c> plus its id.</param>
/// <param name="Sub">The human.</param>
/// <param name="Act">The actor chain, as it appears in the token.</param>
/// <param name="IntrospectRequired">Present, as <c>true</c>, only when the token carries it.</param>
/// <param name="Task">The token's <c>task</c> claim: the task, its expiry and its sponsor.</param>
/// <param name="Aud">The audience.</param>
/// <param name="Iss">This control plane.</param>
/// <param name="Exp">Expiry, Unix seconds.</param>
/// <param name="Iat">Issue time, Unix seconds.</param>
/// <param name="Jti">The token identifier.</param>
/// <param name="TaskId">The task the token belongs to.</param>
/// <param name="TokenType">Always <c>Bearer</c> when active.</param>
public sealed record IntrospectionResponse(
    [property: JsonPropertyName("active")] bool Active,
    [property: JsonPropertyName("revoked_at"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DateTimeOffset? RevokedAt = null,
    [property: JsonPropertyName("revocation_reason"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? RevocationReason = null,
    [property: JsonPropertyName("scope"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Scope = null,
    [property: JsonPropertyName("client_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? ClientId = null,
    [property: JsonPropertyName("sub"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Sub = null,
    [property: JsonPropertyName("act"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] JsonElement? Act = null,
    [property: JsonPropertyName("introspect_required"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] bool? IntrospectRequired = null,
    [property: JsonPropertyName("task"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] IntrospectionTask? Task = null,
    [property: JsonPropertyName("aud"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Aud = null,
    [property: JsonPropertyName("iss"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Iss = null,
    [property: JsonPropertyName("exp"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Exp = null,
    [property: JsonPropertyName("iat"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] long? Iat = null,
    [property: JsonPropertyName("jti"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Jti = null,
    [property: JsonPropertyName("task_id"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TaskId = null,
    [property: JsonPropertyName("token_type"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? TokenType = null)
{
    /// <summary>The answer for anything that is not a live token of ours. Carries no detail.</summary>
    public static readonly IntrospectionResponse Inactive = new(false);
}

/// <summary>The <c>task</c> claim of an active token, as spec section 4 shapes it.</summary>
/// <param name="Id">The task.</param>
/// <param name="Exp">When the task ends, Unix seconds.</param>
/// <param name="Sponsor">The human the task acts for.</param>
public sealed record IntrospectionTask(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("exp")] long Exp,
    [property: JsonPropertyName("sponsor")] string Sponsor);
