using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>
/// An OAuth 2.0 error body (RFC 6749 section 5.2) as spec section 8 requires: the code and a
/// human-readable description, and on an <c>access_denied</c> from the token endpoint the
/// machine-readable reason, an extension member section 5.2 permits. Never carries a token, a key
/// or a stack trace.
/// </summary>
public sealed record OAuthErrorResponse
{
    /// <summary>Builds an error body.</summary>
    /// <param name="error">The error code.</param>
    /// <param name="errorDescription">What went wrong, for a developer reading the response.</param>
    /// <param name="reason">The audit reason, only on <c>access_denied</c>.</param>
    /// <exception cref="ArgumentException"><paramref name="reason"/> given with an error other than <c>access_denied</c>.</exception>
    public OAuthErrorResponse(string error, string errorDescription, string? reason = null)
    {
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(errorDescription);
        if (reason is not null && !string.Equals(error, AccessDenied, StringComparison.Ordinal))
        {
            throw new ArgumentException("Only access_denied carries a reason.", nameof(reason));
        }

        Error = error;
        ErrorDescription = errorDescription;
        Reason = reason;
    }

    /// <summary>The error code. Fixed at construction, so a reason can never end up on another code.</summary>
    [JsonPropertyName("error")]
    public string Error { get; }

    /// <summary>What went wrong, for a developer reading the response.</summary>
    [JsonPropertyName("error_description")]
    public string ErrorDescription { get; }

    /// <summary>
    /// The reason written to the audit record for this refusal, such as <c>task_revoked</c>, so a
    /// client can tell a task that is over from one it may use again later. Only an
    /// <c>access_denied</c> carries one, and only once the agent has authenticated. Omitted
    /// otherwise.
    /// </summary>
    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; }

    /// <summary>The request is missing a parameter, repeats one, or has one with an invalid value.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>Client authentication failed: the agent is unknown or its assertion was rejected.</summary>
    public const string InvalidClient = "invalid_client";

    /// <summary>The subject token is expired, invalid or from an untrusted issuer.</summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>The grant type is not supported.</summary>
    public const string UnsupportedGrantType = "unsupported_grant_type";

    /// <summary>The scope intersection is empty, or refresh tried to widen.</summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>The audience is not in the agent's <c>allowed_audiences</c>.</summary>
    public const string InvalidTarget = "invalid_target";

    /// <summary>The agent is disabled, the task is revoked, or the delegation depth is exceeded.</summary>
    public const string AccessDenied = "access_denied";

    /// <summary>The server could not reach the keys it needs to verify a credential. The caller should retry.</summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";

    /// <summary>Too many requests from this source; answered as <c>429</c> with <c>Retry-After</c>.</summary>
    public const string SlowDown = "slow_down";

    /// <summary>The HTTP status for <paramref name="error"/>: 401 for <see cref="InvalidClient"/>, 503 for <see cref="TemporarilyUnavailable"/>, otherwise 400 (RFC 6749 section 5.2).</summary>
    /// <param name="error">An error code.</param>
    public static int StatusCodeFor(string error) => error switch
    {
        InvalidClient => StatusCodes.Status401Unauthorized,
        TemporarilyUnavailable => StatusCodes.Status503ServiceUnavailable,
        _ => StatusCodes.Status400BadRequest,
    };

    /// <summary>The JSON response for this error with the status <see cref="StatusCodeFor"/> gives.</summary>
    public IResult ToResult() => Results.Json(this, statusCode: StatusCodeFor(Error));
}
