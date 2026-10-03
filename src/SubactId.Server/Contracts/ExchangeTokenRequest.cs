using SubactId.Core.Validation;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Contracts;

/// <summary>
/// The form body of a token-exchange request to <c>POST /oauth2/token</c> (spec section 3,
/// RFC 8693). <see cref="Validate"/> reports every problem at once. Token values are never
/// included in an error.
/// </summary>
/// <param name="GrantType">Must be <see cref="TokenExchangeGrantType"/>.</param>
/// <param name="SubjectToken">The human's access token from the upstream identity provider.</param>
/// <param name="SubjectTokenType">Must be <see cref="AccessTokenType"/>.</param>
/// <param name="ActorToken">The agent's <c>private_key_jwt</c> client assertion.</param>
/// <param name="ActorTokenType">Must be <see cref="JwtTokenType"/>.</param>
/// <param name="RequestedTokenType">Optional. When present, must be <see cref="AccessTokenType"/>.</param>
/// <param name="Resource">The audience the token is for, an absolute http or https URL.</param>
/// <param name="Scope">Space-separated scopes requested.</param>
/// <param name="ClientId">Optional. When present, must name the same agent as the assertion.</param>
public sealed record ExchangeTokenRequest(
    string? GrantType,
    string? SubjectToken,
    string? SubjectTokenType,
    string? ActorToken,
    string? ActorTokenType,
    string? RequestedTokenType,
    string? Resource,
    string? Scope,
    string? ClientId)
{
    /// <summary>Prints the record with the subject token and the actor assertion redacted, so a log line or exception message that includes it carries no credential.</summary>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"GrantType = {GrantType}, SubjectToken = {Redacted.Of(SubjectToken)}, SubjectTokenType = {SubjectTokenType}, ActorToken = {Redacted.Of(ActorToken)}, ActorTokenType = {ActorTokenType}, RequestedTokenType = {RequestedTokenType}, Resource = {Resource}, Scope = {Scope}, ClientId = {ClientId}");
        return true;
    }


    /// <summary>The RFC 8693 grant type.</summary>
    public const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>The RFC 8693 access token type. Used for the subject token and for every issued token.</summary>
    public const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>The RFC 8693 JWT token type, used for the actor token.</summary>
    public const string JwtTokenType = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>The requested scopes: <see cref="Scope"/> split on spaces, in order, empty entries dropped.</summary>
    public IReadOnlyList<string> Scopes { get; } = FormParameters.SplitScopes(Scope);

    /// <summary>
    /// Reads the request from a form. Empty values count as omitted (RFC 6749 section 3.2).
    /// Repeated ones are reported in <paramref name="errors"/> and not used.
    /// </summary>
    /// <param name="form">The parsed form body.</param>
    /// <param name="errors">Parameters that were repeated.</param>
    public static ExchangeTokenRequest FromForm(IFormCollection form, out IReadOnlyList<ValidationError> errors)
    {
        ArgumentNullException.ThrowIfNull(form);

        var repeated = new List<ValidationError>();
        var request = new ExchangeTokenRequest(
            FormParameters.Single(form, "grant_type", repeated),
            FormParameters.Single(form, "subject_token", repeated),
            FormParameters.Single(form, "subject_token_type", repeated),
            FormParameters.Single(form, "actor_token", repeated),
            FormParameters.Single(form, "actor_token_type", repeated),
            FormParameters.Single(form, "requested_token_type", repeated),
            FormParameters.Single(form, "resource", repeated),
            FormParameters.Single(form, "scope", repeated),
            FormParameters.Single(form, "client_id", repeated));
        errors = repeated;
        return request;
    }

    /// <summary>Every problem with the request, named by parameter. Empty means the request is well-formed.</summary>
    public IReadOnlyList<ValidationError> Validate()
    {
        var errors = new List<ValidationError>();

        if (GrantType != TokenExchangeGrantType)
        {
            errors.Add(new("grant_type", $"must be {TokenExchangeGrantType}."));
        }

        FormParameters.RequireToken(SubjectToken, "subject_token", errors, Jws.MaxUpstreamTokenLength);
        if (SubjectTokenType != AccessTokenType)
        {
            errors.Add(new("subject_token_type", $"must be {AccessTokenType}."));
        }

        FormParameters.RequireToken(ActorToken, "actor_token", errors);
        if (ActorTokenType != JwtTokenType)
        {
            errors.Add(new("actor_token_type", $"must be {JwtTokenType}."));
        }

        if (RequestedTokenType is not null && RequestedTokenType != AccessTokenType)
        {
            errors.Add(new("requested_token_type", $"must be {AccessTokenType} when present."));
        }

        FormParameters.RequireResource(Resource, errors);
        FormParameters.RequireScope(Scope, Scopes, errors);
        FormParameters.OptionalClientId(ClientId, errors);
        return errors;
    }
}
