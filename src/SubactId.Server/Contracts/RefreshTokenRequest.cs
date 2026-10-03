using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>
/// The form body of a refresh request to <c>POST /oauth2/token</c>: the parameters of spec
/// section 5 plus the agent's <c>private_key_jwt</c> assertion (RFC 7523 section 2.2). A grant is
/// bound to its agent, so only that agent's key may redeem it.
/// </summary>
/// <param name="GrantType">Must be <see cref="RefreshTokenGrantType"/>.</param>
/// <param name="RefreshToken">The task grant issued by the exchange.</param>
/// <param name="Resource">The audience, which must be the task's.</param>
/// <param name="Scope">Space-separated scopes requested. Never wider than granted.</param>
/// <param name="ClientAssertion">The agent's <c>private_key_jwt</c> assertion.</param>
/// <param name="ClientAssertionType">Must be <see cref="JwtBearerAssertionType"/>.</param>
/// <param name="ClientId">Optional. When present, must name the same agent as the assertion.</param>
public sealed record RefreshTokenRequest(
    string? GrantType,
    string? RefreshToken,
    string? Resource,
    string? Scope,
    string? ClientAssertion,
    string? ClientAssertionType,
    string? ClientId)
{
    /// <summary>Prints the record with the task grant and the client assertion redacted, so a log line or exception message that includes it carries no credential.</summary>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"GrantType = {GrantType}, RefreshToken = {Redacted.Of(RefreshToken)}, Resource = {Resource}, Scope = {Scope}, ClientAssertion = {Redacted.Of(ClientAssertion)}, ClientAssertionType = {ClientAssertionType}, ClientId = {ClientId}");
        return true;
    }


    /// <summary>The RFC 6749 refresh grant type.</summary>
    public const string RefreshTokenGrantType = "refresh_token";

    /// <summary>The RFC 7523 client assertion type.</summary>
    public const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /// <summary>Longest <c>refresh_token</c> accepted. A real grant is far shorter.</summary>
    public const int MaxRefreshTokenLength = 512;

    /// <summary>The requested scopes: <see cref="Scope"/> split on spaces, in order, empty entries dropped.</summary>
    public IReadOnlyList<string> Scopes { get; } = FormParameters.SplitScopes(Scope);

    /// <summary>Reads the request from a form. Empty values count as omitted. Repeated ones are reported in <paramref name="errors"/>.</summary>
    /// <param name="form">The parsed form body.</param>
    /// <param name="errors">Parameters that were repeated.</param>
    public static RefreshTokenRequest FromForm(IFormCollection form, out IReadOnlyList<ValidationError> errors)
    {
        ArgumentNullException.ThrowIfNull(form);

        var repeated = new List<ValidationError>();
        var request = new RefreshTokenRequest(
            FormParameters.Single(form, "grant_type", repeated),
            FormParameters.Single(form, "refresh_token", repeated),
            FormParameters.Single(form, "resource", repeated),
            FormParameters.Single(form, "scope", repeated),
            FormParameters.Single(form, "client_assertion", repeated),
            FormParameters.Single(form, "client_assertion_type", repeated),
            FormParameters.Single(form, "client_id", repeated));
        errors = repeated;
        return request;
    }

    /// <summary>Every problem with the request, named by parameter. Empty means the request is well-formed.</summary>
    public IReadOnlyList<ValidationError> Validate()
    {
        var errors = new List<ValidationError>();

        if (GrantType != RefreshTokenGrantType)
        {
            errors.Add(new("grant_type", $"must be {RefreshTokenGrantType}."));
        }

        if (RefreshToken is null)
        {
            errors.Add(new("refresh_token", "is required."));
        }
        else if (RefreshToken.Length > MaxRefreshTokenLength)
        {
            errors.Add(new("refresh_token", $"must be at most {MaxRefreshTokenLength} characters."));
        }

        FormParameters.RequireResource(Resource, errors);
        FormParameters.RequireScope(Scope, Scopes, errors);
        FormParameters.RequireToken(ClientAssertion, "client_assertion", errors);
        if (ClientAssertionType != JwtBearerAssertionType)
        {
            errors.Add(new("client_assertion_type", $"must be {JwtBearerAssertionType}."));
        }

        FormParameters.OptionalClientId(ClientId, errors);
        return errors;
    }
}
