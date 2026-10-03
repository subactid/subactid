using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>
/// The form body of <c>POST /oauth2/revoke</c> (RFC 7009 section 2.1): the token, an optional
/// hint, and the agent's <c>private_key_jwt</c> assertion. Only the agent a token was issued to
/// may revoke it.
/// </summary>
/// <param name="Token">The task token or task grant to revoke.</param>
/// <param name="TokenTypeHint">Optional, and not consulted. An unrecognised hint is ignored (RFC 7009 section 2.1).</param>
/// <param name="ClientAssertion">The agent's <c>private_key_jwt</c> assertion.</param>
/// <param name="ClientAssertionType">Must be <see cref="RefreshTokenRequest.JwtBearerAssertionType"/>.</param>
/// <param name="ClientId">Optional. When present, must name the same agent as the assertion.</param>
public sealed record RevokeTokenRequest(
    string? Token,
    string? TokenTypeHint,
    string? ClientAssertion,
    string? ClientAssertionType,
    string? ClientId)
{
    /// <summary>Prints the record with the token and the client assertion redacted, so a log line or exception message that includes it carries no credential.</summary>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"Token = {Redacted.Of(Token)}, TokenTypeHint = {TokenTypeHint}, ClientAssertion = {Redacted.Of(ClientAssertion)}, ClientAssertionType = {ClientAssertionType}, ClientId = {ClientId}");
        return true;
    }


    /// <summary>Reads the request from a form. Empty values count as omitted. Repeated ones are reported in <paramref name="errors"/>.</summary>
    /// <param name="form">The parsed form body.</param>
    /// <param name="errors">Parameters that were repeated.</param>
    public static RevokeTokenRequest FromForm(IFormCollection form, out IReadOnlyList<ValidationError> errors)
    {
        ArgumentNullException.ThrowIfNull(form);

        var repeated = new List<ValidationError>();
        var request = new RevokeTokenRequest(
            FormParameters.Single(form, "token", repeated),
            FormParameters.Single(form, "token_type_hint", repeated),
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

        FormParameters.RequireToken(Token, "token", errors);
        FormParameters.RequireToken(ClientAssertion, "client_assertion", errors);
        if (ClientAssertionType != RefreshTokenRequest.JwtBearerAssertionType)
        {
            errors.Add(new("client_assertion_type", $"must be {RefreshTokenRequest.JwtBearerAssertionType}."));
        }

        FormParameters.OptionalClientId(ClientId, errors);
        return errors;
    }
}
