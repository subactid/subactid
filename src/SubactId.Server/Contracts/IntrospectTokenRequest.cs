using SubactId.Core.Validation;

namespace SubactId.Server.Contracts;

/// <summary>The form body of <c>POST /oauth2/introspect</c> (RFC 7662 section 2.1).</summary>
/// <param name="Token">The task token to describe.</param>
/// <param name="TokenTypeHint">Optional and ignored.</param>
public sealed record IntrospectTokenRequest(string? Token, string? TokenTypeHint)
{
    /// <summary>Prints the record with the token redacted, so a log line or exception message that includes it carries no credential.</summary>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append($"Token = {Redacted.Of(Token)}, TokenTypeHint = {TokenTypeHint}");
        return true;
    }


    /// <summary>Reads the request from a form. Empty values count as omitted. Repeated ones are reported in <paramref name="errors"/>.</summary>
    /// <param name="form">The parsed form body.</param>
    /// <param name="errors">Parameters that were repeated.</param>
    public static IntrospectTokenRequest FromForm(IFormCollection form, out IReadOnlyList<ValidationError> errors)
    {
        ArgumentNullException.ThrowIfNull(form);

        var repeated = new List<ValidationError>();
        var request = new IntrospectTokenRequest(FormParameters.Single(form, "token", repeated), FormParameters.Single(form, "token_type_hint", repeated));
        errors = repeated;
        return request;
    }

    /// <summary>Every problem with the request, named by parameter. Empty means the request is well-formed.</summary>
    public IReadOnlyList<ValidationError> Validate()
    {
        var errors = new List<ValidationError>();
        FormParameters.RequireToken(Token, "token", errors);
        return errors;
    }
}
