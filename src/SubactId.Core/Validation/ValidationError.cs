namespace SubactId.Core.Validation;

/// <summary>One validation problem, attributed to a field named as in the spec (snake_case).</summary>
/// <param name="Field">The spec field name, for example <c>max_token_ttl</c>.</param>
/// <param name="Message">What is wrong. Never echoes the submitted value.</param>
public sealed record ValidationError(string Field, string Message);
