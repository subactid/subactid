using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using SubactId.Core.Tokens;

namespace SubactId.Tokens.Issuance;

/// <summary>The claims of a task token as read back strictly from a verified payload.</summary>
/// <param name="Jti">Token identifier.</param>
/// <param name="TaskId">The task the token belongs to.</param>
/// <param name="AgentId">The acting agent's id, taken from <c>client_id</c> without the prefix.</param>
/// <param name="ClientId">The acting agent as written, <c>agent:</c> plus its id.</param>
/// <param name="Subject">The human.</param>
/// <param name="Scope">Granted scopes, space-separated, if present.</param>
/// <param name="Audience">The audience, if present.</param>
/// <param name="Issuer">The issuer, if present.</param>
/// <param name="ExpiresAt">Token expiry.</param>
/// <param name="IssuedAt">Issue time in Unix seconds, if present.</param>
/// <param name="Depth">The outermost actor's depth, if present.</param>
/// <param name="Act">The <c>act</c> claim as written.</param>
/// <param name="TaskExpiresAt">The task's expiry in Unix seconds, <c>task.exp</c>.</param>
/// <param name="TaskSponsor">The human the task acts for, <c>task.sponsor</c>.</param>
/// <param name="IntrospectRequired">Whether the token carries <c>introspect_required: true</c>.</param>
public sealed record TaskTokenView(string Jti, string TaskId, string AgentId, string ClientId, string Subject, string? Scope, string? Audience, string? Issuer, DateTimeOffset ExpiresAt, long? IssuedAt, int? Depth, JsonElement Act, long TaskExpiresAt, string TaskSponsor, bool IntrospectRequired);

/// <summary>
/// Reads a verified task token payload strictly. The token, task, agent and human claims must be
/// present, well-formed and within the ledger's bounds, and <c>sub</c> must not carry the agent
/// prefix. Otherwise the payload is not a task token.
/// </summary>
public static class TaskTokenReader
{
    /// <summary>Longest <c>jti</c> or task id accepted.</summary>
    public const int MaxIdLength = 64;

    /// <summary>Longest <c>sub</c> accepted.</summary>
    public const int MaxSubjectLength = 256;

    /// <summary>Reads <paramref name="payload"/>; <c>false</c>, never an exception, when it is not a task token.</summary>
    /// <param name="payload">A payload that verified against this control plane's keys.</param>
    /// <param name="view">The claims, when it is a task token.</param>
    public static bool TryRead(byte[] payload, [NotNullWhen(true)] out TaskTokenView? view)
    {
        ArgumentNullException.ThrowIfNull(payload);

        view = null;
        try
        {
            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || Text(root, "jti") is not { Length: > 0 and <= MaxIdLength } jti
                || Text(root, "client_id") is not { } clientId || !clientId.StartsWith(ActorClaim.AgentSubjectPrefix, StringComparison.Ordinal) || clientId.Length <= ActorClaim.AgentSubjectPrefix.Length
                || Text(root, "sub") is not { Length: > 0 and <= MaxSubjectLength } subject || ActorClaim.IsAgentSubject(subject)
                || !root.TryGetProperty("task", out var task) || task.ValueKind != JsonValueKind.Object || Text(task, "id") is not { Length: > 0 and <= MaxIdLength } taskId
                || !task.TryGetProperty("exp", out var taskExp) || taskExp.ValueKind != JsonValueKind.Number || !taskExp.TryGetInt64(out var taskExpSeconds)
                || Text(task, "sponsor") is not { Length: > 0 and <= MaxSubjectLength } sponsor
                || !root.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number || !exp.TryGetInt64(out var expSeconds)
                || !root.TryGetProperty("act", out var act) || act.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            // Written only as true. Anything else is not a token this control plane wrote.
            var introspectRequired = root.TryGetProperty("introspect_required", out var required);
            if (introspectRequired && required.ValueKind != JsonValueKind.True)
            {
                return false;
            }

            var iat = root.TryGetProperty("iat", out var iatElement) && iatElement.ValueKind == JsonValueKind.Number && iatElement.TryGetInt64(out var iatSeconds) ? iatSeconds : (long?)null;
            var depth = act.TryGetProperty("depth", out var depthElement) && depthElement.ValueKind == JsonValueKind.Number && depthElement.TryGetInt32(out var d) ? d : (int?)null;
            view = new TaskTokenView(jti, taskId, clientId[ActorClaim.AgentSubjectPrefix.Length..], clientId, subject, Text(root, "scope"), Text(root, "aud"), Text(root, "iss"), DateTimeOffset.FromUnixTimeSeconds(expSeconds), iat, depth, act.Clone(), taskExpSeconds, sponsor, introspectRequired);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
