using SubactId.Core.Agents;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Core.Validation;
using SubactId.Server.Contracts;
using SubactId.Server.Tokens;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;

namespace SubactId.Server.Introspection;

/// <summary>Outcome of an introspection request: exactly one of an answer or an error.</summary>
/// <param name="Response">The answer.</param>
/// <param name="Error">The OAuth error, when the request itself was bad.</param>
public sealed record IntrospectionOutcome(IntrospectionResponse? Response, OAuthErrorResponse? Error);

/// <summary>
/// Answers <c>POST /oauth2/introspect</c> from storage, so revocations take effect immediately.
/// A token is active only if it verifies against this control plane's keys, is an unexpired task
/// token not revoked by <c>jti</c>, its task is active and unexpired, and its agent is enabled.
/// Otherwise it is <c>active: false</c>, with the revocation time and reason when the token or
/// task was revoked, or the reason when the agent was disabled. The hint is ignored.
/// </summary>
public sealed class IntrospectionService(SigningKeySet keys, IRevocationRepository revocations, ITaskRepository tasks, IAgentRepository agents, TokenAudit denials, TimeProvider clock)
{
    /// <summary>Reason given when the token's agent has been disabled.</summary>
    public const string AgentDisabled = "agent_disabled";

    /// <summary>Handles the parsed form: a bad request is an error, anything else an answer.</summary>
    /// <param name="request">The parsed form.</param>
    /// <param name="formErrors">Problems found while reading the form.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IntrospectionOutcome> IntrospectAsync(IntrospectTokenRequest request, IReadOnlyList<ValidationError> formErrors, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(formErrors);

        var errors = formErrors.Concat(request.Validate()).ToList();
        if (errors.Count > 0)
        {
            var fields = string.Join(", ", errors.Select(e => $"{e.Field} {e.Message}"));
            return new IntrospectionOutcome(null, (await denials.DenyAsync(OAuthErrorResponse.InvalidRequest, $"The request is invalid: {fields}", OAuthErrorResponse.InvalidRequest)).Error);
        }

        return new IntrospectionOutcome(await IntrospectAsync(request.Token, cancellationToken), null);
    }

    /// <summary>Describes <paramref name="token"/>.</summary>
    /// <param name="token">The token as presented.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IntrospectionResponse> IntrospectAsync(string? token, CancellationToken cancellationToken = default)
    {
        if (!Jws.TryVerifyAccessToken(keys, token, out var payload) || !TaskTokenReader.TryRead(payload!, out var view))
        {
            return IntrospectionResponse.Inactive;
        }

        var now = clock.GetUtcNow();
        if (now >= view.ExpiresAt)
        {
            return IntrospectionResponse.Inactive;
        }

        if (await revocations.FindTokenAsync(view.Jti, cancellationToken) is { } revoked)
        {
            return new IntrospectionResponse(false, revoked.RevokedAt, revoked.Reason);
        }

        var task = await tasks.FindAsync(view.AgentId, view.TaskId, cancellationToken);
        if (task is null || task.Status == DelegationTaskStatus.Expired || now >= task.ExpiresAt)
        {
            // Expiry is not a revocation and is never reported as one.
            return IntrospectionResponse.Inactive;
        }

        if (task.Status == DelegationTaskStatus.Revoked)
        {
            return new IntrospectionResponse(false, task.RevokedAt, task.RevocationReason);
        }

        var agent = await agents.FindAsync(view.AgentId, cancellationToken);
        if (agent is not { Enabled: true })
        {
            return new IntrospectionResponse(false, RevocationReason: AgentDisabled);
        }

        return new IntrospectionResponse(
            true,
            Scope: view.Scope,
            ClientId: view.ClientId,
            Sub: view.Subject,
            Act: view.Act,
            IntrospectRequired: view.IntrospectRequired ? true : null,
            Task: new IntrospectionTask(view.TaskId, view.TaskExpiresAt, view.TaskSponsor),
            Aud: view.Audience,
            Iss: view.Issuer,
            Exp: view.ExpiresAt.ToUnixTimeSeconds(),
            Iat: view.IssuedAt,
            Jti: view.Jti,
            TaskId: view.TaskId,
            TokenType: TokenResponse.Bearer);
    }
}
