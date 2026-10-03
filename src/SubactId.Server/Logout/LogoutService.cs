using SubactId.Core.Audit;
using SubactId.Core.Revocation;
using SubactId.Core.Signals;
using SubactId.Core.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Revocation;
using SubactId.Server.Tokens;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Logout;

/// <summary>
/// The OpenID Connect back-channel logout receiver. A logout naming a session ends the tasks that
/// session started. A logout naming only the person ends all their tasks.
///
/// It revokes tasks but never blocks the person, who may sign in again and start new tasks. What
/// it does refuse is the sign-in that ended: the exchange reads the revocation recorded here, so a
/// subject token of the logged-out session, or for a logout of the person one issued before the
/// logout, cannot start a task (spec section 6).
///
/// The person is matched by the task's sponsor (<c>sub</c>), not the configured key claim.
/// </summary>
public sealed class LogoutService(
    LogoutTokenValidator tokens,
    ISignalReplayStore replays,
    ITaskRevocation tasks,
    IRevocationRepository revocations,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    DenialAggregator aggregator,
    RenewalSummary summaries,
    TimeProvider clock,
    ReplayPurgeGate? purgeGate = null)
{
    /// <summary>Reason recorded on a task revoked because its session or person logged out.</summary>
    public const string LoggedOut = "sponsor_logged_out";

    /// <summary>The <c>revoked_by</c> value for a revocation an identity provider asked for.</summary>
    public const string IdentityProvider = "identity_provider";

    private readonly ReplayPurgeGate purgeGate = purgeGate ?? new ReplayPurgeGate();

    /// <summary>
    /// Validates <paramref name="logoutToken"/> and, if it holds, ends what it asks to end.
    /// </summary>
    /// <param name="logoutToken">The <c>logout_token</c> form field.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The refusal reason, or <c>null</c> when the logout was accepted.</returns>
    public async Task<LogoutRejection?> ReceiveAsync(string? logoutToken, CancellationToken cancellationToken = default)
    {
        var validation = await tokens.ValidateAsync(logoutToken, cancellationToken);
        if (validation.Signal is not { } signal)
        {
            await DenyAsync(validation.Reason);
            return validation.Reason;
        }

        // The jti is recorded first and in the same transaction as the revocation, so a token
        // revokes once and a failed attempt can be retried. Concurrent duplicates conflict on insert.
        var now = clock.GetUtcNow();
        var outcome = await unitOfWork.RunAsync(
            async ct =>
            {
                if (!await replays.TryRecordAsync(signal.Issuer, signal.Jti, signal.ExpiresAt, ct))
                {
                    return (Replayed: true, Ended: 0);
                }

                // The session if the token names one, otherwise the whole person. Never both.
                var ended = signal.SessionId is { Length: > 0 } session
                    ? await tasks.RevokeSessionTasksAsync(session, now, LoggedOut, ct)
                    : await tasks.RevokeSubjectTasksAsync(signal.Subject!, now, LoggedOut, ct);

                // Names the token's subject, or for a session-only token the sponsor of the ended
                // tasks. A session logout that ended nothing names nobody.
                var records = new List<AuditEvent>(ended.Count + 1)
                {
                    new(now, AuditEvents.SponsorSignal, null, null, signal.Subject ?? (ended.Count > 0 ? ended[0].Sponsor : null), Decision: AuditDecision.Allow, Reason: LoggedOut),
                };
                records.AddRange(ended.SelectMany(t => summaries.Ending(RevocationService.Record(t, now, t.IsRoot ? LoggedOut : ITaskRevocation.ParentRevoked), t.Renewals)));

                // Recorded whether or not anything was running, because it also refuses the
                // sign-in that ended. Written after the walk above took the session's or the
                // subject's lock, so an exchange under way reads it or finishes first. A session
                // logout refuses every token of that session; a logout of the person refuses
                // their tokens issued before the logout token, by the identity provider's clock.
                await revocations.AddAsync(
                    signal.SessionId is { Length: > 0 } named
                        ? new Core.Revocation.Revocation(null, null, null, null, named, now, LoggedOut, IdentityProvider)
                        : new Core.Revocation.Revocation(null, null, null, null, null, now, LoggedOut, IdentityProvider, Subject: signal.Subject, IssuedBefore: signal.IssuedAt),
                    ct);

                await audit.AppendAsync(records, ct);
                return (Replayed: false, Ended: ended.Count);
            },
            cancellationToken);

        // A replayed token is answered as accepted (section 2.8) and changes nothing, so nothing
        // is recorded.
        if (!outcome.Replayed)
        {
            await PurgeOccasionallyAsync(now, cancellationToken);
        }

        return null;
    }

    /// <summary>
    /// Refuses a request whose body could not be read as a form, recording it as the malformed
    /// token it could not carry.
    /// </summary>
    /// <returns>The refusal reason.</returns>
    public async Task<LogoutRejection?> RefuseUnreadableAsync()
    {
        await DenyAsync(LogoutRejection.Malformed);
        return LogoutRejection.Malformed;
    }

    /// <summary>
    /// Records a refusal through the denial aggregator. Nothing from the unverified token is
    /// recorded.
    /// </summary>
    private async Task DenyAsync(LogoutRejection reason)
    {
        var record = new AuditEvent(
            clock.GetUtcNow(),
            AuditEvents.SignalDenied,
            Decision: AuditDecision.Deny,
            Reason: AuditReason.Of("logout", reason));
        await aggregator.RecordAsync(record, audit);
    }

    private async Task PurgeOccasionallyAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (purgeGate.TryClaim(now))
        {
            await replays.PurgeExpiredAsync(now, cancellationToken);
        }
    }
}
