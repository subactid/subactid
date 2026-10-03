using SubactId.Core.Audit;
using SubactId.Core.Signals;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Tokens;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Signals;

/// <summary>
/// The Shared Signals / CAEP receiver. Turns a transmitter's signed security event token into a
/// sponsor block, the ending of the person's tasks, or both.
///
/// <para>
/// It acts on four events: account disabled, purged and enabled, and sessions revoked. Other
/// valid events are accepted and ignored.
/// </para>
/// <para>
/// <c>session-revoked</c> ends the person's tasks but does not block them.
/// <c>account-disabled</c> blocks them until lifted.
/// </para>
/// </summary>
public sealed class SecurityEventService(
    SecurityEventTokenValidator tokens,
    ISignalReplayStore replays,
    SponsorSignalWriter signals,
    IAuditWriter audit,
    IUnitOfWork unitOfWork,
    DenialAggregator aggregator,
    TimeProvider clock,
    ReplayPurgeGate? purgeGate = null)
{
    /// <summary>Reason recorded when a transmitter reports the person's sessions were revoked.</summary>
    public const string SessionsRevoked = "ssf_sessions_revoked";

    /// <summary>Reason recorded when a transmitter reports the account disabled.</summary>
    public const string AccountDisabled = "ssf_account_disabled";

    /// <summary>Reason recorded when a transmitter reports the account deleted.</summary>
    public const string AccountPurged = "ssf_account_purged";

    /// <summary>Reason recorded when a transmitter reports the account enabled again.</summary>
    public const string AccountEnabled = "ssf_account_enabled";

    /// <summary>The <c>revoked_by</c> value for a revocation a Shared Signals transmitter asked for.</summary>
    public const string Transmitter = "signals_transmitter";

    private readonly ReplayPurgeGate purgeGate = purgeGate ?? new ReplayPurgeGate();

    /// <summary>
    /// Validates <paramref name="securityEventToken"/> and, if it holds, acts on the events it
    /// carries.
    /// </summary>
    /// <param name="securityEventToken">The compact JWS the transmitter posted.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The refusal reason, or <c>null</c> when the token was accepted.</returns>
    public async Task<SecurityEventRejection?> ReceiveAsync(string? securityEventToken, CancellationToken cancellationToken = default)
    {
        var validation = await tokens.ValidateAsync(securityEventToken, cancellationToken);
        if (validation.Signal is not { } signal)
        {
            await DenyAsync(validation.Reason);
            return validation.Reason;
        }

        // The jti is recorded in the same transaction as the actions, so a failed attempt can
        // be retried with the same token.
        var now = clock.GetUtcNow();
        var replayed = await unitOfWork.RunAsync(
            async ct =>
            {
                if (!await replays.TryRecordAsync(signal.Issuer, signal.Jti, signal.ExpiresAt, ct))
                {
                    return true;
                }

                // Everyone the token names, together, before the first action writes anything,
                // so two tokens naming the same people in a different order never wait in a cycle.
                await signals.HoldAsync(signal.Actions.Select(a => a.SponsorKey).ToList(), ct);
                foreach (var action in signal.Actions)
                {
                    await ApplyAsync(action, signal.IssuedAt, now, ct);
                }

                return false;
            },
            cancellationToken);

        // A replayed token is answered as accepted (RFC 8935 has only 202 for this) and changes
        // nothing, so nothing is recorded.
        if (!replayed)
        {
            await PurgeOccasionallyAsync(now, cancellationToken);
        }

        return null;
    }

    /// <summary>
    /// Applies one event to the person it names. An unhandled kind throws, so it can never fall
    /// through to lifting a block.
    /// </summary>
    /// <remarks>
    /// Account events are ordered by the token's <c>iat</c>, since a transmitter may deliver them
    /// out of order, for example from a retry queue. The <c>iat</c> of the latest one applied is
    /// kept per person, and an <c>account-disabled</c>, <c>account-purged</c> or
    /// <c>account-enabled</c> issued before it is not applied: a late <c>account-disabled</c> does
    /// not block a person a newer <c>account-enabled</c> let back in, and a late
    /// <c>account-enabled</c> does not lift a newer block. One with the same <c>iat</c> is applied
    /// after it. A <c>session-revoked</c> is not ordered; it also refuses the person's subject
    /// tokens issued before it.
    /// </remarks>
    private Task ApplyAsync(SecurityEventAction action, DateTimeOffset issuedAt, DateTimeOffset now, CancellationToken cancellationToken) => action.Kind switch
    {
        SecurityEventKind.SessionsRevoked => signals.RevokeAsync(action.SponsorKey, SessionsRevoked, Transmitter, now, signsOutBefore: issuedAt, cancellationToken),
        SecurityEventKind.AccountDisabled => signals.BlockAsync(action.SponsorKey, SponsorBlockSource.Ssf, SponsorBlockKind.Disabled, AccountDisabled, Transmitter, now, eventAt: issuedAt, cancellationToken: cancellationToken),
        SecurityEventKind.AccountPurged => signals.BlockAsync(action.SponsorKey, SponsorBlockSource.Ssf, SponsorBlockKind.Deleted, AccountPurged, Transmitter, now, eventAt: issuedAt, cancellationToken: cancellationToken),
        SecurityEventKind.AccountEnabled => signals.UnblockAsync(action.SponsorKey, SponsorBlockSource.Ssf, AccountEnabled, now, eventAt: issuedAt, cancellationToken: cancellationToken),
        _ => throw new ArgumentOutOfRangeException(nameof(action), action.Kind, "No action is defined for this kind of security event."),
    };

    /// <summary>
    /// Refuses an authenticated push whose body is not a security event token by its media type,
    /// recording it as a malformed token.
    /// </summary>
    public Task RefuseUnreadableAsync() => DenyAsync(SecurityEventRejection.Malformed);

    /// <summary>
    /// Records a refusal through the denial aggregator. Nothing from the unverified token is
    /// recorded.
    /// </summary>
    private async Task DenyAsync(SecurityEventRejection reason)
    {
        var record = new AuditEvent(
            clock.GetUtcNow(),
            AuditEvents.SignalDenied,
            Decision: AuditDecision.Deny,
            Reason: AuditReason.Of("ssf", reason));
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
