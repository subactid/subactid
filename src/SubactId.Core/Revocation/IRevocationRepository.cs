namespace SubactId.Core.Revocation;

/// <summary>
/// One explicit revocation (spec section 6): a token by <c>jti</c>, a task tree, all of an agent's
/// tasks, all tasks for one human (by sponsor key, or by upstream <c>sub</c> for a logout), or all
/// tasks from one identity provider session. Exactly one of the six identifiers is set.
/// </summary>
/// <param name="Jti">The token, when one token was revoked.</param>
/// <param name="TaskId">The root task, when a tree was revoked.</param>
/// <param name="AgentId">The agent, when all of its tasks were revoked.</param>
/// <param name="SponsorKey">The human, when every task acting for them was revoked.</param>
/// <param name="SessionId">The identity provider's session, when every task started from it was revoked.</param>
/// <param name="RevokedAt">When it took effect.</param>
/// <param name="Reason">Machine-readable reason, for example <c>operator_kill_switch</c>.</param>
/// <param name="RevokedBy">Who did it: an agent id, or <c>admin</c>.</param>
/// <param name="ExpiresAt">For a token: when the token expires. The record may be purged after that.</param>
/// <param name="Subject">The human's upstream <c>sub</c>, when a logout named the person and no session.</param>
/// <param name="IssuedBefore">
/// For a revocation that signs the person out (a logout naming them, a transmitter's
/// <c>session-revoked</c>): subject tokens issued before this instant may not start a task. The
/// signal's own <c>iat</c>, by the clock that also stamps the person's tokens. A revocation by
/// session needs none: every token of a session that was logged out is refused.
/// </param>
public sealed record Revocation(
    string? Jti,
    string? TaskId,
    string? AgentId,
    string? SponsorKey,
    string? SessionId,
    DateTimeOffset RevokedAt,
    string Reason,
    string? RevokedBy,
    DateTimeOffset? ExpiresAt = null,
    string? Subject = null,
    DateTimeOffset? IssuedBefore = null);

/// <summary>The sign-in a subject token stands for, as an exchange checks it against logouts.</summary>
/// <param name="Subject">The human's upstream <c>sub</c>.</param>
/// <param name="SponsorKey">The same human, as the configured key claim names them.</param>
/// <param name="SessionId">The identity provider session the token belongs to, if it names one.</param>
/// <param name="IssuedAt">The token's <c>iat</c>, if it carries one.</param>
public sealed record SignIn(string Subject, string SponsorKey, string? SessionId, DateTimeOffset? IssuedAt);

/// <summary>Persistence of explicit revocations. Introspection reads the token revocations.</summary>
public interface IRevocationRepository
{
    /// <summary>
    /// Records <paramref name="revocation"/>. If the <c>jti</c> is already revoked, the existing
    /// record is kept and <c>false</c> is returned.
    /// </summary>
    Task<bool> AddAsync(Revocation revocation, CancellationToken cancellationToken = default);

    /// <summary>The revocation of the token with <paramref name="jti"/>, if any.</summary>
    Task<Revocation?> FindTokenAsync(string jti, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether <paramref name="signIn"/> has been signed out: its session was logged out, or a
    /// revocation signing out the person (by <c>sub</c> or by sponsor key) carries an
    /// <see cref="Revocation.IssuedBefore"/> later than the token's <c>iat</c>. A token without an
    /// <c>iat</c> cannot be shown to be later, so any such revocation signs it out. One existence
    /// query. Read inside the exchange's fenced unit of work, so a logout cannot pass it.
    /// </summary>
    /// <param name="signIn">The subject token's sign-in.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> IsSignedOutAsync(SignIn signIn, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes up to <paramref name="batchSize"/> sign-outs recorded before
    /// <paramref name="before"/>, oldest first, and returns how many were removed. A sign-out is a
    /// revocation by session or one with <see cref="Revocation.IssuedBefore"/> set: the records
    /// <see cref="IsSignedOutAsync"/> reads. Every other revocation (of a token, a task, an agent,
    /// or by an operator for a person) is never removed here. Safe to run on several instances at
    /// once.
    /// </summary>
    /// <param name="before">Sign-outs recorded before this instant are removed.</param>
    /// <param name="batchSize">The most removed in one call.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<int> PruneSignOutsAsync(DateTimeOffset before, int batchSize, CancellationToken cancellationToken = default);
}
