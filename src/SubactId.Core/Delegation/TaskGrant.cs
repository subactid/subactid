namespace SubactId.Core.Delegation;

/// <summary>
/// A task grant, the <c>refresh_token</c> of spec section 3, identified only by the hash of
/// its value. The value itself exists only in the response that issued it.
/// </summary>
/// <param name="GrantHash">SHA-256 of the grant value.</param>
/// <param name="TaskId">The task the grant is bound to.</param>
/// <param name="AgentId">The agent the grant is bound to; any other agent presenting it is refused.</param>
/// <param name="Scopes">
/// Scopes the grant may refresh into. Never wider than the task's scopes. Narrowed to the scope of
/// each successful refresh, so a narrowing sticks.
/// </param>
/// <param name="CreatedAt">When the grant was issued.</param>
/// <param name="ExpiresAt">When the grant stops working, at the latest the task expiry.</param>
/// <param name="RevokedAt">When the grant was revoked, if it was.</param>
/// <param name="LastUsedAt">When the grant was last used to refresh.</param>
/// <param name="Renewals">
/// How many times the grant has been used to refresh. Counted in storage in the same statement
/// that records the use.
/// </param>
public sealed record TaskGrant(
    ReadOnlyMemory<byte> GrantHash,
    string TaskId,
    string AgentId,
    IReadOnlyList<string> Scopes,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? RevokedAt,
    DateTimeOffset? LastUsedAt,
    int Renewals = 0);
