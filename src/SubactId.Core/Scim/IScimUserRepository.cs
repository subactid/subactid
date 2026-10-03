namespace SubactId.Core.Scim;

/// <summary>
/// Persistence for SCIM-provisioned users. Separate from sponsor blocks. A SCIM write that changes
/// both writes them in one transaction.
/// </summary>
public interface IScimUserRepository
{
    /// <summary>The user with <paramref name="id"/>, or <c>null</c>.</summary>
    /// <param name="id">The identifier this control plane assigned.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ScimUser?> FindAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds <paramref name="user"/>. Throws <see cref="Storage.DuplicateEntityException"/> when
    /// the <c>userName</c> is taken.
    /// </summary>
    /// <param name="user">The user to add.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task AddAsync(ScimUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces <paramref name="expected"/> with <paramref name="user"/>, only if the stored user
    /// still equals <paramref name="expected"/>. Returns <c>false</c> when there is no such user
    /// or it has changed, and nothing is written. Throws
    /// <see cref="Storage.DuplicateEntityException"/> when the new <c>userName</c> belongs to
    /// somebody else.
    /// </summary>
    /// <remarks>
    /// The check stops a concurrent write from undoing a deactivation decided from a stale read.
    /// </remarks>
    /// <param name="expected">The user as the caller read it.</param>
    /// <param name="user">The user as it should now be, with the same id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> ReplaceAsync(ScimUser expected, ScimUser user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes <paramref name="expected"/>, only if the stored user still equals it (as in
    /// <see cref="ReplaceAsync"/>). Returns <c>false</c> when there is no such user or it has changed.
    /// </summary>
    /// <param name="expected">The user as the caller read it.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> DeleteAsync(ScimUser expected, CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether a user other than <paramref name="exceptId"/> is stored under
    /// <paramref name="sponsorKey"/> and inactive. One existence query.
    /// </summary>
    /// <remarks>
    /// Two records may share a sponsor key. A reactivation of one must not lift the block that
    /// the other's deactivation placed.
    /// </remarks>
    /// <param name="sponsorKey">The key tasks use for the person.</param>
    /// <param name="exceptId">The user being written, which is not counted.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<bool> AnyOtherInactiveAsync(string sponsorKey, string exceptId, CancellationToken cancellationToken = default);

    /// <summary>How many users are stored. Used to enforce the user limit.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<int> CountAsync(CancellationToken cancellationToken = default);

    /// <summary>One page of the users matching <paramref name="filter"/>, ordered by id, with the total that matched.</summary>
    /// <param name="filter">What to return and from where.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<ScimUserPage> ListAsync(ScimUserFilter filter, CancellationToken cancellationToken = default);
}
