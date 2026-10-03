using System.Text.Json;
using SubactId.Core.Scim;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Signals;
using SubactId.Tokens.Issuance;

namespace SubactId.Server.Scim;

/// <summary>Why a SCIM request could not be carried out.</summary>
public enum ScimFailure
{
    /// <summary>No user with that id.</summary>
    NotFound,

    /// <summary>Another user already has that <c>userName</c>.</summary>
    UserNameTaken,

    /// <summary>The body carries no usable <c>userName</c>.</summary>
    MissingUserName,

    /// <summary>The attribute this deployment keys people by is absent or unusable.</summary>
    MissingSponsorKey,

    /// <summary>The body is not the shape this endpoint takes.</summary>
    MalformedBody,

    /// <summary>A value for a kept attribute has the wrong type.</summary>
    InvalidValue,

    /// <summary>The receiver already holds its configured maximum of users.</summary>
    Capacity,

    /// <summary>The user kept changing under the request, so the write was not applied.</summary>
    Changed,
}

/// <summary>
/// The SCIM 2.0 Users receiver's logic. Turns a provisioning write into a sponsor block (with
/// live tasks revoked) or the lifting of one.
///
/// <para>
/// The state in every write, including a create, is applied. Inactive blocks the person and
/// revokes their live tasks. Active lifts a block this receiver placed, unless another record
/// naming the person is inactive, or a deletion placed it and the write is not a create.
/// </para>
/// <para>
/// A block placed by another source is never replaced, lifted or taken over.
/// </para>
/// <para>
/// Audit records are written only when a block is placed or lifted or a task ends, not for a
/// write that restates the current state.
/// </para>
/// </summary>
public sealed class ScimUserService(
    IScimUserRepository users,
    SponsorSignalWriter signals,
    IUnitOfWork unitOfWork,
    ScimOptions options,
    TimeProvider clock)
{
    /// <summary>Reason recorded when a provisioning client reports somebody inactive.</summary>
    public const string Deactivated = "scim_deactivated";

    /// <summary>Reason recorded when a provisioning client deletes somebody.</summary>
    public const string Deleted = "scim_deleted";

    /// <summary>Reason recorded when a provisioning client reports somebody active again.</summary>
    public const string Reactivated = "scim_reactivated";

    /// <summary>The <c>revoked_by</c> value for a revocation a provisioning client asked for.</summary>
    public const string ProvisioningClient = "provisioning_client";

    /// <summary>Prefix of the identifiers this receiver assigns to user records.</summary>
    public const string IdPrefix = "scim";

    /// <summary>Longest <c>userName</c> or <c>externalId</c> accepted. Matches the storage columns.</summary>
    public const int MaxAttributeLength = 256;

    /// <summary>
    /// How many times a write is re-read and re-applied when the user changed under it, before
    /// the client gets <see cref="ScimFailure.Changed"/>.
    /// </summary>
    public const int MaxWriteAttempts = 3;

    /// <summary>The user with <paramref name="id"/>, or a failure.</summary>
    /// <param name="id">The identifier this receiver assigned.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(ScimUser? User, ScimFailure? Failure)> GetAsync(string? id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(id))
        {
            return (null, ScimFailure.NotFound);
        }

        return await users.FindAsync(id, cancellationToken) is { } user ? (user, null) : (null, ScimFailure.NotFound);
    }

    /// <summary>One page of users.</summary>
    /// <param name="filter">What to return and from where.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<ScimUserPage> ListAsync(ScimUserFilter filter, CancellationToken cancellationToken = default) =>
        users.ListAsync(filter, cancellationToken);

    /// <summary>Creates a user and applies the state the request asks for.</summary>
    /// <param name="request">The body.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(ScimUser? User, ScimFailure? Failure)> CreateAsync(ScimUserRequest? request, CancellationToken cancellationToken = default)
    {
        if (Read(request, out var userName, out var externalId, out var active) is { } invalid)
        {
            return (null, invalid);
        }

        if (SponsorKeyOf(userName, externalId) is not { } sponsorKey)
        {
            return (null, ScimFailure.MissingSponsorKey);
        }

        // Checked before the insert. Concurrent creates can exceed the ceiling slightly.
        if (await users.CountAsync(cancellationToken) >= options.MaxUsers)
        {
            return (null, ScimFailure.Capacity);
        }

        var now = clock.GetUtcNow();
        var user = new ScimUser(OpaqueId.New(IdPrefix, now), userName, externalId, sponsorKey, active, now, now);

        try
        {
            return await unitOfWork.RunAsync<(ScimUser?, ScimFailure?)>(
                async ct =>
                {
                    await signals.HoldAsync([sponsorKey], ct);
                    await users.AddAsync(user, ct);
                    await ApplyAsync(user, previousKey: null, ScimWrite.Create, restated: false, now, ct);
                    return (user, null);
                },
                cancellationToken);
        }
        catch (DuplicateEntityException)
        {
            return (null, ScimFailure.UserNameTaken);
        }
    }

    /// <summary>Replaces a user with what the request says, and applies the state it asks for.</summary>
    /// <param name="id">The identifier this receiver assigned.</param>
    /// <param name="request">The body.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(ScimUser? User, ScimFailure? Failure)> ReplaceAsync(string? id, ScimUserRequest? request, CancellationToken cancellationToken = default)
    {
        if (Read(request, out var userName, out var externalId, out var active) is { } invalid)
        {
            return (null, invalid);
        }

        return await WriteAsync(id, existing => existing with { UserName = userName, ExternalId = externalId, Active = active }, cancellationToken);
    }

    /// <summary>
    /// Applies a patch. Operations on kept attributes are applied and the rest are ignored.
    /// </summary>
    /// <param name="id">The identifier this receiver assigned.</param>
    /// <param name="request">The body.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(ScimUser? User, ScimFailure? Failure)> PatchAsync(string? id, ScimPatchRequest? request, CancellationToken cancellationToken = default)
    {
        if (request?.Operations is not { Count: > 0 } operations || operations.Any(o => !ScimPatch.IsWellFormed(o)))
        {
            return (null, ScimFailure.MalformedBody);
        }

        return await WriteAsync(id, existing => ScimPatch.Apply(existing, operations), cancellationToken);
    }

    /// <summary>
    /// Deletes a user, blocks the person as deleted and revokes their live tasks.
    /// </summary>
    /// <param name="id">The identifier this receiver assigned.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<ScimFailure?> DeleteAsync(string? id, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(id))
        {
            return ScimFailure.NotFound;
        }

        for (var attempt = 1; ; attempt++)
        {
            if (await users.FindAsync(id, cancellationToken) is not { } existing)
            {
                return ScimFailure.NotFound;
            }

            var now = clock.GetUtcNow();
            var deleted = await unitOfWork.RunAsync(
                async ct =>
                {
                    await signals.HoldAsync([existing.SponsorKey], ct);

                    // Delete only if unchanged since read, so the blocked key is the current one.
                    if (!await users.DeleteAsync(existing, ct))
                    {
                        return false;
                    }

                    await ApplyAsync(existing, previousKey: null, ScimWrite.Delete, restated: false, now, ct);
                    return true;
                },
                cancellationToken);
            if (deleted)
            {
                return null;
            }

            if (attempt == MaxWriteAttempts)
            {
                return ScimFailure.Changed;
            }
        }
    }

    /// <summary>
    /// Reads a user, applies <paramref name="change"/>, validates the result and writes it back
    /// only if the user is unchanged since it was read. Otherwise retries from the current state,
    /// up to <see cref="MaxWriteAttempts"/> times.
    /// </summary>
    private async Task<(ScimUser? User, ScimFailure? Failure)> WriteAsync(string? id, Func<ScimUser, ScimUser?> change, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(id))
        {
            return (null, ScimFailure.NotFound);
        }

        for (var attempt = 1; ; attempt++)
        {
            if (await users.FindAsync(id, cancellationToken) is not { } existing)
            {
                return (null, ScimFailure.NotFound);
            }

            if (change(existing) is not { } changed)
            {
                return (null, ScimFailure.InvalidValue);
            }

            if (!IsAttribute(changed.UserName))
            {
                return (null, ScimFailure.MissingUserName);
            }

            if (changed.ExternalId is not null && !IsAttribute(changed.ExternalId))
            {
                return (null, ScimFailure.MalformedBody);
            }

            if (SponsorKeyOf(changed.UserName, changed.ExternalId) is not { } sponsorKey)
            {
                return (null, ScimFailure.MissingSponsorKey);
            }

            var now = clock.GetUtcNow();
            var updated = changed with { SponsorKey = sponsorKey, UpdatedAt = now };

            try
            {
                var written = await unitOfWork.RunAsync(
                    async ct =>
                    {
                        // Both people, if the write moves the record from one to another, taken
                        // together. The record is replaced only if unchanged since read, so these
                        // are its keys.
                        await signals.HoldAsync(Keys(updated.SponsorKey, existing.SponsorKey), ct);
                        if (!await users.ReplaceAsync(existing, updated, ct))
                        {
                            return false;
                        }

                        // A directory sync re-sends everyone's state. A write that changes neither
                        // whether the person is active nor who they are only restates it.
                        var restated = existing.Active == updated.Active && string.Equals(existing.SponsorKey, updated.SponsorKey, StringComparison.Ordinal);
                        await ApplyAsync(updated, existing.SponsorKey, ScimWrite.Change, restated, now, ct);
                        return true;
                    },
                    cancellationToken);
                if (written)
                {
                    return (updated, null);
                }
            }
            catch (DuplicateEntityException)
            {
                return (null, ScimFailure.UserNameTaken);
            }

            if (attempt == MaxWriteAttempts)
            {
                return (null, ScimFailure.Changed);
            }
        }
    }

    /// <summary>
    /// Applies the user's state: blocks the person and ends their tasks, or lifts a block this
    /// receiver placed.
    /// </summary>
    /// <remarks>
    /// The caller holds every key the write touches (see <see cref="SponsorSignalWriter.HoldAsync"/>)
    /// from the start of its unit of work, before it writes the record. Whether a block stands
    /// depends on every record naming the person, so two writes to records that share a key take
    /// turns: the second reads what the first committed, and neither lifts a block on a state the
    /// other has not settled.
    /// </remarks>
    /// <param name="user">The user as the write leaves it.</param>
    /// <param name="previousKey">
    /// The key the record named before this write. A deactivation also blocks this key if it
    /// differs. A reactivation never unblocks it.
    /// </param>
    /// <param name="write">Whether the record was created, changed or removed.</param>
    /// <param name="restated">Whether the write left the person's state and key as they were, so a refusal by another source's block is not recorded again.</param>
    /// <param name="now">The time to record.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task ApplyAsync(ScimUser user, string? previousKey, ScimWrite write, bool restated, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var deleted = write == ScimWrite.Delete;
        if (write == ScimWrite.Create)
        {
            // A block a deletion placed waits for a new record naming the person, and this is one.
            // From here the block is held, or lifted, by the records that remain, this one included.
            await signals.ForgetDeletionAsync(user.SponsorKey, SponsorBlockSource.Scim, cancellationToken);
        }

        if (user.Active && !deleted)
        {
            // Two records may share a key (the index is not unique, on purpose). The block stands
            // while any other record under it is still inactive: this reactivation is not theirs
            // to undo. Nor is a deletion's: the deleted record is gone and no write to another one
            // stands for it, so only a create lifts that block. Neither is recorded, since nothing
            // changed.
            await signals.UnblockAsync(
                user.SponsorKey,
                SponsorBlockSource.Scim,
                Reactivated,
                now,
                restated,
                stillStands: ct => users.AnyOtherInactiveAsync(user.SponsorKey, user.Id, ct),
                keepsDeletion: true,
                cancellationToken: cancellationToken);
            return;
        }

        var kind = deleted ? SponsorBlockKind.Deleted : SponsorBlockKind.Disabled;
        var reason = deleted ? Deleted : Deactivated;
        var alsoPrevious = previousKey is not null && !string.Equals(previousKey, user.SponsorKey, StringComparison.Ordinal);
        await signals.BlockAsync(user.SponsorKey, SponsorBlockSource.Scim, kind, reason, ProvisioningClient, now, restated, byDeletion: deleted, cancellationToken: cancellationToken);
        if (alsoPrevious)
        {
            await signals.BlockAsync(previousKey!, SponsorBlockSource.Scim, kind, reason, ProvisioningClient, now, restated, byDeletion: deleted, cancellationToken: cancellationToken);
        }
    }

    /// <summary>What a write did to the record it names.</summary>
    private enum ScimWrite
    {
        /// <summary>A new record (<c>POST /Users</c>).</summary>
        Create,

        /// <summary>An existing record replaced or patched.</summary>
        Change,

        /// <summary>An existing record removed.</summary>
        Delete,
    }

    /// <summary>The person a write names, and the one it named before if that is someone else.</summary>
    private static string[] Keys(string sponsorKey, string previousKey) =>
        string.Equals(sponsorKey, previousKey, StringComparison.Ordinal) ? [sponsorKey] : [sponsorKey, previousKey];

    /// <summary>Reads and checks the attributes of a create or replace body.</summary>
    private static ScimFailure? Read(ScimUserRequest? request, out string userName, out string? externalId, out bool active)
    {
        userName = string.Empty;
        externalId = null;
        active = true;

        if (request is null)
        {
            return ScimFailure.MalformedBody;
        }

        if (!IsAttribute(request.UserName))
        {
            return ScimFailure.MissingUserName;
        }

        if (request.ExternalId is { } external && !IsAttribute(external))
        {
            return ScimFailure.MalformedBody;
        }

        userName = request.UserName!;
        externalId = request.ExternalId;

        // A missing or null active means active. Anything else must read as a boolean, the same
        // as in a patch, or the write is refused rather than applied as the wrong state.
        if (request.Active is { ValueKind: not JsonValueKind.Null } sent)
        {
            if (ScimPatch.Boolean(sent) is not { } parsed)
            {
                return ScimFailure.InvalidValue;
            }

            active = parsed;
        }

        return null;
    }

    /// <summary>
    /// The sponsor key signals about this person are matched by, or <c>null</c> when the
    /// configured attribute does not supply a well-formed one.
    /// </summary>
    private string? SponsorKeyOf(string userName, string? externalId)
    {
        var value = options.SponsorKeyAttribute == ScimSponsorKeyAttribute.UserName ? userName : externalId;
        return SponsorKey.IsWellFormed(value) ? value : null;
    }

    /// <summary>Whether a value is storable: non-empty, bounded, no control characters or surrounding space.</summary>
    private static bool IsAttribute(string? value) =>
        value is { Length: > 0 and <= MaxAttributeLength } && !value.Any(char.IsControl) && value.Trim().Length == value.Length;
}
