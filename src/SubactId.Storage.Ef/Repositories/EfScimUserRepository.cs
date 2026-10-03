using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Scim;
using SubactId.Core.Storage;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>
/// The SCIM user records, over the <c>scim_users</c> table. A listing is one projected query for
/// the page plus one count for the total.
///
/// <para>
/// A replace or delete is one statement whose <c>WHERE</c> matches the row as the caller read it,
/// so it does nothing if a concurrent write changed the row first.
/// </para>
/// </summary>
public sealed class EfScimUserRepository(SubactIdDbContext db, IStorageDialect dialect) : IScimUserRepository
{
    /// <inheritdoc />
    public async Task<ScimUser?> FindAsync(string id, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        var row = await db.ScimUsers.AsNoTracking().SingleOrDefaultAsync(u => u.Id == id, cancellationToken);
        return row?.ToDomain();
    }

    /// <inheritdoc />
    public Task<bool> AnyOtherInactiveAsync(string sponsorKey, string exceptId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(sponsorKey);
        ArgumentException.ThrowIfNullOrEmpty(exceptId);

        // Served by the sponsor key index.
        return db.ScimUsers.AsNoTracking().AnyAsync(u => u.SponsorKey == sponsorKey && !u.Active && u.Id != exceptId, cancellationToken);
    }

    /// <inheritdoc />
    public async Task AddAsync(ScimUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        db.ScimUsers.Add(user.ToRow());
        await UniqueViolation.SaveOrThrowDuplicateAsync(db, dialect, "scim user", user.UserName, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> ReplaceAsync(ScimUser expected, ScimUser user, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(user);
        if (!string.Equals(expected.Id, user.Id, StringComparison.Ordinal))
        {
            throw new ArgumentException("A replacement keeps the user's id.", nameof(user));
        }

        var updatedAt = user.UpdatedAt.ToUniversalTime();
        try
        {
            return await AsRead(expected)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(u => u.UserName, user.UserName)
                        .SetProperty(u => u.ExternalId, user.ExternalId)
                        .SetProperty(u => u.SponsorKey, user.SponsorKey)
                        .SetProperty(u => u.Active, user.Active)
                        .SetProperty(u => u.UpdatedAt, updatedAt),
                    cancellationToken) > 0;
        }
        catch (DbException exception) when (dialect.IsUniqueViolation(exception))
        {
            // A bulk update bypasses the change tracker, so the provider's exception arrives unwrapped.
            throw new DuplicateEntityException("scim user", user.UserName);
        }
    }

    /// <inheritdoc />
    public async Task<bool> DeleteAsync(ScimUser expected, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expected);

        return await AsRead(expected).ExecuteDeleteAsync(cancellationToken) > 0;
    }

    /// <summary>
    /// Matches the row only if every value a write decides from still equals
    /// <paramref name="expected"/>. Timestamps are not compared.
    /// </summary>
    private IQueryable<ScimUserRow> AsRead(ScimUser expected) => db.ScimUsers.Where(u =>
        u.Id == expected.Id
        && u.UserName == expected.UserName
        && u.ExternalId == expected.ExternalId
        && u.SponsorKey == expected.SponsorKey
        && u.Active == expected.Active);

    /// <inheritdoc />
    public Task<int> CountAsync(CancellationToken cancellationToken = default) =>
        db.ScimUsers.AsNoTracking().CountAsync(cancellationToken);

    /// <inheritdoc />
    public async Task<ScimUserPage> ListAsync(ScimUserFilter filter, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(filter);

        var matching = db.ScimUsers.AsNoTracking();
        if (filter.UserName is { } userName)
        {
            matching = matching.Where(u => u.UserName == userName);
        }

        if (filter.ExternalId is { } externalId)
        {
            matching = matching.Where(u => u.ExternalId == externalId);
        }

        // The total counts every match, not just this page.
        var total = await matching.CountAsync(cancellationToken);
        var rows = await matching
            .OrderBy(u => u.Id)
            .Skip(filter.StartIndex - 1)
            .Take(filter.Count)
            .Select(u => new ScimUser(u.Id, u.UserName, u.ExternalId, u.SponsorKey, u.Active, u.CreatedAt, u.UpdatedAt))
            .ToListAsync(cancellationToken);

        return new ScimUserPage(rows, total);
    }
}
