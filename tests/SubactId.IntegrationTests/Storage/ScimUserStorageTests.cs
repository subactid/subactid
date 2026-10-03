using SubactId.Core.Scim;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Storage.Ef.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Storage;

/// <summary>
/// The provisioned-user table against a real database: the round trip, userName uniqueness, the
/// lookup listing, and the write guard, which depends on how one <c>UPDATE</c> behaves under a
/// concurrent one.
/// </summary>
public abstract class ScimUserStorageTests(IStorageFixture storage) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    private static ScimUser NewUser(string id, string userName, string? externalId, bool active = true) =>
        new(id, userName, externalId, externalId ?? userName, active, Now, Now);

    [Fact]
    public async Task A_user_is_stored_read_back_by_either_identifier_and_replaced()
    {
        await using var db = storage.CreateDbContext();
        var users = new EfScimUserRepository(db, storage.Dialect);
        var id = UniqueId("scim");
        var userName = UniqueId("ada") + "@example.com";
        var externalId = UniqueId("oid");

        await users.AddAsync(NewUser(id, userName, externalId));

        var stored = await users.FindAsync(id);
        Assert.Equal((userName, externalId, externalId, true), (stored!.UserName, stored.ExternalId, stored.SponsorKey, stored.Active));

        Assert.True(await users.ReplaceAsync(stored, stored with { Active = false, UpdatedAt = Now.AddMinutes(1) }));
        var replaced = await users.FindAsync(id);
        Assert.Equal((false, Now.AddMinutes(1)), (replaced!.Active, replaced.UpdatedAt));

        Assert.True(await users.DeleteAsync(replaced));
        Assert.Null(await users.FindAsync(id));
        Assert.False(await users.DeleteAsync(replaced));
    }

    [Fact]
    public async Task Another_inactive_user_under_the_same_key_is_found_and_the_user_asking_is_not_counted()
    {
        await using var db = storage.CreateDbContext();
        var users = new EfScimUserRepository(db, storage.Dialect);
        var key = UniqueId("oid");
        var asking = UniqueId("scim");
        var other = UniqueId("scim");

        await users.AddAsync(NewUser(asking, UniqueId("ada") + "@example.com", key, active: false));
        Assert.False(await users.AnyOtherInactiveAsync(key, asking));

        await users.AddAsync(NewUser(other, UniqueId("ada") + "@example.com", key, active: true));
        Assert.False(await users.AnyOtherInactiveAsync(key, asking));
        Assert.True(await users.AnyOtherInactiveAsync(key, other));

        var stored = (await users.FindAsync(other))!;
        Assert.True(await users.ReplaceAsync(stored, stored with { Active = false }));
        Assert.True(await users.AnyOtherInactiveAsync(key, asking));
        Assert.False(await users.AnyOtherInactiveAsync(UniqueId("oid"), asking));
    }

    [Fact]
    public async Task A_write_applies_to_the_user_as_it_was_read_or_not_at_all()
    {
        // A write is decided from the user as read. If the user changed in between, the statement
        // matches nothing and the caller reads again.
        var id = UniqueId("scim");
        ScimUser asRead;
        await using (var db = storage.CreateDbContext())
        {
            var users = new EfScimUserRepository(db, storage.Dialect);
            await users.AddAsync(NewUser(id, UniqueId("ada") + "@example.com", UniqueId("oid")));
            asRead = (await users.FindAsync(id))!;
        }

        // Another request deactivates the person.
        await using (var db = storage.CreateDbContext())
        {
            Assert.True(await new EfScimUserRepository(db, storage.Dialect).ReplaceAsync(asRead, asRead with { Active = false }));
        }

        await using (var db = storage.CreateDbContext())
        {
            var users = new EfScimUserRepository(db, storage.Dialect);

            // A rename based on the stale read, which would write the person back as active, touches nothing.
            Assert.False(await users.ReplaceAsync(asRead, asRead with { ExternalId = "renamed", SponsorKey = "renamed" }));
            var now = (await users.FindAsync(id))!;
            Assert.Equal((asRead.ExternalId, false), (now.ExternalId, now.Active));

            // A deletion based on the stale read removes nothing.
            Assert.False(await users.DeleteAsync(asRead));
            Assert.NotNull(await users.FindAsync(id));

            // Read again, the same writes apply.
            Assert.True(await users.ReplaceAsync(now, now with { ExternalId = "renamed", SponsorKey = "renamed" }));
            Assert.True(await users.DeleteAsync((await users.FindAsync(id))!));
            Assert.Null(await users.FindAsync(id));
        }
    }

    [Fact]
    public async Task The_guard_matches_a_user_with_no_external_id_too()
    {
        // The guard matches every value, including absent ones, so the provider must use "is null"
        // rather than "equals null" on both databases.
        await using var db = storage.CreateDbContext();
        var users = new EfScimUserRepository(db, storage.Dialect);
        var id = UniqueId("scim");
        await users.AddAsync(NewUser(id, UniqueId("grace") + "@example.com", externalId: null));
        var asRead = (await users.FindAsync(id))!;
        Assert.Null(asRead.ExternalId);

        Assert.True(await users.ReplaceAsync(asRead, asRead with { Active = false }));
        Assert.False(await users.ReplaceAsync(asRead, asRead with { ExternalId = "late" }));

        var now = (await users.FindAsync(id))!;
        Assert.True(await users.DeleteAsync(now));
        Assert.Null(await users.FindAsync(id));
    }

    [Fact]
    public async Task One_user_name_belongs_to_one_person()
    {
        // A context per step, as a request gets one: a failed insert stays tracked and would be
        // sent again on the same context.
        var userName = UniqueId("grace") + "@example.com";
        var other = NewUser(UniqueId("scim"), UniqueId("other") + "@example.com", UniqueId("oid"));

        await using (var db = storage.CreateDbContext())
        {
            await new EfScimUserRepository(db, storage.Dialect).AddAsync(NewUser(UniqueId("scim"), userName, UniqueId("oid")));
        }

        // SCIM says userName is unique, so a second record for it is a conflict.
        await using (var db = storage.CreateDbContext())
        {
            var users = new EfScimUserRepository(db, storage.Dialect);
            await Assert.ThrowsAsync<DuplicateEntityException>(() => users.AddAsync(NewUser(UniqueId("scim"), userName, UniqueId("oid"))));
        }

        await using (var db = storage.CreateDbContext())
        {
            await new EfScimUserRepository(db, storage.Dialect).AddAsync(other);
        }

        // And it cannot be taken from its owner by a replace either.
        await using (var db = storage.CreateDbContext())
        {
            var users = new EfScimUserRepository(db, storage.Dialect);
            await Assert.ThrowsAsync<DuplicateEntityException>(() => users.ReplaceAsync(other, other with { UserName = userName }));
        }

        await using (var db = storage.CreateDbContext())
        {
            Assert.Equal(other.UserName, (await new EfScimUserRepository(db, storage.Dialect).FindAsync(other.Id))!.UserName);
        }
    }

    [Fact]
    public async Task A_listing_pages_and_reports_how_many_matched_rather_than_how_many_it_returned()
    {
        await using var db = storage.CreateDbContext();
        var users = new EfScimUserRepository(db, storage.Dialect);
        var externalId = UniqueId("team");
        var names = new List<string>();
        for (var i = 0; i < 3; i++)
        {
            var userName = UniqueId("member") + "@example.com";
            names.Add(userName);
            await users.AddAsync(NewUser(UniqueId("scim"), userName, externalId));
        }

        var page = await users.ListAsync(new ScimUserFilter(null, externalId, StartIndex: 2, Count: 1));

        Assert.Equal(3, page.TotalResults);
        Assert.Single(page.Users);

        var byName = await users.ListAsync(new ScimUserFilter(names[0], null, StartIndex: 1, Count: 10));
        Assert.Equal(1, byName.TotalResults);
        Assert.Equal(names[0], Assert.Single(byName.Users).UserName);

        // A person nobody provisioned is an empty page, not an error.
        var none = await users.ListAsync(new ScimUserFilter("nobody@example.com", null, StartIndex: 1, Count: 10));
        Assert.Equal(0, none.TotalResults);
        Assert.Empty(none.Users);
    }

    [Fact]
    public async Task The_table_can_be_counted_for_the_bound_on_how_large_it_may_grow()
    {
        await using var db = storage.CreateDbContext();
        var users = new EfScimUserRepository(db, storage.Dialect);
        var before = await users.CountAsync();

        await users.AddAsync(NewUser(UniqueId("scim"), UniqueId("counted") + "@example.com", UniqueId("oid")));

        Assert.Equal(before + 1, await users.CountAsync());
    }

    [Fact]
    public async Task A_block_a_deletion_marked_stays_for_a_reactivation_and_is_lifted_once_the_mark_is_taken_off()
    {
        await using var db = storage.CreateDbContext();
        var sponsors = new EfSponsorRepository(db, storage.Dialect);
        var key = UniqueId("human");
        await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, Now));

        // A deletion marks the standing block without reporting a change of its own; a later
        // deactivation changes the kind and keeps the mark.
        var deleted = await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Deleted, Now.AddMinutes(1), PlacedByDeletion: true));
        Assert.True(deleted.Written);
        Assert.False((await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Deleted, Now.AddMinutes(2), PlacedByDeletion: true))).Written);
        await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, Now.AddMinutes(3)));
        Assert.Equal((SponsorBlockKind.Disabled, true), ((await sponsors.FindAsync(key))!.Kind, (await sponsors.FindAsync(key))!.PlacedByDeletion));

        Assert.False(await sponsors.UnblockAsync(key, SponsorBlockSource.Scim, unlessPlacedByDeletion: true));
        Assert.NotNull(await sponsors.FindAsync(key));

        await sponsors.ForgetDeletionAsync(key, SponsorBlockSource.Scim);
        Assert.False((await sponsors.FindAsync(key))!.PlacedByDeletion);
        Assert.True(await sponsors.UnblockAsync(key, SponsorBlockSource.Scim, unlessPlacedByDeletion: true));
        Assert.Null(await sponsors.FindAsync(key));
    }

    [Fact]
    public async Task A_new_block_placed_by_a_deletion_is_stored_marked_and_another_sources_block_is_never_marked()
    {
        await using var db = storage.CreateDbContext();
        var sponsors = new EfSponsorRepository(db, storage.Dialect);
        var (key, operatorBlocked) = (UniqueId("human"), UniqueId("human"));

        await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Deleted, Now, PlacedByDeletion: true));
        Assert.True((await sponsors.FindAsync(key))!.PlacedByDeletion);

        // Lifting without the condition, as no SCIM write does, ignores the mark.
        Assert.True(await sponsors.UnblockAsync(key, SponsorBlockSource.Scim));

        await sponsors.BlockAsync(new SponsorBlock(operatorBlocked, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, Now));
        await sponsors.BlockAsync(new SponsorBlock(operatorBlocked, SponsorBlockSource.Scim, SponsorBlockKind.Deleted, Now, PlacedByDeletion: true));
        var standing = (await sponsors.FindAsync(operatorBlocked))!;
        Assert.Equal((SponsorBlockSource.Admin, false), (standing.Source, standing.PlacedByDeletion));
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresScimUserStorageTests(PostgresDatabaseFixture storage) : ScimUserStorageTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteScimUserStorageTests(SqliteDatabaseFixture storage) : ScimUserStorageTests(storage);
