using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Sponsors;
using SubactId.Storage.Ef.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Storage;

/// <summary>
/// The blocked-sponsor table against a real database: the round trip, the rule that only the
/// source that placed a block may lift it, and the backfill that gives existing tasks a sponsor key.
/// </summary>
[Collection(SqliteCollection.Name)]
public class SponsorBlockStorageTests(SqliteDatabaseFixture storage) : IAsyncLifetime
{
    private static readonly DateTimeOffset BlockedAt = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task A_block_is_stored_read_back_and_lifted_by_the_source_that_placed_it()
    {
        await using var db = storage.CreateDbContext();
        var sponsors = new EfSponsorRepository(db, storage.Dialect);
        var key = UniqueId("human");

        Assert.Null(await sponsors.FindAsync(key));

        await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, BlockedAt));
        var stored = await sponsors.FindAsync(key);

        Assert.NotNull(stored);
        Assert.Equal((key, SponsorBlockSource.Admin, SponsorBlockKind.Disabled), (stored.SponsorKey, stored.Source, stored.Kind));
        Assert.Equal(BlockedAt, stored.BlockedAt);

        Assert.False(await sponsors.UnblockAsync(key, SponsorBlockSource.Scim));
        Assert.NotNull(await sponsors.FindAsync(key));

        Assert.True(await sponsors.UnblockAsync(key, SponsorBlockSource.Admin));
        Assert.Null(await sponsors.FindAsync(key));
        Assert.False(await sponsors.UnblockAsync(key, SponsorBlockSource.Admin));
    }

    [Fact]
    public async Task A_second_source_reaching_the_same_conclusion_leaves_the_first_block_standing()
    {
        await using var db = storage.CreateDbContext();
        var sponsors = new EfSponsorRepository(db, storage.Dialect);
        var key = UniqueId("human");
        Assert.True((await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, BlockedAt))).Written);

        var write = await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, BlockedAt.AddMinutes(1)));

        Assert.False(write.Written);
        Assert.Equal((SponsorBlockSource.Scim, SponsorBlockKind.Disabled, BlockedAt), (write.Standing.Source, write.Standing.Kind, write.Standing.BlockedAt));
        Assert.Equal(write.Standing, await sponsors.FindAsync(key));
        Assert.Equal(1, await db.SponsorBlocks.AsNoTracking().CountAsync(s => s.SponsorKey == key));

        // The second source cannot lift a block it never owned.
        Assert.False(await sponsors.UnblockAsync(key, SponsorBlockSource.Admin));
        Assert.NotNull(await sponsors.FindAsync(key));
    }

    [Fact]
    public async Task The_same_source_blocking_again_keeps_its_block_and_only_a_new_kind_changes_it()
    {
        await using var db = storage.CreateDbContext();
        var sponsors = new EfSponsorRepository(db, storage.Dialect);
        var key = UniqueId("human");
        await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, BlockedAt));

        var again = await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, BlockedAt.AddMinutes(1)));
        Assert.False(again.Written);
        Assert.Equal(BlockedAt, (await sponsors.FindAsync(key))!.BlockedAt);

        var deleted = await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Scim, SponsorBlockKind.Deleted, BlockedAt.AddMinutes(2)));
        Assert.True(deleted.Written);
        Assert.Equal((SponsorBlockKind.Deleted, BlockedAt.AddMinutes(2)), (deleted.Standing.Kind, deleted.Standing.BlockedAt));
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("deleted")]
    public async Task Only_a_kind_and_a_source_the_domain_knows_may_be_stored(string kind)
    {
        await using var db = storage.CreateDbContext();
        var key = UniqueId("human");

        await db.Database.ExecuteSqlRawAsync(
            "INSERT INTO sponsor_blocks (sponsor_key, source, kind, blocked_at, placed_by_deletion) VALUES ({0}, 'admin', {1}, {2}, 0)",
            key,
            kind,
            BlockedAt);

        await Assert.ThrowsAsync<SqliteException>(() => db.Database.ExecuteSqlRawAsync(
            "INSERT INTO sponsor_blocks (sponsor_key, source, kind, blocked_at, placed_by_deletion) VALUES ({0}, 'hearsay', 'disabled', {1}, 0)",
            UniqueId("human"),
            BlockedAt));
    }
}
