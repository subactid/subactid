using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SubactId.Core.Audit;
using SubactId.Core.Scim;
using SubactId.Core.Sponsors;
using SubactId.IntegrationTests.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Scim;
using SubactId.Server.Signals;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Scim;

/// <summary>
/// Two SCIM writes for records that share a person, run at the same time against a real
/// database. One is paused inside its unit of work while the other runs, so the interleaving is
/// fixed rather than left to chance.
/// </summary>
public abstract class ScimConcurrencyTests(IStorageFixture storage) : IAsyncLifetime
{
    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(30);

    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task A_reactivation_waits_for_a_deactivation_under_the_same_key_and_leaves_the_person_blocked()
    {
        // A is inactive and B active, both naming the person, who is blocked because of A.
        var key = UniqueId("oid");
        var a = await CreateAsync(key, active: false);
        var b = await CreateAsync(key, active: true);
        Assert.NotNull(await BlockOnAsync(key));
        var seq = await LastSeqAsync();

        // B's deactivation is paused once its block has been found already standing.
        var gate = new Gate(PausePoint.AfterBlock, key);
        var deactivating = Task.Run(() => SetActiveAsync(b, false, gate));
        await gate.Reached.Task.WaitAsync(Patience);

        // A's reactivation runs meanwhile. It may not decide on a state B's write has not settled.
        var reactivating = Task.Run(() => SetActiveAsync(a, true));
        await UntilWaitingOrDoneAsync(reactivating);

        gate.Release.SetResult();
        Assert.Null((await deactivating.WaitAsync(Patience)).Failure);
        Assert.Null((await reactivating.WaitAsync(Patience)).Failure);

        // B is inactive, so the person stays blocked, and nothing was lifted or recorded as lifted.
        Assert.False((await FindAsync(b.Id))!.Active);
        Assert.True((await FindAsync(a.Id))!.Active);
        Assert.Equal(SponsorBlockSource.Scim, (await BlockOnAsync(key))?.Source);
        Assert.DoesNotContain(await RecordsSinceAsync(seq, key), r => r.Reason == ScimUserService.Reactivated);
    }

    [Fact]
    public async Task A_deactivation_that_waits_for_a_reactivation_blocks_the_person_again_and_is_recorded()
    {
        var key = UniqueId("oid");
        var a = await CreateAsync(key, active: false);
        var b = await CreateAsync(key, active: true);
        var seq = await LastSeqAsync();

        // A's reactivation is paused once it has lifted the block.
        var gate = new Gate(PausePoint.AfterUnblock, key);
        var reactivating = Task.Run(() => SetActiveAsync(a, true, gate));
        await gate.Reached.Task.WaitAsync(Patience);

        var deactivating = Task.Run(() => SetActiveAsync(b, false));
        await UntilWaitingOrDoneAsync(deactivating);

        gate.Release.SetResult();
        Assert.Null((await reactivating.WaitAsync(Patience)).Failure);
        Assert.Null((await deactivating.WaitAsync(Patience)).Failure);

        Assert.False((await FindAsync(b.Id))!.Active);
        Assert.Equal(SponsorBlockSource.Scim, (await BlockOnAsync(key))?.Source);
        var records = await RecordsSinceAsync(seq, key);
        Assert.Contains(records, r => r.Event == AuditEvents.SponsorSignal && r.Reason == ScimUserService.Reactivated);
        Assert.Contains(records, r => r.Event == AuditEvents.SponsorSignal && r.Reason == ScimUserService.Deactivated);
    }

    [Fact]
    public async Task A_reactivation_and_a_deletion_under_the_same_key_do_not_deadlock()
    {
        // A is inactive and D active, both naming the person, who is blocked because of A.
        var key = UniqueId("oid");
        var a = await CreateAsync(key, active: false);
        var d = await CreateAsync(key, active: true);

        // D's deletion is paused once it has marked the block as placed by a deletion.
        var gate = new Gate(PausePoint.AfterBlock, key);
        var deleting = Task.Run(() => DeleteAsync(d, gate));
        await gate.Reached.Task.WaitAsync(Patience);

        var reactivating = Task.Run(() => SetActiveAsync(a, true));
        await UntilWaitingOrDoneAsync(reactivating);

        gate.Release.SetResult();
        Assert.Null(await deleting.WaitAsync(Patience));
        Assert.Null((await reactivating.WaitAsync(Patience)).Failure);

        // The deletion's block stays: a reactivation of another record does not lift it.
        Assert.Null(await FindAsync(d.Id));
        Assert.True((await FindAsync(a.Id))!.Active);
        var block = await BlockOnAsync(key);
        Assert.Equal((SponsorBlockSource.Scim, SponsorBlockKind.Deleted, true), (block?.Source, block?.Kind, block?.PlacedByDeletion));
    }

    /// <summary>
    /// Returns once <paramref name="work"/> has finished or is waiting on a lock another unit of
    /// work holds, so the paused write is released only after the other has had its chance to run.
    /// </summary>
    protected abstract Task UntilWaitingOrDoneAsync(Task work);

    private async Task<ScimUser> CreateAsync(string key, bool active)
    {
        var (service, db) = Service();
        await using (db)
        {
            var request = new ScimUserRequest { UserName = UniqueId("ada") + "@example.com", ExternalId = key, Active = JsonSerializer.SerializeToElement(active) };
            var (user, failure) = await service.CreateAsync(request);
            Assert.Null(failure);
            return user!;
        }
    }

    private async Task<(ScimUser? User, ScimFailure? Failure)> SetActiveAsync(ScimUser user, bool active, Gate? gate = null)
    {
        var (service, db) = Service(gate);
        await using (db)
        {
            var request = new ScimUserRequest { UserName = user.UserName, ExternalId = user.ExternalId, Active = JsonSerializer.SerializeToElement(active) };
            return await service.ReplaceAsync(user.Id, request);
        }
    }

    private async Task<ScimFailure?> DeleteAsync(ScimUser user, Gate? gate = null)
    {
        var (service, db) = Service(gate);
        await using (db)
        {
            return await service.DeleteAsync(user.Id);
        }
    }

    private async Task<ScimUser?> FindAsync(string id)
    {
        await using var db = storage.CreateDbContext();
        return await new EfScimUserRepository(db, storage.Dialect).FindAsync(id);
    }

    private async Task<SponsorBlock?> BlockOnAsync(string key)
    {
        await using var db = storage.CreateDbContext();
        return await new EfSponsorRepository(db, storage.Dialect).FindAsync(key);
    }

    private async Task<long> LastSeqAsync()
    {
        await using var db = storage.CreateDbContext();
        return await db.AuditEvents.AsNoTracking().MaxAsync(e => (long?)e.Seq) ?? 0;
    }

    private async Task<List<(string Event, string? Reason)>> RecordsSinceAsync(long seq, string key)
    {
        await using var db = storage.CreateDbContext();
        var rows = await db.AuditEvents.AsNoTracking()
            .Where(e => e.Seq > seq && e.Sponsor == key)
            .Select(e => new { e.Event, e.Reason })
            .ToListAsync();
        return rows.Select(r => (r.Event, r.Reason)).ToList();
    }

    /// <summary>The receiver as the server builds it, on a context of its own, as a request gets one.</summary>
    private (ScimUserService Service, SubactIdDbContext Db) Service(Gate? gate = null)
    {
        var db = storage.CreateDbContext();
        var unitOfWork = new EfUnitOfWork(db, storage.Dialect);
        ISponsorRepository sponsors = new EfSponsorRepository(db, storage.Dialect);
        if (gate is not null)
        {
            sponsors = new PausingSponsors(sponsors, gate);
        }

        var signals = new SponsorSignalWriter(
            sponsors,
            storage.Revocation(db),
            new EfRevocationRepository(db, storage.Dialect),
            new EfAuditWriter(db, unitOfWork, storage.Dialect),
            new RenewalSummary(new DenialAggregationOptions()));
        var options = new ScimOptions { BearerToken = "unused", SponsorKeyAttribute = ScimSponsorKeyAttribute.ExternalId, MaxUsers = int.MaxValue };
        return (new ScimUserService(new EfScimUserRepository(db, storage.Dialect), signals, unitOfWork, options, TimeProvider.System), db);
    }

    private enum PausePoint
    {
        AfterBlock,
        AfterUnblock,
    }

    /// <summary>Where a write stops, and what lets it go on.</summary>
    private sealed class Gate(PausePoint at, string sponsorKey)
    {
        public PausePoint At { get; } = at;

        public string SponsorKey { get; } = sponsorKey;

        public TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task PauseAsync(PausePoint point, string sponsorKey)
        {
            if (point == At && sponsorKey == SponsorKey && Reached.TrySetResult())
            {
                await Release.Task.WaitAsync(Patience);
            }
        }
    }

    /// <summary>The block table, paused at the gate inside the caller's unit of work.</summary>
    private sealed class PausingSponsors(ISponsorRepository inner, Gate gate) : ISponsorRepository
    {
        public Task<SponsorBlock?> FindAsync(string sponsorKey, CancellationToken cancellationToken = default) =>
            inner.FindAsync(sponsorKey, cancellationToken);

        public async Task<SponsorBlockWrite> BlockAsync(SponsorBlock block, CancellationToken cancellationToken = default)
        {
            var write = await inner.BlockAsync(block, cancellationToken);
            await gate.PauseAsync(PausePoint.AfterBlock, block.SponsorKey);
            return write;
        }

        public async Task<bool> UnblockAsync(string sponsorKey, SponsorBlockSource source, bool unlessPlacedByDeletion = false, CancellationToken cancellationToken = default)
        {
            var lifted = await inner.UnblockAsync(sponsorKey, source, unlessPlacedByDeletion, cancellationToken);
            await gate.PauseAsync(PausePoint.AfterUnblock, sponsorKey);
            return lifted;
        }

        public Task ForgetDeletionAsync(string sponsorKey, SponsorBlockSource source, CancellationToken cancellationToken = default) =>
            inner.ForgetDeletionAsync(sponsorKey, source, cancellationToken);

        public Task<bool> AdvanceSignalWatermarkAsync(string sponsorKey, DateTimeOffset eventAt, CancellationToken cancellationToken = default) =>
            inner.AdvanceSignalWatermarkAsync(sponsorKey, eventAt, cancellationToken);
    }
}

/// <summary>
/// The same tests against Postgres, where the two units of work run at once under read committed.
/// </summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresScimConcurrencyTests(PostgresDatabaseFixture storage) : ScimConcurrencyTests(storage)
{
    /// <summary>Waits until another session of this database is waiting on a lock.</summary>
    protected override async Task UntilWaitingOrDoneAsync(Task work)
    {
        await using var connection = await storage.OpenApplicationConnectionAsync();
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (!work.IsCompleted && DateTime.UtcNow < deadline)
        {
            await using var command = new NpgsqlCommand(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()",
                connection);
            if ((long)(await command.ExecuteScalarAsync())! > 0)
            {
                return;
            }

            await Task.Delay(20);
        }
    }
}

/// <summary>
/// The same tests against the embedded database, where a unit of work holds the write lock from
/// its start, so the second one waits for the first and the outcome must still be right.
/// </summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteScimConcurrencyTests(SqliteDatabaseFixture storage) : ScimConcurrencyTests(storage)
{
    /// <summary>The wait is inside the driver and cannot be seen, so the other write gets a moment.</summary>
    protected override async Task UntilWaitingOrDoneAsync(Task work) =>
        await Task.WhenAny(work, Task.Delay(TimeSpan.FromMilliseconds(500)));
}
