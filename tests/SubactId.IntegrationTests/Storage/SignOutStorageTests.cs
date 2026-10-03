using Microsoft.EntityFrameworkCore;
using SubactId.Core.Revocation;
using SubactId.Core.Sponsors;
using SubactId.Storage.Ef.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;
using RevocationRecord = SubactId.Core.Revocation.Revocation;

namespace SubactId.IntegrationTests.Storage;

/// <summary>
/// What an exchange reads to refuse a subject token that was signed out, and the order Shared
/// Signals account events are kept in, against each provider: the queries are the provider's, and so is the way
/// timestamps compare.
/// </summary>
public abstract class SignOutStorageTests(IStorageFixture storage) : IAsyncLifetime
{
    private static readonly DateTimeOffset Now = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task A_session_logout_signs_out_every_token_of_that_session_and_no_other()
    {
        await using var db = storage.CreateDbContext();
        var revocations = new EfRevocationRepository(db, storage.Dialect);
        var (subject, session) = (UniqueId("human"), UniqueId("session"));

        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, subject, session, Now)));
        await revocations.AddAsync(new RevocationRecord(null, null, null, null, session, Now, "sponsor_logged_out", "identity_provider"));

        Assert.True(await revocations.IsSignedOutAsync(new SignIn(subject, subject, session, Now.AddHours(1))));
        Assert.True(await revocations.IsSignedOutAsync(new SignIn(subject, subject, session, null)));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, subject, UniqueId("session"), Now.AddMinutes(-1))));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, subject, null, Now.AddMinutes(-1))));
    }

    [Fact]
    public async Task A_logout_of_the_person_signs_out_their_tokens_issued_before_it_by_their_sub()
    {
        await using var db = storage.CreateDbContext();
        var revocations = new EfRevocationRepository(db, storage.Dialect);
        var (subject, key) = (UniqueId("human"), UniqueId("oid"));
        await revocations.AddAsync(new RevocationRecord(null, null, null, null, null, Now.AddSeconds(3), "sponsor_logged_out", "identity_provider", Subject: subject, IssuedBefore: Now));

        Assert.True(await revocations.IsSignedOutAsync(new SignIn(subject, key, null, Now.AddSeconds(-1))));
        Assert.True(await revocations.IsSignedOutAsync(new SignIn(subject, key, UniqueId("session"), Now.AddDays(-1))));
        Assert.True(await revocations.IsSignedOutAsync(new SignIn(subject, key, null, null)));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, key, null, Now)));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, key, null, Now.AddSeconds(1))));

        // Matched by sub, not by sponsor key: another person whose key is this sub is not signed out.
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(UniqueId("human"), subject, null, Now.AddSeconds(-1))));
    }

    [Fact]
    public async Task A_session_revocation_by_sponsor_key_signs_out_older_tokens_and_a_kill_switch_does_not()
    {
        await using var db = storage.CreateDbContext();
        var revocations = new EfRevocationRepository(db, storage.Dialect);
        var (subject, revoked, killed) = (UniqueId("human"), UniqueId("oid"), UniqueId("oid"));
        await revocations.AddAsync(new RevocationRecord(null, null, null, revoked, null, Now, "ssf_sessions_revoked", "signals_transmitter", IssuedBefore: Now));
        await revocations.AddAsync(new RevocationRecord(null, null, null, killed, null, Now, "operator_kill_switch", "admin"));

        Assert.True(await revocations.IsSignedOutAsync(new SignIn(subject, revoked, null, Now.AddMinutes(-1))));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, revoked, null, Now.AddMinutes(1))));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, killed, null, Now.AddMinutes(-1))));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, killed, null, null)));
    }

    [Fact]
    public async Task A_sign_out_must_name_a_person_and_a_logout_by_sub_is_stored_as_such()
    {
        await using var db = storage.CreateDbContext();
        var revocations = new EfRevocationRepository(db, storage.Dialect);

        await Assert.ThrowsAsync<ArgumentException>(() => revocations.AddAsync(new RevocationRecord(null, null, null, null, UniqueId("session"), Now, "sponsor_logged_out", "identity_provider", IssuedBefore: Now)));
        await Assert.ThrowsAsync<ArgumentException>(() => revocations.AddAsync(new RevocationRecord(null, null, null, UniqueId("oid"), null, Now, "sponsor_logged_out", "identity_provider", Subject: UniqueId("human"))));
    }

    [Fact]
    public async Task Pruning_removes_only_sign_outs_recorded_before_the_cutoff_oldest_first_in_bounded_batches()
    {
        // Far enough in the past that no other test's rows are due at this cutoff.
        var longAgo = new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var cutoff = longAgo.AddDays(10);
        await using var db = storage.CreateDbContext();
        var revocations = new EfRevocationRepository(db, storage.Dialect);
        var (subject, key, agent) = (UniqueId("human"), UniqueId("oid"), UniqueId("agent"));
        var (oldest, older, old, recent) = (UniqueId("session"), UniqueId("session"), UniqueId("session"), UniqueId("session"));

        // Three sign-outs before the cutoff: two logouts of a session and a person-wide sign-out.
        await revocations.AddAsync(new RevocationRecord(null, null, null, null, oldest, longAgo, "sponsor_logged_out", "identity_provider"));
        await revocations.AddAsync(new RevocationRecord(null, null, null, null, older, longAgo.AddDays(1), "sponsor_logged_out", "identity_provider"));
        await revocations.AddAsync(new RevocationRecord(null, null, null, null, null, longAgo.AddDays(2), "sponsor_logged_out", "identity_provider", Subject: subject, IssuedBefore: longAgo.AddDays(2)));

        // Kept: a sign-out after the cutoff, and every other kind of revocation however old.
        await revocations.AddAsync(new RevocationRecord(null, null, null, null, recent, cutoff.AddSeconds(1), "sponsor_logged_out", "identity_provider"));
        await revocations.AddAsync(new RevocationRecord(null, null, null, key, null, longAgo, "operator_kill_switch", "admin"));
        await revocations.AddAsync(new RevocationRecord(null, null, agent, null, null, longAgo, "operator_kill_switch", "admin"));
        await revocations.AddAsync(new RevocationRecord(null, UniqueId("task"), null, null, null, longAgo, "client_revoked", agent));
        var jti = UniqueId("tok");
        await revocations.AddAsync(new RevocationRecord(jti, null, null, null, null, longAgo, "client_revoked", agent, ExpiresAt: longAgo.AddMinutes(5)));

        // Another person's tokens of those sessions, so the person-wide sign-out does not answer.
        var (someone, theirKey) = (UniqueId("human"), UniqueId("oid"));
        Assert.Equal(2, await revocations.PruneSignOutsAsync(cutoff, batchSize: 2));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(someone, theirKey, oldest, null)));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(someone, theirKey, older, null)));
        Assert.True(await revocations.IsSignedOutAsync(new SignIn(subject, key, null, longAgo)));

        Assert.Equal(1, await revocations.PruneSignOutsAsync(cutoff, batchSize: 2));
        Assert.False(await revocations.IsSignedOutAsync(new SignIn(subject, key, null, longAgo)));
        Assert.Equal(0, await revocations.PruneSignOutsAsync(cutoff, batchSize: 2));

        Assert.True(await revocations.IsSignedOutAsync(new SignIn(someone, theirKey, recent, null)));
        Assert.Equal(1, await db.Revocations.AsNoTracking().CountAsync(r => r.SponsorKey == key));
        Assert.Equal(2, await db.Revocations.AsNoTracking().CountAsync(r => r.AgentId == agent || (r.RevokedBy == agent && r.TaskId != null)));
        Assert.NotNull(await revocations.FindTokenAsync(jti));
    }

    [Fact]
    public async Task The_signal_watermark_moves_forward_and_refuses_an_older_event()
    {
        await using var db = storage.CreateDbContext();
        var sponsors = new EfSponsorRepository(db, storage.Dialect);
        var (key, other) = (UniqueId("human"), UniqueId("human"));

        Assert.True(await sponsors.AdvanceSignalWatermarkAsync(key, Now.AddMinutes(-3)));
        Assert.True(await sponsors.AdvanceSignalWatermarkAsync(key, Now.AddMinutes(-1)));

        // Older than the latest: refused, and the watermark does not move back.
        Assert.False(await sponsors.AdvanceSignalWatermarkAsync(key, Now.AddMinutes(-2)));
        Assert.Equal(Now.AddMinutes(-1), (await db.SignalWatermarks.AsNoTracking().SingleAsync(w => w.SponsorKey == key)).EventAt);

        // The same instant as the latest is applied after it.
        Assert.True(await sponsors.AdvanceSignalWatermarkAsync(key, Now.AddMinutes(-1)));

        // Kept per person.
        Assert.True(await sponsors.AdvanceSignalWatermarkAsync(other, Now.AddDays(-1)));
    }

    [Fact]
    public async Task A_late_event_waits_for_a_newer_one_being_applied_and_is_then_refused()
    {
        var key = UniqueId("human");

        // A newer event for the person is being applied and has not committed.
        await using var newer = storage.CreateDbContext();
        await using var newerTransaction = await storage.Dialect.BeginTransactionAsync(newer, CancellationToken.None);
        Assert.True(await new EfSponsorRepository(newer, storage.Dialect).AdvanceSignalWatermarkAsync(key, Now));

        var late = Task.Run(async () =>
        {
            await using var db = storage.CreateDbContext();
            await using var transaction = await storage.Dialect.BeginTransactionAsync(db, CancellationToken.None);
            var applied = await new EfSponsorRepository(db, storage.Dialect).AdvanceSignalWatermarkAsync(key, Now.AddMinutes(-1));
            await transaction.CommitAsync();
            return applied;
        });
        await Task.WhenAny(late, Task.Delay(TimeSpan.FromMilliseconds(500)));
        Assert.False(late.IsCompleted);

        await newerTransaction.CommitAsync();

        Assert.False(await late.WaitAsync(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public async Task A_block_is_lifted_by_its_source_whatever_the_order_of_events()
    {
        // The order is the watermark's to keep; a block carries none.
        await using var db = storage.CreateDbContext();
        var sponsors = new EfSponsorRepository(db, storage.Dialect);
        var key = UniqueId("human");
        await sponsors.BlockAsync(new SponsorBlock(key, SponsorBlockSource.Ssf, SponsorBlockKind.Disabled, Now));

        Assert.False(await sponsors.UnblockAsync(key, SponsorBlockSource.Admin));
        Assert.True(await sponsors.UnblockAsync(key, SponsorBlockSource.Ssf));
        Assert.Null(await sponsors.FindAsync(key));
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresSignOutStorageTests(PostgresDatabaseFixture storage) : SignOutStorageTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteSignOutStorageTests(SqliteDatabaseFixture storage) : SignOutStorageTests(storage);
