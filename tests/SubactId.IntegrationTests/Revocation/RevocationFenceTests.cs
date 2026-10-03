using SubactId.Core.Delegation;
using SubactId.Core.Sponsors;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Revocation;

/// <summary>
/// An exchange storing a task and a revocation by person or session, interleaved by hand. Whichever
/// gets in first, the task never outlives the revocation: either the revocation waits and ends
/// it, or the exchange waits and sees the block. On Postgres the scope locks do the waiting; on
/// SQLite the write lock every unit of work takes does.
/// </summary>
public abstract class RevocationFenceTests(IStorageFixture storage) : IAsyncLifetime
{
    private static readonly TimeSpan StillWaiting = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan Done = TimeSpan.FromSeconds(30);

    private string agentId = null!;

    /// <summary>Whether two units of work can be open at once at all. SQLite serialises every one.</summary>
    protected virtual bool IssuesRunTogether => true;

    public async Task InitializeAsync()
    {
        await storage.EnsureMigratedAsync();
        agentId = UniqueId("fence");
        await using var db = storage.CreateDbContext();
        await new EfAgentRepository(db, storage.Dialect).AddAsync(NewAgent(agentId));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task A_block_that_starts_while_a_task_is_being_stored_waits_for_it_and_ends_it()
    {
        var human = UniqueId("human");
        var task = Live(human);

        // The exchange is inside its unit of work, past the fence, about to store the task.
        await using var exchange = storage.CreateDbContext();
        await using var exchangeTransaction = await storage.Dialect.BeginTransactionAsync(exchange, CancellationToken.None);
        await new EfRevocationFence(exchange).EnterIssueAsync(human, human, sessionId: null, agentId);
        Assert.Null(await new EfSponsorRepository(exchange, storage.Dialect).FindAsync(human));

        // The block arrives now.
        var block = BlockAndRevokeAsync(human);
        await Task.WhenAny(block, Task.Delay(StillWaiting));
        Assert.False(block.IsCompleted);

        await new EfTaskRepository(exchange, storage.Dialect).AddAsync(task);
        await exchangeTransaction.CommitAsync();

        var revoked = await block.WaitAsync(Done);
        Assert.Contains(task.TaskId, revoked);
    }

    [Fact]
    public async Task An_exchange_that_reaches_the_fence_during_a_block_waits_and_then_sees_the_block()
    {
        var human = UniqueId("human");

        // The block's unit of work has written the block and is revoking.
        await using var blocker = storage.CreateDbContext();
        await using var blockTransaction = await storage.Dialect.BeginTransactionAsync(blocker, CancellationToken.None);
        await new EfSponsorRepository(blocker, storage.Dialect).BlockAsync(new SponsorBlock(human, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, DateTimeOffset.UtcNow));
        await storage.Revocation(blocker).RevokeSponsorTasksAsync(human, DateTimeOffset.UtcNow, "sponsor_blocked");

        // The exchange gets to its fence now.
        var seen = Task.Run(async () =>
        {
            await using var exchange = storage.CreateDbContext();
            await using var transaction = await storage.Dialect.BeginTransactionAsync(exchange, CancellationToken.None);
            await new EfRevocationFence(exchange).EnterIssueAsync(human, human, sessionId: null, agentId);
            var found = await new EfSponsorRepository(exchange, storage.Dialect).FindAsync(human);
            await transaction.CommitAsync();
            return found;
        });
        await Task.WhenAny(seen, Task.Delay(StillWaiting));
        Assert.False(seen.IsCompleted);

        await blockTransaction.CommitAsync();

        var block = await seen.WaitAsync(Done);
        Assert.NotNull(block);
        Assert.Equal(SponsorBlockKind.Disabled, block.Kind);
    }

    [Fact]
    public async Task A_logout_of_a_session_waits_for_a_task_that_session_is_storing_and_ends_it()
    {
        var human = UniqueId("human");
        var session = UniqueId("sid");
        var task = Live(human, session);

        await using var exchange = storage.CreateDbContext();
        await using var exchangeTransaction = await storage.Dialect.BeginTransactionAsync(exchange, CancellationToken.None);
        await new EfRevocationFence(exchange).EnterIssueAsync(human, human, session, agentId);

        var logout = Task.Run(async () =>
        {
            await using var db = storage.CreateDbContext();
            await using var transaction = await storage.Dialect.BeginTransactionAsync(db, CancellationToken.None);
            var ended = await storage.Revocation(db).RevokeSessionTasksAsync(session, DateTimeOffset.UtcNow, "logged_out");
            await transaction.CommitAsync();
            return ended.Select(t => t.TaskId).ToList();
        });
        await Task.WhenAny(logout, Task.Delay(StillWaiting));
        Assert.False(logout.IsCompleted);

        await new EfTaskRepository(exchange, storage.Dialect).AddAsync(task);
        await exchangeTransaction.CommitAsync();

        Assert.Contains(task.TaskId, await logout.WaitAsync(Done));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task An_exchange_that_reaches_the_fence_during_a_logout_waits_and_then_sees_it(bool namesSession)
    {
        var human = UniqueId("human");
        var session = UniqueId("sid");
        var issuedAt = DateTimeOffset.UtcNow.AddMinutes(-1);

        // The logout's unit of work has walked the session's or the person's tasks and recorded
        // the sign-out, as the logout receiver does, and has not committed.
        await using var logout = storage.CreateDbContext();
        await using var logoutTransaction = await storage.Dialect.BeginTransactionAsync(logout, CancellationToken.None);
        var now = DateTimeOffset.UtcNow;
        if (namesSession)
        {
            await storage.Revocation(logout).RevokeSessionTasksAsync(session, now, "sponsor_logged_out");
            await new EfRevocationRepository(logout, storage.Dialect).AddAsync(new(null, null, null, null, session, now, "sponsor_logged_out", "identity_provider"));
        }
        else
        {
            await storage.Revocation(logout).RevokeSubjectTasksAsync(human, now, "sponsor_logged_out");
            await new EfRevocationRepository(logout, storage.Dialect).AddAsync(new(null, null, null, null, null, now, "sponsor_logged_out", "identity_provider", Subject: human, IssuedBefore: now));
        }

        // The exchange gets to its fence now, with a subject token from before the logout.
        var signedOut = Task.Run(async () =>
        {
            await using var exchange = storage.CreateDbContext();
            await using var transaction = await storage.Dialect.BeginTransactionAsync(exchange, CancellationToken.None);
            await new EfRevocationFence(exchange).EnterIssueAsync(human, human, session, agentId);
            var found = await new EfRevocationRepository(exchange, storage.Dialect).IsSignedOutAsync(new SubactId.Core.Revocation.SignIn(human, human, session, issuedAt));
            await transaction.CommitAsync();
            return found;
        });
        await Task.WhenAny(signedOut, Task.Delay(StillWaiting));
        Assert.False(signedOut.IsCompleted);

        await logoutTransaction.CommitAsync();

        Assert.True(await signedOut.WaitAsync(Done));
    }

    [Fact]
    public async Task An_agents_kill_switch_waits_for_a_task_being_issued_to_it_and_ends_it()
    {
        var human = UniqueId("human");
        var task = Live(human);

        await using var exchange = storage.CreateDbContext();
        await using var exchangeTransaction = await storage.Dialect.BeginTransactionAsync(exchange, CancellationToken.None);
        await new EfRevocationFence(exchange).EnterIssueAsync(human, human, sessionId: null, agentId);

        var killSwitch = Task.Run(async () =>
        {
            await using var db = storage.CreateDbContext();
            await using var transaction = await storage.Dialect.BeginTransactionAsync(db, CancellationToken.None);
            var ended = await storage.Revocation(db).RevokeAgentTasksAsync(agentId, DateTimeOffset.UtcNow, "operator_kill_switch");
            await transaction.CommitAsync();
            return ended.Select(t => t.TaskId).ToList();
        });
        await Task.WhenAny(killSwitch, Task.Delay(StillWaiting));
        Assert.False(killSwitch.IsCompleted);

        await new EfTaskRepository(exchange, storage.Dialect).AddAsync(task);
        await exchangeTransaction.CommitAsync();

        Assert.Contains(task.TaskId, await killSwitch.WaitAsync(Done));
    }

    [Fact]
    public async Task Exchanges_for_one_person_do_not_wait_for_each_other()
    {
        // The fence is shared among issues: only a revocation takes it exclusively.
        if (!IssuesRunTogether)
        {
            return;
        }

        var human = UniqueId("human");
        await using var first = storage.CreateDbContext();
        await using var firstTransaction = await storage.Dialect.BeginTransactionAsync(first, CancellationToken.None);
        await new EfRevocationFence(first).EnterIssueAsync(human, human, sessionId: null, agentId);

        await using var second = storage.CreateDbContext();
        await using var secondTransaction = await storage.Dialect.BeginTransactionAsync(second, CancellationToken.None);
        await new EfRevocationFence(second).EnterIssueAsync(human, human, sessionId: null, agentId).WaitAsync(Done);

        await secondTransaction.CommitAsync();
        await firstTransaction.CommitAsync();
    }

    [Fact]
    public void Scopes_of_different_kinds_never_share_a_name()
    {
        // A sponsor key that happens to equal a session id is still another scope.
        Assert.NotEqual(RevocationScope.Sponsor("x"), RevocationScope.Session("x"));
        Assert.NotEqual(RevocationScope.LockKey(RevocationScope.Sponsor("x")), RevocationScope.LockKey(RevocationScope.Subject("x")));
    }

    private DelegationTask Live(string human, string? session = null) =>
        NewTask(agentId, sponsor: human, sessionId: session) with { CreatedAt = DateTimeOffset.UtcNow.AddSeconds(-1), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(30) };

    /// <summary>A block in a unit of work of its own, as the admin API places one: the block, then the revocation.</summary>
    private Task<List<string>> BlockAndRevokeAsync(string human) => Task.Run(async () =>
    {
        await using var db = storage.CreateDbContext();
        await using var transaction = await storage.Dialect.BeginTransactionAsync(db, CancellationToken.None);
        await new EfSponsorRepository(db, storage.Dialect).BlockAsync(new SponsorBlock(human, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, DateTimeOffset.UtcNow));
        var ended = await storage.Revocation(db).RevokeSponsorTasksAsync(human, DateTimeOffset.UtcNow, "sponsor_blocked");
        await transaction.CommitAsync();
        return ended.Select(t => t.TaskId).ToList();
    });
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresRevocationFenceTests(PostgresDatabaseFixture storage) : RevocationFenceTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteRevocationFenceTests(SqliteDatabaseFixture storage) : RevocationFenceTests(storage)
{
    /// <inheritdoc />
    protected override bool IssuesRunTogether => false;
}
