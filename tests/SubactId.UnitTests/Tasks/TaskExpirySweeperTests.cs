using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Tasks;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Tasks;

public class TaskExpirySweeperTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 11, 12, 0, 0, TimeSpan.Zero);

    /// <summary>An in-memory sweep that hands out due tasks in batches, and records what it was asked.</summary>
    private sealed class QueueSweep(IEnumerable<ExpiredTask> due) : ITaskExpirySweep
    {
        private readonly Queue<ExpiredTask> queue = new(due);

        public List<(DateTimeOffset Now, int BatchSize)> Calls { get; } = [];

        public Task<IReadOnlyList<ExpiredTask>> ExpireDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default)
        {
            Calls.Add((now, batchSize));
            var batch = new List<ExpiredTask>();
            while (batch.Count < batchSize && queue.Count > 0) batch.Add(queue.Dequeue());
            return Task.FromResult<IReadOnlyList<ExpiredTask>>(batch);
        }
    }

    /// <summary>An in-memory retention purge that hands out a fixed number of removals in batches, and records what it was asked.</summary>
    private sealed class QueueRetention(int terminal) : ITaskRetention
    {
        private int remaining = terminal;

        public List<(DateTimeOffset Before, int BatchSize)> Calls { get; } = [];

        public Task<int> PurgeTerminalAsync(DateTimeOffset before, int batchSize, CancellationToken cancellationToken = default)
        {
            Calls.Add((before, batchSize));
            var removed = Math.Min(batchSize, remaining);
            remaining -= removed;
            return Task.FromResult(removed);
        }
    }

    private static readonly TimeSpan Retention = TimeSpan.FromDays(3);

    private static ExpiredTask Expired(int i) => new($"task_{i}", "jira-triage", "human", "https://jira.internal", ["jira:read", "jira:comment"], 1, Now.AddMinutes(-i));

    private static (TaskExpirySweeper Sweeper, QueueSweep Sweep, InMemoryAudit Audit) Build(int due, int batchSize) =>
        Build(due, batchSize, new QueueRetention(0));

    private static (TaskExpirySweeper Sweeper, QueueSweep Sweep, InMemoryAudit Audit) Build(int due, int batchSize, QueueRetention retention) =>
        Build(Enumerable.Range(1, due).Select(Expired), batchSize, retention);

    private static (TaskExpirySweeper Sweeper, QueueSweep Sweep, InMemoryAudit Audit) Build(IEnumerable<ExpiredTask> due, int batchSize, QueueRetention retention)
    {
        var sweep = new QueueSweep(due);
        var audit = new InMemoryAudit();
        var services = new ServiceCollection();
        services.AddScoped<ITaskExpirySweep>(_ => sweep);
        services.AddScoped<ITaskRetention>(_ => retention);
        services.AddScoped<IAuditWriter>(_ => audit);
        services.AddScoped<IUnitOfWork, PassThroughUnitOfWork>();
        var options = new SubactIdOptions
        {
            Issuer = new Uri("https://subactid.internal.example.com"),
            UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
            Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = "unused" },
            Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromHours(1), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
            Agents = AgentRegistrationLimits.Default,
            Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = batchSize, Retention = Retention },
            Signing = new SigningOptions { Keys = [] },
            Admin = new AdminOptions(),
            Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
        };
        var provider = services.BuildServiceProvider();
        return (new TaskExpirySweeper(provider.GetRequiredService<IServiceScopeFactory>(), options, new RenewalSummary(options.Audit.Aggregation), new FakeTimeProvider(Now), NullLogger<TaskExpirySweeper>.Instance), sweep, audit);
    }

    [Fact]
    public async Task Writes_one_task_expired_record_per_task_with_the_tasks_attribution()
    {
        var (sweeper, _, audit) = Build(due: 2, batchSize: 100);

        Assert.Equal(2, await sweeper.SweepAsync());

        Assert.Equal(2, audit.Events.Count);
        var first = audit.Events[0];
        Assert.Equal((AuditEvents.TaskExpired, "task_1", "jira-triage", "human", "https://jira.internal", "jira:read jira:comment", 1, null, TaskExpirySweeper.Reason), (first.Event, first.TaskId, first.AgentId, first.Sponsor, first.Audience, first.Scope, first.DelegationDepth, first.Decision, first.Reason));
        Assert.Equal(Now, first.Ts);
    }

    [Fact]
    public async Task A_task_renewed_more_than_once_expires_with_its_renewal_summary_first()
    {
        var (sweeper, _, audit) = Build([Expired(1) with { Renewals = 4 }, Expired(2) with { Renewals = 1 }, Expired(3)], batchSize: 100, new QueueRetention(0));

        Assert.Equal(3, await sweeper.SweepAsync());

        Assert.Equal([AuditEvents.TokenRefreshed, AuditEvents.TaskExpired, AuditEvents.TaskExpired, AuditEvents.TaskExpired], audit.Events.Select(e => e.Event));
        var summary = audit.Events[0];
        var expired = audit.Events[1];
        Assert.Equal(("task_1", "task_1", 3, AuditDecision.Allow, null, null, Now), (summary.TaskId, expired.TaskId, summary.Count, summary.Decision, summary.Jti, summary.Reason, summary.Ts));
        Assert.Equal((expired.AgentId, expired.Sponsor, expired.Audience, expired.Scope, expired.DelegationDepth), (summary.AgentId, summary.Sponsor, summary.Audience, summary.Scope, summary.DelegationDepth));
        Assert.All(audit.Events.Skip(1), e => Assert.Null(e.Count));
    }

    [Fact]
    public async Task Keeps_taking_batches_until_one_comes_back_short()
    {
        var (sweeper, sweep, audit) = Build(due: 250, batchSize: 100);

        Assert.Equal(250, await sweeper.SweepAsync());

        Assert.Equal([100, 100, 100], sweep.Calls.Select(c => c.BatchSize));
        Assert.Equal(250, audit.Events.Count);
        Assert.Equal(250, audit.Events.Select(e => e.TaskId).Distinct().Count());
    }

    [Fact]
    public async Task An_exact_multiple_of_the_batch_costs_one_extra_empty_pass_and_nothing_else()
    {
        var (sweeper, sweep, _) = Build(due: 200, batchSize: 100);

        Assert.Equal(200, await sweeper.SweepAsync());

        Assert.Equal(3, sweep.Calls.Count);
    }

    [Fact]
    public async Task Nothing_due_means_no_records()
    {
        var (sweeper, _, audit) = Build(due: 0, batchSize: 100);

        Assert.Equal(0, await sweeper.SweepAsync());
        Assert.Empty(audit.Events);
    }

    [Fact]
    public async Task The_purge_removes_tasks_that_expired_before_the_retention_period_in_batches_and_records_nothing()
    {
        var retention = new QueueRetention(250);
        var (sweeper, _, audit) = Build(due: 0, batchSize: 100, retention);

        Assert.Equal(250, await sweeper.PurgeAsync());

        // Every batch asks for what expired before now minus the retention period, never for anything younger.
        Assert.Equal([100, 100, 100], retention.Calls.Select(c => c.BatchSize));
        Assert.All(retention.Calls, c => Assert.Equal(Now - Retention, c.Before));
        // Housekeeping, not a decision about anyone: the ledger already holds the task's own record.
        Assert.Empty(audit.Events);
    }
}
