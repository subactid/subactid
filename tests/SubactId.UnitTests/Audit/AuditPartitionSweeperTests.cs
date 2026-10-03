using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using Xunit;

namespace SubactId.UnitTests.Audit;

public class AuditPartitionSweeperTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);

    /// <summary>Partitions that record what they were asked to make sure of.</summary>
    private sealed class RecordingPartitions : IAuditLedgerPartitions
    {
        private readonly List<(DateTimeOffset From, int MonthsAhead)> calls = [];

        public IReadOnlyList<(DateTimeOffset From, int MonthsAhead)> Calls
        {
            get
            {
                lock (calls)
                {
                    return [.. calls];
                }
            }
        }

        public Task<AuditLedgerLayout> InspectAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<int> EnsureAsync(DateTimeOffset from, int monthsAhead, CancellationToken cancellationToken = default)
        {
            lock (calls)
            {
                calls.Add((from, monthsAhead));
            }

            return Task.FromResult(0);
        }
    }

    /// <summary>The runway comes from the setting and is ensured at start, not an hour later.</summary>
    [Fact]
    public async Task The_runway_the_setting_asks_for_is_made_sure_of_at_start_and_again_every_hour()
    {
        var clock = new FakeTimeProvider(Now);
        var partitions = new RecordingPartitions();
        var sweeper = new AuditPartitionSweeper(partitions, Options(monthsAhead: 3), clock, NullLogger<AuditPartitionSweeper>.Instance);

        await sweeper.StartAsync(CancellationToken.None);
        await EventuallyAsync(() => partitions.Calls.Count == 1);
        Assert.Equal((Now, 3), partitions.Calls[0]);

        clock.Advance(AuditPartitionSweeper.TopUpInterval);
        await EventuallyAsync(() => partitions.Calls.Count == 2);
        Assert.Equal((Now + AuditPartitionSweeper.TopUpInterval, 3), partitions.Calls[1]);

        await sweeper.StopAsync(CancellationToken.None);
    }

    private static SubactIdOptions Options(int monthsAhead) => new()
    {
        Issuer = new Uri("https://subactid.internal.example.com"),
        UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
        Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = "unused" },
        Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromHours(1), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
        Agents = AgentRegistrationLimits.Default,
        Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 100, Retention = TimeSpan.FromDays(3) },
        Signing = new SigningOptions { Keys = [] },
        Admin = new AdminOptions(),
        Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval, PartitionMonthsAhead = monthsAhead },
    };

    /// <summary>A pass runs on the loop's own thread, so the test waits for it.</summary>
    private static async Task EventuallyAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "the pass did not run within ten seconds");
            await Task.Delay(10);
        }
    }
}
