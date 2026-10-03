using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Revocation;
using SubactId.Core.Storage;
using SubactId.Server.Configuration;
using SubactId.Server.Revocation;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;
using RevocationRecord = SubactId.Core.Revocation.Revocation;

namespace SubactId.UnitTests.Revocation;

/// <summary>
/// The pass that removes sign-outs once no token they refuse can still be valid, and the check that
/// warns when the identity provider's tokens outlive them.
/// </summary>
public class SignOutPrunerTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 11, 12, 0, 0, TimeSpan.Zero);

    private static SubactIdOptions Options(TimeSpan retention) => new()
    {
        Issuer = new Uri("https://subactid.internal.example.com"),
        UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
        Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = "unused" },
        Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromHours(1), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
        Agents = AgentRegistrationLimits.Default,
        Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 100 },
        Revocations = new RevocationOptions { SignOutRetention = retention },
        Signing = new SigningOptions { Keys = [] },
        Admin = new AdminOptions(),
        Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
    };

    private static (SignOutPruner Pruner, InMemoryRevocations Revocations) Build(TimeSpan retention)
    {
        var revocations = new InMemoryRevocations();
        var services = new ServiceCollection();
        services.AddScoped<IRevocationRepository>(_ => revocations);
        services.AddScoped<IUnitOfWork, PassThroughUnitOfWork>();
        var provider = services.BuildServiceProvider();
        return (new SignOutPruner(provider.GetRequiredService<IServiceScopeFactory>(), Options(retention), new FakeTimeProvider(Now), NullLogger<SignOutPruner>.Instance), revocations);
    }

    private static RevocationRecord SessionLogout(DateTimeOffset at) => new(null, null, null, null, "session-" + Guid.NewGuid().ToString("N"), at, "sponsor_logged_out", "identity_provider");

    [Fact]
    public async Task Removes_sign_outs_recorded_more_than_the_retention_ago_and_keeps_the_rest()
    {
        var (pruner, revocations) = Build(TimeSpan.FromHours(24));
        var old = SessionLogout(Now.AddHours(-25));
        var personWide = new RevocationRecord(null, null, null, "oid-1", null, Now.AddHours(-30), "ssf_sessions_revoked", "signals_transmitter", IssuedBefore: Now.AddHours(-30));
        var recent = SessionLogout(Now.AddHours(-23));
        var killSwitch = new RevocationRecord(null, null, null, "oid-2", null, Now.AddDays(-10), "operator_kill_switch", "admin");
        var token = new RevocationRecord("tok_1", null, null, null, null, Now.AddDays(-10), "client_revoked", "agent", ExpiresAt: Now.AddDays(-9));
        revocations.Stored.AddRange([old, personWide, recent, killSwitch, token]);

        Assert.Equal(2, await pruner.PruneAsync());

        Assert.Equal([recent, killSwitch, token], revocations.Stored);
        Assert.Equal(Now.AddHours(-24), Assert.Single(revocations.Prunes).Before);
    }

    [Fact]
    public async Task Keeps_taking_batches_until_one_comes_back_short()
    {
        var (pruner, revocations) = Build(TimeSpan.FromHours(1));
        revocations.Stored.AddRange(Enumerable.Range(1, (SignOutPruner.BatchSize * 2) + 5).Select(i => SessionLogout(Now.AddHours(-2).AddSeconds(-i))));

        Assert.Equal((SignOutPruner.BatchSize * 2) + 5, await pruner.PruneAsync());

        Assert.Empty(revocations.Stored);
        Assert.Equal([SignOutPruner.BatchSize, SignOutPruner.BatchSize, SignOutPruner.BatchSize], revocations.Prunes.Select(p => p.BatchSize));
    }

    [Fact]
    public async Task Nothing_due_costs_one_empty_batch()
    {
        var (pruner, revocations) = Build(TimeSpan.FromHours(24));
        revocations.Stored.Add(SessionLogout(Now));

        Assert.Equal(0, await pruner.PruneAsync());

        Assert.Single(revocations.Stored);
        Assert.Single(revocations.Prunes);
    }

    [Fact]
    public void A_subject_token_that_outlives_the_retention_is_reported_once_and_not_refused()
    {
        var logger = new CountingLogger();
        var check = new SignOutRetentionCheck(Options(TimeSpan.FromMinutes(30)), logger);

        // Within the retention, counting the minute of clock skew: nothing to say. Without an iat,
        // what the token has left from now is what counts.
        Assert.False(check.Observe(Now.AddMinutes(-5), Now.AddMinutes(24), Now));
        Assert.False(check.Observe(null, Now.AddMinutes(29), Now));
        Assert.Equal(0, logger.Warnings);

        Assert.True(check.Observe(Now.AddMinutes(-5), Now.AddMinutes(25), Now));
        Assert.True(check.Observe(null, Now.AddMinutes(30), Now));
        Assert.True(check.Observe(Now, Now.AddHours(2), Now));

        Assert.Equal(1, logger.Warnings);
    }

    private sealed class CountingLogger : ILogger<SignOutRetentionCheck>
    {
        public int Warnings { get; private set; }

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings++;
            }
        }
    }
}
