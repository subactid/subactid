using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Hosting;
using Xunit;

namespace SubactId.UnitTests.Audit;

/// <summary>
/// A denial that names nobody is never dropped because the ledger could not take it at that
/// moment: it is counted into the next summary for its reason, and a summary that could not be
/// written is written by the next pass.
/// </summary>
public class RefusalRecordingTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task An_admission_refusal_the_ledger_cannot_take_is_carried_into_the_next_summary()
    {
        var aggregator = new DenialAggregator(new FakeTimeProvider(Now), new DenialAggregationOptions { Enabled = true });
        var audit = new SwitchableAudit { Failing = true };
        var http = Request(aggregator, audit, "/oauth2/token");

        // The caller still gets its refusal: nothing is thrown at it.
        await RateLimiting.RecordAsync(http, RateLimiting.Reason);

        Assert.Empty(audit.Written);
        var summary = Assert.Single(aggregator.Drain());
        Assert.Equal((AuditEvents.TokenDenied, RateLimiting.Reason, (int?)1), (summary.Event, summary.Reason, summary.Count));
    }

    [Fact]
    public async Task An_admission_refusal_is_written_through_when_the_ledger_takes_it()
    {
        var aggregator = new DenialAggregator(new FakeTimeProvider(Now), new DenialAggregationOptions { Enabled = true });
        var audit = new SwitchableAudit();

        await RateLimiting.RecordAsync(Request(aggregator, audit, "/admin/agents"), RateLimiting.Reason);

        var record = Assert.Single(audit.Written);
        Assert.Equal((AuditEvents.AdminDenied, RateLimiting.Reason, AuditDecision.Deny), (record.Event, record.Reason, record.Decision));
        Assert.Empty(aggregator.Drain());
    }

    [Theory]
    [InlineData(AuditEvents.AdminDenied, "admin_key_invalid")]
    [InlineData(AuditEvents.ScimDenied, "scim_credential_invalid")]
    [InlineData(AuditEvents.SsfDenied, "ssf_credential_invalid")]
    [InlineData(AuditEvents.SignalDenied, "logout_malformed")]
    [InlineData(AuditEvents.TokenDenied, "actor_unknown_agent")]
    public async Task Any_refusal_that_names_nobody_is_carried_over_when_the_ledger_cannot_take_it(string auditEvent, string reason)
    {
        var aggregator = new DenialAggregator(new FakeTimeProvider(Now), new DenialAggregationOptions { Enabled = true });
        var audit = new SwitchableAudit { Failing = true };
        var denial = new AuditEvent(Now, auditEvent, Decision: AuditDecision.Deny, Reason: reason);

        // Nothing is thrown, so the caller still gets its refusal.
        await aggregator.RecordAsync(denial, audit);

        Assert.Empty(audit.Written);
        var summary = Assert.Single(aggregator.Drain());
        Assert.Equal((auditEvent, reason, (int?)1), (summary.Event, summary.Reason, summary.Count));
    }

    [Fact]
    public async Task A_refusal_that_names_someone_is_not_summarised_and_its_write_failure_fails_the_request()
    {
        var aggregator = new DenialAggregator(new FakeTimeProvider(Now), new DenialAggregationOptions { Enabled = true });
        var audit = new SwitchableAudit { Failing = true };
        var denial = new AuditEvent(Now, AuditEvents.TokenDenied, AgentId: "jira-triage", Decision: AuditDecision.Deny, Reason: "scope_widened");

        await Assert.ThrowsAsync<IOException>(() => aggregator.RecordAsync(denial, audit));
        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public async Task A_refusal_that_names_nobody_is_written_through_when_the_ledger_takes_it()
    {
        var aggregator = new DenialAggregator(new FakeTimeProvider(Now), new DenialAggregationOptions { Enabled = true });
        var audit = new SwitchableAudit();
        var denial = new AuditEvent(Now, AuditEvents.AdminDenied, Decision: AuditDecision.Deny, Reason: "admin_key_invalid");

        await aggregator.RecordAsync(denial, audit);

        Assert.Equal(denial, Assert.Single(audit.Written));
        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public async Task Without_somewhere_to_count_it_an_admission_refusal_is_an_error_not_a_silent_skip()
    {
        var http = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider() };
        http.Request.Path = "/oauth2/token";

        await Assert.ThrowsAsync<InvalidOperationException>(() => RateLimiting.RecordAsync(http, RateLimiting.Reason));
    }

    [Fact]
    public async Task A_window_whose_summary_could_not_be_written_is_written_by_the_next_pass()
    {
        var clock = new FakeTimeProvider(Now);
        var options = new DenialAggregationOptions { Enabled = true };
        var aggregator = new DenialAggregator(clock, options);
        var audit = new SwitchableAudit { Failing = true };
        var services = new ServiceCollection().AddScoped<IAuditWriter>(_ => audit).BuildServiceProvider();
        var flusher = new DenialAggregationFlusher(aggregator, services.GetRequiredService<IServiceScopeFactory>(), options, clock, NullLogger<DenialAggregationFlusher>.Instance);

        var denial = new AuditEvent(Now, AuditEvents.TokenDenied, Decision: AuditDecision.Deny, Reason: "actor_unknown_agent");
        Assert.True(aggregator.ShouldWriteThrough(denial));
        for (var i = 0; i < 7; i++)
        {
            aggregator.ShouldWriteThrough(denial);
        }

        await Assert.ThrowsAsync<IOException>(() => flusher.FlushAsync());
        Assert.Empty(audit.Written);

        audit.Failing = false;
        Assert.Equal(1, await flusher.FlushAsync());
        Assert.Equal(7, Assert.Single(audit.Written).Count);
    }

    private static DefaultHttpContext Request(DenialAggregator aggregator, IAuditWriter audit, string path)
    {
        var services = new ServiceCollection()
            .AddSingleton(aggregator)
            .AddSingleton<TimeProvider>(new FakeTimeProvider(Now))
            .AddSingleton(audit)
            .BuildServiceProvider();
        var http = new DefaultHttpContext { RequestServices = services };
        http.Request.Path = path;
        return http;
    }

    /// <summary>A ledger that can be made to refuse every write, as one that cannot be reached does.</summary>
    private sealed class SwitchableAudit : IAuditWriter
    {
        public bool Failing { get; set; }

        public List<AuditEvent> Written { get; } = [];

        public Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            ThrowIfFailing();
            Written.Add(auditEvent);
            return Task.FromResult((long)Written.Count);
        }

        public Task AppendAsync(IReadOnlyList<AuditEvent> auditEvents, CancellationToken cancellationToken = default)
        {
            ThrowIfFailing();
            Written.AddRange(auditEvents);
            return Task.CompletedTask;
        }

        private void ThrowIfFailing()
        {
            if (Failing)
            {
                throw new IOException("The ledger cannot be reached.");
            }
        }
    }
}
