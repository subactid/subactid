using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using Xunit;

namespace SubactId.UnitTests.Audit;

public class DenialAggregatorTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static DenialAggregator Aggregator(out FakeTimeProvider clock, bool enabled = true)
    {
        clock = new FakeTimeProvider(Now);
        return new DenialAggregator(clock, new DenialAggregationOptions { Enabled = enabled });
    }

    private static AuditEvent Anonymous(string reason = "actor_unknown_agent", string name = AuditEvents.TokenDenied) =>
        new(Now, name, Decision: AuditDecision.Deny, Reason: reason);

    [Fact]
    public void The_first_denial_of_a_reason_is_written_through_and_the_rest_are_counted()
    {
        var aggregator = Aggregator(out _);

        Assert.True(aggregator.ShouldWriteThrough(Anonymous()));
        for (var i = 0; i < 99; i++)
        {
            Assert.False(aggregator.ShouldWriteThrough(Anonymous()));
        }

        var summary = Assert.Single(aggregator.Drain());
        Assert.Equal(99, summary.Count);
        Assert.Equal("actor_unknown_agent", summary.Reason);
        Assert.Equal(AuditDecision.Deny, summary.Decision);
    }

    [Fact]
    public void A_denial_that_names_an_agent_is_never_counted()
    {
        var aggregator = Aggregator(out _);

        // A denial naming an agent is always written, however many arrive.
        for (var i = 0; i < 100; i++)
        {
            Assert.True(aggregator.ShouldWriteThrough(Anonymous() with { AgentId = "jira-triage" }));
        }

        Assert.Empty(aggregator.Drain());
    }

    [Theory]
    [InlineData("sponsor")]
    [InlineData("task")]
    [InlineData("jti")]
    public void A_denial_carrying_any_identity_is_never_counted(string field)
    {
        var aggregator = Aggregator(out _);
        var record = field switch
        {
            "sponsor" => Anonymous() with { Sponsor = "f47ac10b-58cc-4372-a567-0e02b2c3d479" },
            "task" => Anonymous() with { TaskId = "task_01HQZX9K4M" },
            _ => Anonymous() with { Jti = "tok_01HQZX9K5P" },
        };

        Assert.True(aggregator.ShouldWriteThrough(record));
        Assert.True(aggregator.ShouldWriteThrough(record));
        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public void An_allowed_record_is_never_counted()
    {
        var aggregator = Aggregator(out _);

        Assert.True(aggregator.ShouldWriteThrough(new AuditEvent(Now, AuditEvents.TokenIssued, Decision: AuditDecision.Allow)));
        Assert.True(aggregator.ShouldWriteThrough(new AuditEvent(Now, AuditEvents.TokenIssued, Decision: AuditDecision.Allow)));
        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public void Each_reason_and_each_event_keeps_its_own_count()
    {
        var aggregator = Aggregator(out _);

        foreach (var record in new[] { Anonymous("actor_malformed"), Anonymous("actor_invalid_signature"), Anonymous("missing_api_key", AuditEvents.AdminDenied) })
        {
            Assert.True(aggregator.ShouldWriteThrough(record));
            Assert.False(aggregator.ShouldWriteThrough(record));
            Assert.False(aggregator.ShouldWriteThrough(record));
        }

        var summaries = aggregator.Drain();
        Assert.Equal(3, summaries.Count);
        Assert.All(summaries, s => Assert.Equal(2, s.Count));
        Assert.Contains(summaries, s => s.Event == AuditEvents.AdminDenied && s.Reason == "missing_api_key");
        Assert.Equal(["actor_invalid_signature", "actor_malformed", "missing_api_key"], summaries.Select(s => s.Reason).Order());
    }

    [Fact]
    public void A_drain_closes_the_window_so_the_next_denial_is_written_through_again()
    {
        var aggregator = Aggregator(out _);

        Assert.True(aggregator.ShouldWriteThrough(Anonymous()));
        Assert.False(aggregator.ShouldWriteThrough(Anonymous()));
        Assert.Single(aggregator.Drain());

        // A new window: the ledger records it straight away, not a window later.
        Assert.True(aggregator.ShouldWriteThrough(Anonymous()));
    }

    [Fact]
    public void A_reason_that_happened_once_produces_no_summary()
    {
        var aggregator = Aggregator(out _);

        Assert.True(aggregator.ShouldWriteThrough(Anonymous()));

        // Its one occurrence was already written, so no "zero more" summary.
        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public void A_summary_is_stamped_when_it_is_drained_not_when_the_window_opened()
    {
        var aggregator = Aggregator(out var clock);

        aggregator.ShouldWriteThrough(Anonymous());
        aggregator.ShouldWriteThrough(Anonymous());
        clock.Advance(TimeSpan.FromMinutes(1));

        Assert.Equal(Now.AddMinutes(1), Assert.Single(aggregator.Drain()).Ts);
    }

    [Fact]
    public void A_summary_carries_no_identity_because_the_denials_it_counts_had_none()
    {
        var aggregator = Aggregator(out _);

        aggregator.ShouldWriteThrough(Anonymous());
        aggregator.ShouldWriteThrough(Anonymous());

        var summary = Assert.Single(aggregator.Drain());
        Assert.Null(summary.AgentId);
        Assert.Null(summary.Sponsor);
        Assert.Null(summary.TaskId);
        Assert.Null(summary.Jti);
        Assert.Null(summary.Scope);
        Assert.Null(summary.Audience);
    }

    [Fact]
    public void A_summary_is_not_itself_aggregated()
    {
        var aggregator = Aggregator(out _);

        // Otherwise a drained summary fed back in would open a window of its own and the counts
        // would compound.
        var summary = new AuditEvent(Now, AuditEvents.TokenDenied, Decision: AuditDecision.Deny, Reason: "actor_malformed", Count: 12);
        Assert.True(aggregator.ShouldWriteThrough(summary));
        Assert.True(aggregator.ShouldWriteThrough(summary));
        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public void Switched_off_nothing_is_counted()
    {
        var aggregator = Aggregator(out _, enabled: false);

        for (var i = 0; i < 10; i++)
        {
            Assert.True(aggregator.ShouldWriteThrough(Anonymous()));
        }

        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public void A_denial_that_could_not_be_written_is_counted_into_the_next_summary()
    {
        var aggregator = Aggregator(out _);

        // Written through, but the write failed: it comes back rather than being lost.
        var first = Anonymous();
        Assert.True(aggregator.ShouldWriteThrough(first));
        aggregator.CarryOver(first);
        Assert.False(aggregator.ShouldWriteThrough(Anonymous()));

        Assert.Equal(2, Assert.Single(aggregator.Drain()).Count);
    }

    [Fact]
    public void A_summary_that_could_not_be_written_comes_back_whole()
    {
        var aggregator = Aggregator(out _);
        Assert.True(aggregator.ShouldWriteThrough(Anonymous()));
        for (var i = 0; i < 41; i++)
        {
            aggregator.ShouldWriteThrough(Anonymous());
        }

        var failed = Assert.Single(aggregator.Drain());
        aggregator.CarryOver(failed);

        // The next window starts with the 41 that were never written, and adds to them.
        aggregator.ShouldWriteThrough(Anonymous());
        Assert.Equal(42, Assert.Single(aggregator.Drain()).Count);
    }

    [Fact]
    public void Switched_off_a_denial_that_could_not_be_written_is_still_kept()
    {
        var aggregator = Aggregator(out _, enabled: false);

        aggregator.CarryOver(Anonymous());

        Assert.Equal(1, Assert.Single(aggregator.Drain()).Count);
    }

    [Theory]
    [InlineData("agent")]
    [InlineData("sponsor")]
    [InlineData("task")]
    [InlineData("jti")]
    [InlineData("allow")]
    public void Only_a_denial_that_names_nobody_can_be_carried_over(string kind)
    {
        var aggregator = Aggregator(out _);
        var record = kind switch
        {
            "agent" => Anonymous() with { AgentId = "agent" },
            "sponsor" => Anonymous() with { Sponsor = "human" },
            "task" => Anonymous() with { TaskId = "task_1" },
            "jti" => Anonymous() with { Jti = "jti" },
            _ => Anonymous() with { Decision = AuditDecision.Allow },
        };

        Assert.Throws<ArgumentException>(() => aggregator.CarryOver(record));
        Assert.Empty(aggregator.Drain());
    }

    [Fact]
    public async Task Counting_is_safe_from_many_threads_at_once()
    {
        var aggregator = Aggregator(out _);
        const int Threads = 16;
        const int Each = 500;

        await Task.WhenAll(Enumerable.Range(0, Threads).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < Each; i++)
            {
                aggregator.ShouldWriteThrough(Anonymous());
            }
        })));

        // One of the 8000 was written through; every other one is in the count, none lost.
        Assert.Equal((Threads * Each) - 1, Assert.Single(aggregator.Drain()).Count);
    }
}
