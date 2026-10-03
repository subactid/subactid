using Microsoft.Extensions.Time.Testing;
using SubactId.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Tokens.Upstream;

/// <summary>
/// The circuit in front of the sponsor check. On its own it only ever answers
/// <see cref="SponsorStatus.Unavailable"/>. The rest is how quickly it stops waiting on a provider
/// that is gone and notices one that is back.
/// </summary>
public class SponsorStatusCircuitTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    private static readonly DateTimeOffset Now = new(2026, 9, 23, 9, 0, 0, TimeSpan.Zero);

    private sealed class Scripted : ISponsorStatusProbe
    {
        public SponsorStatus Answer { get; set; } = SponsorStatus.Active;

        /// <summary>Whether an Unavailable answer is the provider failing; by default it is.</summary>
        public bool ProviderFailed { get; set; } = true;

        public int Calls { get; private set; }

        public TaskCompletionSource<SponsorStatus>? Hold { get; set; }

        public async Task<SponsorStatus> GetAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default) =>
            (await LookUpAsync(subject, maxAge, cancellationToken)).Status;

        public async Task<SponsorLookup> LookUpAsync(string subject, TimeSpan maxAge, CancellationToken cancellationToken = default)
        {
            Calls++;
            var status = Hold is { } hold ? await hold.Task.WaitAsync(cancellationToken) : Answer;
            return new SponsorLookup(status, status == SponsorStatus.Unavailable && ProviderFailed);
        }
    }

    private static async Task FailAsync(SponsorStatusCircuit circuit, int times)
    {
        for (var i = 0; i < times; i++)
        {
            Assert.Equal(SponsorStatus.Unavailable, await circuit.GetAsync(Human, TimeSpan.Zero));
        }
    }

    [Fact]
    public async Task Answers_pass_through_unchanged_while_the_provider_answers()
    {
        var inner = new Scripted();
        var circuit = new SponsorStatusCircuit(inner, new FakeTimeProvider(Now));

        foreach (var answer in new[] { SponsorStatus.Active, SponsorStatus.Disabled, SponsorStatus.NotFound, SponsorStatus.Active })
        {
            inner.Answer = answer;
            Assert.Equal(answer, await circuit.GetAsync(Human, TimeSpan.Zero));
        }

        Assert.Equal(4, inner.Calls);
        Assert.False(circuit.IsOpen);
    }

    [Fact]
    public async Task Fewer_failures_than_the_threshold_keep_asking()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var circuit = new SponsorStatusCircuit(inner, new FakeTimeProvider(Now));

        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen - 1);

        Assert.False(circuit.IsOpen);
        Assert.Equal(SponsorStatusCircuit.FailuresToOpen - 1, inner.Calls);
    }

    [Fact]
    public async Task A_success_in_between_resets_the_count()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var circuit = new SponsorStatusCircuit(inner, new FakeTimeProvider(Now));

        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen - 1);
        inner.Answer = SponsorStatus.Active;
        await circuit.GetAsync(Human, TimeSpan.Zero);
        inner.Answer = SponsorStatus.Unavailable;
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen - 1);

        Assert.False(circuit.IsOpen);
    }

    [Fact]
    public async Task Once_open_it_refuses_without_asking()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var circuit = new SponsorStatusCircuit(inner, new FakeTimeProvider(Now));
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen);
        var asked = inner.Calls;

        // The provider is back, but the circuit has not looked yet: still a refusal, never a yes.
        inner.Answer = SponsorStatus.Active;
        Assert.Equal(SponsorStatus.Unavailable, await circuit.GetAsync(Human, TimeSpan.Zero));

        Assert.True(circuit.IsOpen);
        Assert.Equal(asked, inner.Calls);
    }

    [Fact]
    public async Task After_the_open_period_one_question_closes_it_again()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var clock = new FakeTimeProvider(Now);
        var circuit = new SponsorStatusCircuit(inner, clock);
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen);

        clock.Advance(SponsorStatusCircuit.OpenFor);
        inner.Answer = SponsorStatus.Disabled;

        Assert.Equal(SponsorStatus.Disabled, await circuit.GetAsync(Human, TimeSpan.Zero));
        Assert.False(circuit.IsOpen);
    }

    [Fact]
    public async Task A_failed_probe_opens_it_again_straight_away()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var clock = new FakeTimeProvider(Now);
        var circuit = new SponsorStatusCircuit(inner, clock);
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen);

        clock.Advance(SponsorStatusCircuit.OpenFor);
        await FailAsync(circuit, 1);
        var asked = inner.Calls;

        inner.Answer = SponsorStatus.Active;
        Assert.Equal(SponsorStatus.Unavailable, await circuit.GetAsync(Human, TimeSpan.Zero));
        Assert.Equal(asked, inner.Calls);
    }

    [Fact]
    public async Task Only_one_question_is_let_through_while_probing()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var clock = new FakeTimeProvider(Now);
        var circuit = new SponsorStatusCircuit(inner, clock);
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen);
        clock.Advance(SponsorStatusCircuit.OpenFor);

        inner.Hold = new TaskCompletionSource<SponsorStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        var probe = circuit.GetAsync(Human, TimeSpan.Zero);
        var asked = inner.Calls;

        Assert.Equal(SponsorStatus.Unavailable, await circuit.GetAsync(Human, TimeSpan.Zero));
        Assert.Equal(asked, inner.Calls);

        inner.Hold.SetResult(SponsorStatus.Active);
        Assert.Equal(SponsorStatus.Active, await probe);
        Assert.False(circuit.IsOpen);
    }

    [Fact]
    public async Task One_person_the_provider_will_not_describe_never_opens_it()
    {
        // A 403 for one account, or an unusable record, is a refusal for that person only. It must not
        // open the circuit for everybody.
        var inner = new Scripted { Answer = SponsorStatus.Unavailable, ProviderFailed = false };
        var circuit = new SponsorStatusCircuit(inner, new FakeTimeProvider(Now));

        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen * 3);

        Assert.False(circuit.IsOpen);
        Assert.Equal(SponsorStatusCircuit.FailuresToOpen * 3, inner.Calls);
    }

    [Fact]
    public async Task An_unusable_answer_between_provider_failures_resets_the_count()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var circuit = new SponsorStatusCircuit(inner, new FakeTimeProvider(Now));

        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen - 1);
        inner.ProviderFailed = false;
        await FailAsync(circuit, 1);
        inner.ProviderFailed = true;
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen - 1);

        Assert.False(circuit.IsOpen);
    }

    [Fact]
    public async Task A_probe_the_provider_answered_closes_it_even_when_the_answer_was_unusable()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var clock = new FakeTimeProvider(Now);
        var circuit = new SponsorStatusCircuit(inner, clock);
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen);
        clock.Advance(SponsorStatusCircuit.OpenFor);

        inner.ProviderFailed = false;
        Assert.Equal(SponsorStatus.Unavailable, await circuit.GetAsync(Human, TimeSpan.Zero));

        Assert.False(circuit.IsOpen);
    }

    /// <summary>A clock whose wall time and monotonic time are set separately, as a stepped system clock leaves them.</summary>
    private sealed class SteppedClock : TimeProvider
    {
        public DateTimeOffset Wall { get; set; } = Now;

        public long Ticks { get; set; }

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow() => Wall;

        public override long GetTimestamp() => Ticks;
    }

    [Fact]
    public async Task A_wall_clock_stepped_back_does_not_hold_it_open()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var clock = new SteppedClock();
        var circuit = new SponsorStatusCircuit(inner, clock);
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen);

        // The open period has passed, and meanwhile the wall clock was stepped back an hour.
        clock.Ticks += SponsorStatusCircuit.OpenFor.Ticks;
        clock.Wall = Now - TimeSpan.FromHours(1);
        inner.Answer = SponsorStatus.Active;

        Assert.Equal(SponsorStatus.Active, await circuit.GetAsync(Human, TimeSpan.Zero));
    }

    [Fact]
    public async Task A_probe_the_caller_abandoned_lets_the_next_caller_probe()
    {
        var inner = new Scripted { Answer = SponsorStatus.Unavailable };
        var clock = new FakeTimeProvider(Now);
        var circuit = new SponsorStatusCircuit(inner, clock);
        await FailAsync(circuit, SponsorStatusCircuit.FailuresToOpen);
        clock.Advance(SponsorStatusCircuit.OpenFor);

        inner.Hold = new TaskCompletionSource<SponsorStatus>();
        using var cancel = new CancellationTokenSource();
        var probe = circuit.GetAsync(Human, TimeSpan.Zero, cancel.Token);
        await cancel.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);

        inner.Hold = null;
        inner.Answer = SponsorStatus.Active;
        Assert.Equal(SponsorStatus.Active, await circuit.GetAsync(Human, TimeSpan.Zero));
    }
}
