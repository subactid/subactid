using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Core.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Audit;

public class AuditOutboxDrainTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 11, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(5, 16)]
    [InlineData(9, 256)]
    [InlineData(10, 300)]
    [InlineData(40, 300)]
    [InlineData(int.MaxValue, 300)]
    public void Backoff_doubles_from_one_second_and_caps_at_five_minutes(int attempts, int seconds) =>
        Assert.Equal(TimeSpan.FromSeconds(seconds), AuditOutboxDrain.Backoff(attempts));

    [Fact]
    public void Backoff_rejects_zero_attempts() => Assert.Throws<ArgumentOutOfRangeException>(() => AuditOutboxDrain.Backoff(0));

    [Fact]
    public async Task A_pass_delivers_every_due_entry_in_batches_and_in_sequence_order()
    {
        var (drain, outbox, sink) = Build(queued: 25, batchSize: 10);

        var delivered = await drain.DrainAsync();

        Assert.Equal(25, delivered);
        Assert.Equal([10, 10, 5], sink.Deliveries.Select(d => d.Count));
        Assert.Equal(Enumerable.Range(1, 25).Select(i => (long)i), sink.Deliveries.SelectMany(d => d).Select(r => r.Seq));

        // What was delivered is removed from the queue.
        Assert.Empty(outbox.Entries);
    }

    [Fact]
    public async Task A_pass_with_nothing_due_touches_neither_the_sink_nor_the_store()
    {
        var (drain, outbox, sink) = Build(queued: 3, batchSize: 10);
        foreach (var entry in outbox.Entries)
        {
            entry.NextAttemptAt = Now.AddSeconds(1);
        }

        Assert.Equal(0, await drain.DrainAsync());
        Assert.Empty(sink.Deliveries);
        Assert.Equal(3, outbox.Entries.Count);
        Assert.All(outbox.Entries, e => Assert.Equal(0, e.Attempts));
    }

    [Fact]
    public async Task A_failed_delivery_records_the_attempt_pushes_the_batch_back_and_ends_the_pass()
    {
        var (drain, outbox, sink) = Build(queued: 25, batchSize: 10);
        sink.Failure = new AuditSinkException("The audit sink answered 503.");

        var delivered = await drain.DrainAsync();

        Assert.Equal(0, delivered);
        Assert.Single(sink.Deliveries);
        Assert.Equal(25, outbox.Entries.Count);
        var tried = outbox.Entries.Take(10).ToList();
        Assert.All(tried, e => Assert.Equal((1, "AuditSinkException: The audit sink answered 503.", Now.AddSeconds(1)), (e.Attempts, e.LastError, e.NextAttemptAt)));
        Assert.All(outbox.Entries.Skip(10), e => Assert.Equal((0, null, Now), (e.Attempts, e.LastError, e.NextAttemptAt)));
    }

    [Fact]
    public async Task Each_entry_waits_by_its_own_failures_not_the_batch_it_happened_to_share()
    {
        var (drain, outbox, sink) = Build(queued: 3, batchSize: 10);
        outbox.Entries[0].Attempts = 6;
        outbox.Entries[1].Attempts = 3;
        outbox.Entries[2].Attempts = 6;
        sink.Failure = new HttpRequestException("Connection refused");

        await drain.DrainAsync();

        Assert.Equal([Now + AuditOutboxDrain.Backoff(7), Now + AuditOutboxDrain.Backoff(4), Now + AuditOutboxDrain.Backoff(7)], outbox.Entries.Select(e => e.NextAttemptAt));
        Assert.Equal([7, 4, 7], outbox.Entries.Select(e => e.Attempts));
        Assert.All(outbox.Entries, e => Assert.Equal("HttpRequestException: Connection refused", e.LastError));
        Assert.Equal(2, outbox.FailureMarks);
    }

    [Fact]
    public async Task The_wait_is_measured_from_when_the_sink_answered_not_from_the_claim()
    {
        var (drain, outbox, sink) = Build(queued: 2, batchSize: 1);
        sink.OnDeliver = () => outbox.Clock.Advance(TimeSpan.FromSeconds(10));
        sink.Failure = new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout of 10 seconds elapsing.");

        await drain.DrainAsync();
        Assert.Equal(Now.AddSeconds(11), outbox.Entries[0].NextAttemptAt);
        Assert.Equal("TaskCanceledException: The request was canceled due to the configured HttpClient.Timeout of 10 seconds elapsing.", outbox.Entries[0].LastError);

        sink.Failure = null;
        await drain.DrainAsync();
        Assert.Empty(outbox.Entries);
    }

    [Fact]
    public async Task Entries_are_delivered_once_the_sink_recovers()
    {
        var (drain, outbox, sink) = Build(queued: 4, batchSize: 10);
        sink.Failure = new AuditSinkException("The audit sink answered 500.");
        await drain.DrainAsync();
        sink.Failure = null;

        // Not yet due: the backoff holds.
        Assert.Equal(0, await drain.DrainAsync());
        Assert.Single(sink.Deliveries);

        outbox.Clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(4, await drain.DrainAsync());
        Assert.Equal(2, sink.Deliveries.Count);
        Assert.Empty(outbox.Entries);
    }

    [Fact]
    public async Task A_queued_entry_whose_record_cannot_be_read_is_a_failed_delivery_not_a_silent_skip()
    {
        var (drain, outbox, sink) = Build(queued: 3, batchSize: 10);
        outbox.Ledger.Records.RemoveAt(1);

        Assert.Equal(0, await drain.DrainAsync());
        Assert.Empty(sink.Deliveries);
        Assert.All(outbox.Entries, e => Assert.Equal((1, "AuditSinkException: A queued ledger record could not be read."), (e.Attempts, e.LastError)));
    }

    [Fact]
    public async Task Cancellation_during_delivery_surfaces_and_records_nothing()
    {
        var (drain, outbox, sink) = Build(queued: 3, batchSize: 10);
        using var cancellation = new CancellationTokenSource();
        sink.OnDeliver = () => cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => drain.DrainAsync(cancellation.Token));
        Assert.Equal(3, outbox.Entries.Count);
        Assert.All(outbox.Entries, e => Assert.Equal((0, (string?)null), (e.Attempts, e.LastError)));
    }

    private static (AuditOutboxDrain Drain, InMemoryOutbox Outbox, RecordingSink Sink) Build(int queued, int batchSize)
    {
        var clock = new FakeTimeProvider(Now);
        var outbox = new InMemoryOutbox(clock, queued);
        var sink = new RecordingSink();
        var services = new ServiceCollection();
        services.AddSingleton<IAuditOutboxQueue>(outbox);
        services.AddSingleton<IAuditLedgerReader>(outbox.Ledger);
        services.AddSingleton<IAuditCheckpointQuery>(new NothingSealedYet());
        services.AddSingleton<IAuditSink>(sink);
        services.AddSingleton<IUnitOfWork>(new PassThroughUnitOfWork());
        var options = new AuditOptions { SinkUrl = new Uri("https://sink.example.test/audit"), DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = batchSize, CheckpointInterval = AuditOptions.DefaultCheckpointInterval };
        var provider = services.BuildServiceProvider();
        return (new AuditOutboxDrain(provider.GetRequiredService<IServiceScopeFactory>(), options, clock, NullLogger<AuditOutboxDrain>.Instance), outbox, sink);
    }

    /// <summary>The outbox and the ledger it points at, in memory, with the same rules as the store: a claim takes what is due, oldest first, and a delivered entry is gone.</summary>
    private sealed class InMemoryOutbox(FakeTimeProvider clock, int queued) : IAuditOutboxQueue
    {
        public FakeTimeProvider Clock { get; } = clock;

        public InMemoryLedger Ledger { get; } = new(queued);

        public List<Entry> Entries { get; } = Enumerable.Range(1, queued).Select(i => new Entry { Id = i, AuditSeq = i, NextAttemptAt = Now }).ToList();

        public int FailureMarks { get; private set; }

        public Task<IReadOnlyList<AuditOutboxEntry>> ClaimDueAsync(DateTimeOffset now, int batchSize, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditOutboxEntry>>(Entries.Where(e => e.NextAttemptAt <= now).OrderBy(e => e.Id).Take(batchSize).Select(e => new AuditOutboxEntry(e.Id, e.AuditSeq, e.Attempts)).ToList());

        public Task RemoveDeliveredAsync(IReadOnlyList<long> ids, CancellationToken cancellationToken = default)
        {
            Entries.RemoveAll(e => ids.Contains(e.Id));
            return Task.CompletedTask;
        }

        public Task MarkFailedAsync(IReadOnlyList<long> ids, DateTimeOffset now, string error, DateTimeOffset nextAttemptAt, CancellationToken cancellationToken = default)
        {
            FailureMarks++;
            foreach (var entry in Entries.Where(e => ids.Contains(e.Id)))
            {
                entry.Attempts++;
                entry.LastError = error;
                entry.NextAttemptAt = nextAttemptAt;
            }

            return Task.CompletedTask;
        }

        public sealed class Entry
        {
            public long Id { get; init; }

            public long AuditSeq { get; init; }

            public int Attempts { get; set; }

            public string? LastError { get; set; }

            public DateTimeOffset NextAttemptAt { get; set; }
        }
    }

    private sealed class InMemoryLedger(int count) : IAuditLedgerReader
    {
        public List<AuditLedgerRecord> Records { get; } = Enumerable.Range(1, count)
            .Select(i => new AuditLedgerRecord(i, new AuditEvent(Now.AddSeconds(-count + i), AuditEvents.TokenIssued, $"task_{i}", "jira-triage", "human", Decision: AuditDecision.Allow)))
            .ToList();

        public Task<IReadOnlyList<AuditLedgerRecord>> ReadAsync(long afterSeq, int limit, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<IReadOnlyList<AuditLedgerRecord>> ReadBySeqAsync(IReadOnlyList<long> seqs, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLedgerRecord>>(Records.Where(r => seqs.Contains(r.Seq)).OrderBy(r => r.Seq).ToList());

        public Task<IReadOnlyList<AuditLedgerRecord>> ReadRangeAsync(long afterSeq, long throughSeq, int limit, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLedgerRecord>>(Records.Where(r => r.Seq > afterSeq && r.Seq <= throughSeq).OrderBy(r => r.Seq).Take(limit).ToList());
    }

    /// <summary>A ledger the sealing pass has not reached yet, as with a freshly queued record.</summary>
    private sealed class NothingSealedYet : IAuditCheckpointQuery
    {
        public Task<IReadOnlyList<AuditCheckpoint>> ReadAsync(long afterId, int limit, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditCheckpoint>>([]);

        public Task<AuditCheckpoint?> SealingAsync(long seq, CancellationToken cancellationToken = default) => Task.FromResult<AuditCheckpoint?>(null);

        public Task<IReadOnlyDictionary<long, long>> SealingAsync(IReadOnlyList<long> seqs, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyDictionary<long, long>>(new Dictionary<long, long>());
    }

    private sealed class RecordingSink : IAuditSink
    {
        public List<IReadOnlyList<AuditLedgerRecord>> Deliveries { get; } = [];

        public Exception? Failure { get; set; }

        public Action? OnDeliver { get; set; }

        public Task DeliverAsync(IReadOnlyList<AuditLedgerRecord> records, IReadOnlyDictionary<long, long> sealing, CancellationToken cancellationToken = default)
        {
            Deliveries.Add(records);
            OnDeliver?.Invoke();
            cancellationToken.ThrowIfCancellationRequested();
            return Failure is null ? Task.CompletedTask : Task.FromException(Failure);
        }
    }
}
