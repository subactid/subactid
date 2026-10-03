using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Storage;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

public abstract class AuditQueryTests(IStorageFixture storage) : IAsyncLifetime
{
    protected static readonly DateTimeOffset September = new(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    public Task InitializeAsync() => storage.EnsureMigratedAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task The_checkpoint_batch_lookup_runs_on_this_provider_and_finds_nothing_unsealed()
    {
        // The lookup filters on a list of sequence numbers inside the query; each provider must
        // translate that. Numbers past the end of the ledger are sealed by no checkpoint.
        await using var db = storage.CreateDbContext();

        var page = await new EfAuditCheckpointQuery(db).SealingAsync([long.MaxValue - 1, long.MaxValue - 5, long.MaxValue - 1]);

        Assert.Empty(page);
    }

    [Fact]
    public async Task Every_action_taken_on_behalf_of_a_person_last_month_comes_back_in_order_and_nothing_else()
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
        var human = UniqueId("human");
        var other = UniqueId("other");

        await writer.AppendAsync(
        [
            new AuditEvent(September.AddDays(-1), AuditEvents.TokenIssued, "task_aug", "jira-triage", human, Decision: AuditDecision.Allow),
            new AuditEvent(September.AddDays(3), AuditEvents.TokenIssued, "task_1", "jira-triage", human, Decision: AuditDecision.Allow),
            new AuditEvent(September.AddDays(3), AuditEvents.TokenIssued, "task_1", "jira-triage", other, Decision: AuditDecision.Allow),
            new AuditEvent(September.AddDays(10), AuditEvents.TokenDenied, null, "db-agent", human, Decision: AuditDecision.Deny, Reason: "audience_not_allowed"),
            new AuditEvent(September.AddDays(20), AuditEvents.TokenRefreshed, "task_1", "jira-triage", human, Decision: AuditDecision.Allow),
            new AuditEvent(September.AddDays(29).AddHours(23).AddMinutes(59), AuditEvents.TaskExpired, "task_1", "jira-triage", human),
            new AuditEvent(September.AddMonths(1), AuditEvents.TokenIssued, "task_oct", "jira-triage", human, Decision: AuditDecision.Allow),
        ]);
        var query = new EfAuditQuery(db, storage.Dialect);

        var month = await query.QueryAsync(new AuditQuery(Sponsor: human, From: September, To: September.AddMonths(1)));

        Assert.Equal([AuditEvents.TokenIssued, AuditEvents.TokenDenied, AuditEvents.TokenRefreshed, AuditEvents.TaskExpired], month.Select(r => r.Event.Event));
        Assert.All(month, r => Assert.Equal(human, r.Event.Sponsor));
        Assert.Equal(month.Select(r => r.Seq).Order(), month.Select(r => r.Seq));

        var denied = await query.QueryAsync(new AuditQuery(Sponsor: human, Decision: AuditDecision.Deny));
        Assert.Equal([AuditEvents.TokenDenied], denied.Select(r => r.Event.Event));

        var byAgent = await query.QueryAsync(new AuditQuery(AgentId: "db-agent", Sponsor: human));
        Assert.Equal([AuditEvents.TokenDenied], byAgent.Select(r => r.Event.Event));

        var byTask = await query.QueryAsync(new AuditQuery(TaskId: "task_1", Sponsor: human, From: September.AddDays(4)));
        Assert.Equal([AuditEvents.TokenRefreshed, AuditEvents.TaskExpired], byTask.Select(r => r.Event.Event));

        var all = await query.QueryAsync(new AuditQuery(Sponsor: human));
        Assert.Equal(6, all.Count);
    }

    [Fact]
    public async Task Pages_follow_the_cursor_through_records_that_share_a_timestamp_without_a_gap_or_a_repeat()
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
        var human = UniqueId("paged");

        // Eleven records over three timestamps: ties on every page boundary.
        await writer.AppendAsync(Enumerable.Range(0, 11).Select(i => new AuditEvent(September.AddMinutes(i / 4), AuditEvents.TokenIssued, $"task_{i}", "jira-triage", human, Decision: AuditDecision.Allow)).ToList());
        var query = new EfAuditQuery(db, storage.Dialect);

        var collected = new List<AuditLedgerRecord>();
        AuditCursor? after = null;
        for (var page = 0; page < 10; page++)
        {
            var records = await query.QueryAsync(new AuditQuery(Sponsor: human, After: after, Limit: 3));
            if (records.Count == 0)
            {
                break;
            }

            collected.AddRange(records);
            after = new AuditCursor(records[^1].Event.Ts, records[^1].Seq);
        }

        Assert.Equal(Enumerable.Range(0, 11).Select(i => $"task_{i}"), collected.Select(r => r.Event.TaskId));
        Assert.Equal(collected.Select(r => r.Seq).Order(), collected.Select(r => r.Seq));
    }


}

/// <summary>The same tests against Postgres, plus the plan its planner produces.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresAuditQueryTests(PostgresDatabaseFixture storage) : AuditQueryTests(storage)
{
    [Fact]
    public async Task The_month_query_for_one_sponsor_is_served_from_the_sponsor_fingerprint_index_never_a_scan_of_the_ledger()
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
        var human = UniqueId("indexed");

        // Many records in the range, few for this person: the case the index is for. The planner may
        // top-N sort the matches, but must not scan the ledger.
        for (var batch = 0; batch < 10; batch++)
        {
            await writer.AppendAsync(Enumerable.Range(0, 600).Select(i => new AuditEvent(September.AddMinutes((batch * 600 + i) * 7), AuditEvents.TokenIssued, $"task_{i}", "jira-triage", i % 100 == 0 ? human : UniqueId("crowd"), Decision: AuditDecision.Allow)).ToList());
        }

        // Denials across the same span, a few percent of it, so the partial index is not empty.
        await writer.AppendAsync(Enumerable.Range(0, 300).Select(i => new AuditEvent(September.AddMinutes(i * 140), AuditEvents.TokenDenied, null, "db-agent", UniqueId("crowd"), Decision: AuditDecision.Deny, Reason: "audience_not_allowed")).ToList());

        await db.Database.ExecuteSqlRawAsync("ANALYZE audit_events");

        var plan = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(Sponsor: human, From: September, To: September.AddMonths(1), Limit: 101)));

        Assert.True(plan.Contains("ix_audit_events_sponsor_fingerprint_ts_seq", StringComparison.Ordinal), plan);
        Assert.DoesNotContain("Seq Scan", plan, StringComparison.Ordinal);

        var afterFirstPage = new AuditCursor(September.AddDays(4), 0);
        var paged = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(Sponsor: human, From: September, To: September.AddMonths(1), After: afterFirstPage, Limit: 101)));
        Assert.True(paged.Contains("ix_audit_events_sponsor_fingerprint_ts_seq", StringComparison.Ordinal), paged);
        Assert.DoesNotContain("Seq Scan", paged, StringComparison.Ordinal);

        // The agent filter uses the other fingerprinted index.
        var byAgent = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(AgentId: "db-agent", From: September, To: September.AddMonths(1), Limit: 101)));
        Assert.True(byAgent.Contains("ix_audit_events_agent_id_fingerprint_ts_seq", StringComparison.Ordinal), byAgent);
        Assert.DoesNotContain("Seq Scan", byAgent, StringComparison.Ordinal);

        // Filtering by decision must use its own partial index, not (ts, seq).
        var denials = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(From: September.AddDays(10), To: September.AddDays(11), Decision: AuditDecision.Deny, Limit: 101)));
        Assert.True(denials.Contains("ix_audit_events_deny_ts_seq", StringComparison.Ordinal), denials);
        Assert.DoesNotContain("Seq Scan", denials, StringComparison.Ordinal);

        // With neither a sponsor, an agent nor a decision, the time index carries the page.
        var byTime = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(From: September.AddDays(10), To: September.AddDays(11), Limit: 101)));
        Assert.True(byTime.Contains("ix_audit_events_ts_seq", StringComparison.Ordinal), byTime);
        Assert.DoesNotContain("Seq Scan", byTime, StringComparison.Ordinal);
    }

    /// <summary>
    /// Strings with equal fingerprints share index entries, so the query also compares the column.
    /// A collision costs a row read, never another person's record in the answer.
    /// </summary>
    [Fact]
    public async Task A_sponsor_sharing_a_fingerprint_with_the_one_asked_about_stays_out_of_the_answer()
    {
        var (asked, shares) = await TwoSponsorsSharingAFingerprintAsync();
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);

        await writer.AppendAsync(
        [
            new AuditEvent(September.AddDays(12), AuditEvents.TokenIssued, "task_asked", "jira-triage", asked, Decision: AuditDecision.Allow),
            new AuditEvent(September.AddDays(12), AuditEvents.TokenIssued, "task_shares", "jira-triage", shares, Decision: AuditDecision.Allow),
        ]);

        var answer = await new EfAuditQuery(db, storage.Dialect).QueryAsync(new AuditQuery(Sponsor: asked, From: September, To: September.AddMonths(1), Limit: 100));

        Assert.Equal(["task_asked"], answer.Select(r => r.Event.TaskId));
        Assert.All(answer, record => Assert.Equal(asked, record.Event.Sponsor));
    }

    /// <summary>
    /// Two strings the database says share a fingerprint. Asked of the database, because the
    /// collision that matters is the one its own md5 function makes.
    /// </summary>
    private async Task<(string Asked, string Shares)> TwoSponsorsSharingAFingerprintAsync()
    {
        await using var connection = await storage.OpenApplicationConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (array_agg(v ORDER BY v))[1], (array_agg(v ORDER BY v))[2]
            FROM (SELECT 'collision-' || g AS v FROM generate_series(1, 300000) g) s
            GROUP BY audit_events_fingerprint(v)
            HAVING count(*) > 1
            ORDER BY min(v)
            LIMIT 1
            """;

        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), "No two of the candidate strings shared a fingerprint, so this test would prove nothing.");
        return (reader.GetString(0), reader.GetString(1));
    }

    /// <summary>The planner's JSON for the query, run with the same parameters the query would send.</summary>

    private static async Task<string> ExplainAsync(SubactId.Storage.Ef.SubactIdDbContext db, IQueryable<SubactId.Storage.Ef.Schema.AuditEventRow> query)
    {
        await using var command = query.CreateDbCommand();
        var sql = command.CommandText;
        command.CommandText = "EXPLAIN (FORMAT JSON) " + sql;
        await db.Database.OpenConnectionAsync();
        try
        {
            var plan = (string?)await command.ExecuteScalarAsync();
            Assert.NotNull(plan);
            using var document = JsonDocument.Parse(plan);
            return sql + Environment.NewLine + document.RootElement.GetRawText();
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }
}

/// <summary>The same tests against the embedded database, plus the plan its planner produces.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteAuditQueryTests(SqliteDatabaseFixture storage) : AuditQueryTests(storage)
{
    [Fact]
    public async Task The_month_query_for_one_sponsor_searches_the_sponsor_time_index_never_scans_the_ledger()
    {
        await using var db = storage.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, storage.Dialect), storage.Dialect);
        var human = UniqueId("indexed");
        for (var batch = 0; batch < 4; batch++)
        {
            await writer.AppendAsync(Enumerable.Range(0, 250).Select(i => new AuditEvent(September.AddMinutes(((batch * 250) + i) * 7), AuditEvents.TokenIssued, $"task_{i}", "jira-triage", i % 100 == 0 ? human : UniqueId("crowd"), Decision: AuditDecision.Allow)).ToList());
        }

        // Denials across the same span, so the partial index is chosen over a populated one.
        await writer.AppendAsync(Enumerable.Range(0, 120).Select(i => new AuditEvent(September.AddMinutes(i * 145), AuditEvents.TokenDenied, null, "db-agent", UniqueId("crowd"), Decision: AuditDecision.Deny, Reason: "audience_not_allowed")).ToList());

        await db.Database.ExecuteSqlRawAsync("ANALYZE");

        var plan = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(Sponsor: human, From: September, To: September.AddMonths(1), Limit: 101)));
        Assert.Contains("ix_audit_events_sponsor_ts_seq", plan, StringComparison.Ordinal);
        Assert.DoesNotContain("SCAN audit_events", plan, StringComparison.Ordinal);

        var denials = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(From: September.AddDays(10), To: September.AddDays(11), Decision: AuditDecision.Deny, Limit: 101)));
        Assert.Contains("ix_audit_events_deny_ts_seq", denials, StringComparison.Ordinal);
        Assert.DoesNotContain("SCAN audit_events", denials, StringComparison.Ordinal);

        var byTime = await ExplainAsync(db, new EfAuditQuery(db, storage.Dialect).Build(new AuditQuery(From: September.AddDays(10), To: September.AddDays(11), Limit: 101)));
        Assert.Contains("ix_audit_events_ts_seq", byTime, StringComparison.Ordinal);
        Assert.DoesNotContain("SCAN audit_events", byTime, StringComparison.Ordinal);
    }

    /// <summary>The query plan as SQLite explains it, one line per step.</summary>
    private static async Task<string> ExplainAsync(SubactId.Storage.Ef.SubactIdDbContext db, IQueryable<SubactId.Storage.Ef.Schema.AuditEventRow> query)
    {
        await using var command = query.CreateDbCommand();
        var sql = command.CommandText;
        command.CommandText = "EXPLAIN QUERY PLAN " + sql;
        await db.Database.OpenConnectionAsync();
        try
        {
            await using var reader = await command.ExecuteReaderAsync();
            var steps = new List<string>();
            while (await reader.ReadAsync())
            {
                steps.Add(reader.GetString(reader.GetOrdinal("detail")));
            }

            return sql + Environment.NewLine + string.Join(Environment.NewLine, steps);
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }
}
