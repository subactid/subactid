using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Signals;
using SubactId.Core.Storage;
using SubactId.Server.Audit;
using SubactId.Server.Logout;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Revocation;
using SubactId.UnitTests.Tokens.Exchange;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.NoAggregationHelper;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Logout;

/// <summary>
/// What a valid logout token does. It ends tasks but never blocks the person, because signing out
/// is not being disabled. A token naming a session ends only that session's tasks.
/// </summary>
public class LogoutServiceTests
{
    private const string LogoutAudience = "workbench";
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private sealed class Harness
    {
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public InMemoryAudit Audit { get; } = new();
        public InMemoryRevocations Revocations { get; } = new();
        public InMemorySignalReplays Replays { get; } = new();

        public TrackingUnitOfWork UnitOfWork { get; } = new();

        public LogoutService Build() => new(
            new LogoutTokenValidator(new StaticUpstreamKeys(Snapshot()), LogoutAudience, Clock),
            Replays,
            new InMemoryTaskRevocation(Tasks, Grants),
            Revocations,
            Audit,
            UnitOfWork,
            NoAggregation(Clock),
            new RenewalSummary(new DenialAggregationOptions()),
            Clock);

        public Harness WithTask(string taskId, string sponsor, string? sessionId)
        {
            Tasks.Stored.Add(new DelegationTask(taskId, "jira-triage", sponsor, sponsor, sessionId, null, 1, "https://jira.internal", ["jira:read"], DelegationTaskStatus.Active, Now.AddMinutes(-5), Now.AddMinutes(25), null, null));
            return this;
        }

        public DelegationTask Task(string taskId) => Tasks.Stored.Single(t => t.TaskId == taskId);
    }

    private static Dictionary<string, object?> LogoutClaims(params (string Key, object? Value)[] overrides)
    {
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["aud"] = LogoutAudience,
            ["sub"] = Human,
            ["iat"] = Now.AddSeconds(-5).ToUnixTimeSeconds(),
            ["jti"] = "logout-1",
            ["events"] = new Dictionary<string, object?> { [LogoutTokenValidator.LogoutEvent] = new Dictionary<string, object?>() },
        };
        foreach (var (key, value) in overrides)
        {
            if (value is null && key.StartsWith('-')) claims.Remove(key[1..]);
            else claims[key] = value;
        }

        return claims;
    }

    private static string Token(params (string Key, object? Value)[] overrides) => Mint("RS256", "rsa1", LogoutClaims(overrides));

    [Fact]
    public async Task A_logout_naming_the_person_ends_every_task_of_theirs()
    {
        var harness = new Harness()
            .WithTask("task_1", Human, "session-1")
            .WithTask("task_2", Human, null)
            .WithTask("task_other", "somebody-else", "session-1");

        Assert.Null(await harness.Build().ReceiveAsync(Token()));

        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_2").Status);
        Assert.Equal(LogoutService.LoggedOut, harness.Task("task_1").RevocationReason);

        // Another person's task is untouched, even in a session with the same name.
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_other").Status);

        Assert.Equal(AuditEvents.SponsorSignal, harness.Audit.Events[0].Event);
        Assert.Equal((Human, AuditDecision.Allow, LogoutService.LoggedOut), (harness.Audit.Events[0].Sponsor, harness.Audit.Events[0].Decision, harness.Audit.Events[0].Reason));
        Assert.Equal(["task_1", "task_2"], harness.Audit.Events.Skip(1).Select(e => e.TaskId).Order(StringComparer.Ordinal));

        // The person is named by their sub, and their tokens issued before the logout token are
        // signed out, by the identity provider's clock.
        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((Human, (string?)null, LogoutService.LoggedOut, LogoutService.IdentityProvider), (revocation.Subject, revocation.SponsorKey, revocation.Reason, revocation.RevokedBy));
        Assert.Equal(Now.AddSeconds(-5), revocation.IssuedBefore);
    }

    [Fact]
    public async Task A_logout_naming_a_session_ends_only_that_sessions_tasks()
    {
        // The same person signed in twice. Signing out of one window is not signing out of both.
        var harness = new Harness()
            .WithTask("task_here", Human, "session-1")
            .WithTask("task_elsewhere", Human, "session-2")
            .WithTask("task_sessionless", Human, null);

        Assert.Null(await harness.Build().ReceiveAsync(Token(("sid", "session-1"))));

        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_here").Status);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_elsewhere").Status);

        // A task with no session is never matched by a session logout, so a provider that emits no
        // sid cannot end everything with one logout.
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_sessionless").Status);

        // Recorded as a session, not under the column that means a person.
        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal(("session-1", null), (revocation.SessionId, revocation.SponsorKey));
    }

    [Fact]
    public async Task A_logout_naming_only_a_session_still_names_the_person_whose_tasks_it_ended()
    {
        // The token does not say whose session it was, but the tasks it ended do, and one session has
        // one sponsor, so the record names them.
        var harness = new Harness().WithTask("task_here", Human, "session-1");

        Assert.Null(await harness.Build().ReceiveAsync(Token(("-sub", null), ("sid", "session-1"))));

        Assert.Equal(AuditEvents.SponsorSignal, harness.Audit.Events[0].Event);
        Assert.Equal(Human, harness.Audit.Events[0].Sponsor);
    }

    [Fact]
    public async Task A_session_logout_that_ended_nothing_names_nobody()
    {
        // Nothing about the session is known here but its name, and a name is not a person.
        var harness = new Harness();

        Assert.Null(await harness.Build().ReceiveAsync(Token(("-sub", null), ("sid", "session-9"))));

        var signal = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SponsorSignal, null), (signal.Event, signal.Sponsor));
    }

    [Fact]
    public async Task The_replay_record_commits_with_the_revocation_or_not_at_all()
    {
        // The jti is recorded inside the revocation's transaction. Recorded earlier, a failed commit
        // would leave it burned, and the provider's retry would be refused as a replay.
        var harness = new Harness().WithTask("task_1", Human, null);

        Assert.Null(await harness.Build().ReceiveAsync(Token()));

        Assert.True(harness.Replays.RecordedInsideTransaction, "the replay record was written outside the revocation's transaction");
        Assert.Single(harness.Replays.Stored);
    }

    [Fact]
    public async Task A_logout_never_blocks_the_person()
    {
        // Signing out is not being disabled: the same person may sign in again and start a task.
        var harness = new Harness().WithTask("task_1", Human, null);

        Assert.Null(await harness.Build().ReceiveAsync(Token()));

        Assert.Equal(AuditEvents.SponsorSignal, harness.Audit.Events[0].Event);
        Assert.DoesNotContain(harness.Audit.Events, e => e.Event == AuditEvents.SponsorBlocked);
    }

    [Fact]
    public async Task The_same_token_twice_ends_the_tasks_once_and_is_accepted_both_times()
    {
        // The logout happened the first time. The second is answered as accepted and records nothing.
        var harness = new Harness().WithTask("task_1", Human, null);
        var service = harness.Build();
        var token = Token();

        Assert.Null(await service.ReceiveAsync(token));
        var recorded = harness.Audit.Events.Count;

        Assert.Null(await service.ReceiveAsync(token));

        Assert.Single(harness.Revocations.Stored);
        Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorSignal);
        Assert.Equal(recorded, harness.Audit.Events.Count);
    }

    [Fact]
    public async Task Two_issuers_using_the_same_identifier_are_two_signals()
    {
        var harness = new Harness();
        await harness.Replays.TryRecordAsync("https://idp.somewhere-else.test", "logout-1", Now.AddMinutes(5));

        Assert.Null(await harness.Build().ReceiveAsync(Token()));
    }

    [Fact]
    public async Task A_logout_for_somebody_with_nothing_running_is_accepted_ends_nothing_and_still_signs_them_out()
    {
        var harness = new Harness();

        Assert.Null(await harness.Build().ReceiveAsync(Token()));

        Assert.Equal(AuditEvents.SponsorSignal, Assert.Single(harness.Audit.Events).Event);

        // Nothing was running, but a subject token from before the logout must not start a task.
        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((Human, Now.AddSeconds(-5)), (revocation.Subject, revocation.IssuedBefore));
    }

    [Fact]
    public async Task A_session_logout_with_nothing_running_still_signs_the_session_out()
    {
        var harness = new Harness();

        Assert.Null(await harness.Build().ReceiveAsync(Token(("sid", "session-1"))));

        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal(("session-1", (string?)null, (DateTimeOffset?)null), (revocation.SessionId, revocation.Subject, revocation.IssuedBefore));
    }

    [Fact]
    public async Task A_token_that_does_not_validate_changes_nothing_and_is_recorded_naming_nobody()
    {
        var harness = new Harness().WithTask("task_1", Human, null);

        var rejection = await harness.Build().ReceiveAsync(Mint("RS256", "rsa1", LogoutClaims(), rsa: Rsa2));

        Assert.Equal(LogoutRejection.InvalidSignature, rejection);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);
        Assert.Empty(harness.Revocations.Stored);

        // Nothing in an unverified token is worth writing down, so the record names nobody.
        var denial = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SignalDenied, AuditDecision.Deny), (denial.Event, denial.Decision));
        Assert.Null(denial.Sponsor);
        Assert.Null(denial.TaskId);
        Assert.Equal("logout_invalid_signature", denial.Reason);
    }

    [Fact]
    public async Task A_refused_token_is_not_recorded_as_seen_so_the_real_one_still_works()
    {
        // A replay record for a token that failed validation would let an attacker who guessed a jti
        // block the genuine logout carrying it.
        var harness = new Harness().WithTask("task_1", Human, null);
        var service = harness.Build();

        Assert.Equal(LogoutRejection.InvalidSignature, await service.ReceiveAsync(Mint("RS256", "rsa1", LogoutClaims(), rsa: Rsa2)));
        Assert.Null(await service.ReceiveAsync(Token()));

        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
    }
}

/// <summary>
/// Signal replay protection over a dictionary, with the table's one-winner rule. It also notes
/// whether each record was written while a <see cref="TrackingUnitOfWork"/> was open.
/// </summary>
internal sealed class InMemorySignalReplays : ISignalReplayStore
{
    public Dictionary<(string Issuer, string Jti), DateTimeOffset> Stored { get; } = [];

    public int Purges { get; private set; }

    public bool RecordedInsideTransaction { get; private set; } = true;

    public Task<bool> TryRecordAsync(string issuer, string jti, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        RecordedInsideTransaction &= TrackingUnitOfWork.Open;
        return Task.FromResult(Stored.TryAdd((issuer, jti), expiresAt));
    }

    public Task<int> PurgeExpiredAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        Purges++;
        var stale = Stored.Where(e => e.Value < now).Select(e => e.Key).ToList();
        foreach (var key in stale)
        {
            Stored.Remove(key);
        }

        return Task.FromResult(stale.Count);
    }
}

/// <summary>
/// No transaction, but it tracks when work is running inside it, so a fake store can tell whether
/// it was written to inside the unit of work.
/// </summary>
internal sealed class TrackingUnitOfWork : IUnitOfWork
{
    // Flows into the awaited work and everything it calls, so a store called from inside the unit
    // of work sees it open and one called outside does not.
    private static readonly AsyncLocal<bool> open = new();

    public static bool Open => open.Value;

    public async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> work, CancellationToken cancellationToken = default)
    {
        open.Value = true;
        return await work(cancellationToken);
    }
}
