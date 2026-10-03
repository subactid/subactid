using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Sponsors;
using SubactId.Server.Admin;
using SubactId.Server.Audit;
using SubactId.Server.Signals;
using SubactId.Tokens.Upstream;
using SubactId.UnitTests.Logout;
using SubactId.UnitTests.Revocation;
using SubactId.UnitTests.Tokens.Exchange;
using SubactId.UnitTests.Tokens.Upstream;
using Xunit;
using static SubactId.UnitTests.NoAggregationHelper;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Signals;

/// <summary>
/// What a security event does to a person. Sessions ending ends the tasks and lets the person
/// start again. An account closing also refuses them until something says otherwise.
/// </summary>
public class SecurityEventServiceTests
{
    private const string StreamAudience = "https://subactid.internal.example.com/events";
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private sealed class Harness
    {
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public InMemoryAudit Audit { get; } = new();
        public InMemoryRevocations Revocations { get; } = new();
        public InMemorySponsorBlocks Blocks { get; } = new();
        public InMemorySignalReplays Replays { get; } = new();
        public TrackingUnitOfWork UnitOfWork { get; } = new();

        public SecurityEventService Build() => new(
            new SecurityEventTokenValidator(new StaticUpstreamKeys(Snapshot()), StreamAudience, Issuer, Clock),
            Replays,
            new SponsorSignalWriter(Blocks, new InMemoryTaskRevocation(Tasks, Grants), Revocations, Audit, new RenewalSummary(new DenialAggregationOptions())),
            Audit,
            UnitOfWork,
            NoAggregation(Clock),
            Clock);

        public Harness WithTask(string taskId, string sponsorKey)
        {
            Tasks.Stored.Add(new DelegationTask(taskId, "jira-triage", Human, sponsorKey, null, null, 1, "https://jira.internal", ["jira:read"], DelegationTaskStatus.Active, Now.AddMinutes(-5), Now.AddMinutes(25), null, null));
            return this;
        }

        public Harness WithBlock(string sponsorKey, SponsorBlockSource source, SponsorBlockKind kind = SponsorBlockKind.Disabled)
        {
            Blocks.Stored[sponsorKey] = new SponsorBlock(sponsorKey, source, kind, Now.AddDays(-1));
            return this;
        }

        public DelegationTask Task(string taskId) => Tasks.Stored.Single(t => t.TaskId == taskId);
    }

    private static Dictionary<string, object?> Subject(string sub) => new()
    {
        ["format"] = "iss_sub",
        ["iss"] = Issuer,
        ["sub"] = sub,
    };

    private static string Token(string eventType, string subject = Human, string jti = "event-1", DateTimeOffset? issuedAt = null) => Mint("RS256", "rsa1", new Dictionary<string, object?>
    {
        ["iss"] = Issuer,
        ["aud"] = StreamAudience,
        ["iat"] = (issuedAt ?? Now.AddSeconds(-5)).ToUnixTimeSeconds(),
        ["jti"] = jti,
        ["events"] = new Dictionary<string, object?> { [eventType] = new Dictionary<string, object?> { ["subject"] = Subject(subject) } },
    });

    [Fact]
    public async Task Sessions_being_revoked_ends_the_tasks_and_leaves_the_person_free_to_start_again()
    {
        var harness = new Harness().WithTask("task_1", Human).WithTask("task_other", "somebody-else");

        Assert.Null(await harness.Build().ReceiveAsync(Token(SecurityEventTokenValidator.SessionRevoked)));

        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(SecurityEventService.SessionsRevoked, harness.Task("task_1").RevocationReason);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_other").Status);

        // Ending sessions is not disabling somebody, so nothing refuses them afterwards.
        Assert.Empty(harness.Blocks.Stored);

        var signal = harness.Audit.Events[0];
        Assert.Equal((AuditEvents.SponsorSignal, Human, AuditDecision.Allow, SecurityEventService.SessionsRevoked), (signal.Event, signal.Sponsor, signal.Decision, signal.Reason));

        // It also signs the person out: their subject tokens issued before the event may not start
        // a task.
        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((Human, SecurityEventService.Transmitter, (DateTimeOffset?)Now.AddSeconds(-5)), (revocation.SponsorKey, revocation.RevokedBy, revocation.IssuedBefore));
    }

    [Fact]
    public async Task Sessions_being_revoked_with_nothing_running_still_signs_the_person_out_on_the_record()
    {
        var harness = new Harness();

        Assert.Null(await harness.Build().ReceiveAsync(Token(SecurityEventTokenValidator.SessionRevoked)));

        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((Human, (DateTimeOffset?)Now.AddSeconds(-5)), (revocation.SponsorKey, revocation.IssuedBefore));
        var signal = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SponsorSignal, Human, SecurityEventService.SessionsRevoked), (signal.Event, signal.Sponsor, signal.Reason));
    }

    [Fact]
    public async Task The_time_of_the_latest_account_event_is_kept_and_never_moves_back()
    {
        var harness = new Harness();
        var service = harness.Build();

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "disabled", issuedAt: Now.AddMinutes(-3))));
        Assert.Equal(Now.AddMinutes(-3), harness.Blocks.Watermarks[Human]);

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enabled", issuedAt: Now.AddMinutes(-1))));
        Assert.Equal(Now.AddMinutes(-1), harness.Blocks.Watermarks[Human]);

        // Kept after the block is lifted, which is when a late disabling would otherwise land.
        Assert.Empty(harness.Blocks.Stored);
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "late", issuedAt: Now.AddMinutes(-2))));
        Assert.Equal(Now.AddMinutes(-1), harness.Blocks.Watermarks[Human]);

        // A session ending is not an account event and is not ordered.
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.SessionRevoked, jti: "sessions", issuedAt: Now.AddMinutes(-4))));
        Assert.Equal(Now.AddMinutes(-1), harness.Blocks.Watermarks[Human]);
    }

    [Fact]
    public async Task An_account_enabled_issued_before_the_disabling_that_placed_the_block_does_not_lift_it()
    {
        // Delivered out of order: the disabling was issued after the enabling, so it stands.
        var harness = new Harness();
        var service = harness.Build();
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "disabled", issuedAt: Now.AddMinutes(-1))));

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enabled", issuedAt: Now.AddMinutes(-2))));

        Assert.Equal(SponsorBlockSource.Ssf, harness.Blocks.Stored[Human].Source);
        Assert.DoesNotContain(harness.Audit.Events, e => e.Reason == SecurityEventService.AccountEnabled);
        var refusal = Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorUnblocked);
        Assert.Equal((AuditDecision.Deny, SponsorSignalWriter.SignalOutOfOrder, Human), (refusal.Decision, refusal.Reason, refusal.Sponsor));
    }

    [Theory]
    [InlineData(SecurityEventTokenValidator.AccountDisabled)]
    [InlineData(SecurityEventTokenValidator.AccountPurged)]
    public async Task An_account_closing_issued_before_an_enabling_already_applied_neither_blocks_nor_ends_anything(string eventType)
    {
        // Disabled, enabled again, and the person starts a new task. A disabling issued between
        // the two arrives late: the person was let back in after it, so it is not applied.
        var harness = new Harness();
        var service = harness.Build();
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "disabled", issuedAt: Now.AddMinutes(-3))));
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enabled", issuedAt: Now.AddMinutes(-1))));
        harness.WithTask("task_new", Human);
        harness.Audit.Events.Clear();

        Assert.Null(await service.ReceiveAsync(Token(eventType, jti: "late", issuedAt: Now.AddMinutes(-2))));

        Assert.Empty(harness.Blocks.Stored);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_new").Status);
        var refusal = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SponsorBlocked, AuditDecision.Deny, SponsorSignalWriter.SignalOutOfOrder, Human), (refusal.Event, refusal.Decision, refusal.Reason, refusal.Sponsor));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(60)]
    public async Task An_account_enabled_issued_with_or_after_the_disabling_lifts_the_block(int secondsLater)
    {
        var harness = new Harness();
        var service = harness.Build();
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "disabled", issuedAt: Now.AddMinutes(-2))));

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enabled", issuedAt: Now.AddMinutes(-2).AddSeconds(secondsLater))));

        Assert.Empty(harness.Blocks.Stored);
        Assert.Contains(harness.Audit.Events, e => e.Reason == SecurityEventService.AccountEnabled && e.Sponsor == Human);
    }

    [Fact]
    public async Task An_account_closing_with_the_same_iat_as_an_enabling_already_applied_is_applied_after_it()
    {
        // Two events in the same second cannot be told apart by iat: the one that arrives last wins,
        // and a disabling arriving last blocks.
        var harness = new Harness();
        var service = harness.Build();
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enabled", issuedAt: Now.AddMinutes(-2))));

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "disabled", issuedAt: Now.AddMinutes(-2))));

        Assert.Equal(SponsorBlockSource.Ssf, harness.Blocks.Stored[Human].Source);
        Assert.DoesNotContain(harness.Audit.Events, e => e.Reason == SponsorSignalWriter.SignalOutOfOrder);
    }

    [Fact]
    public async Task A_later_disabling_that_restates_the_block_moves_the_order_forward()
    {
        // Disabled twice; an enabling issued between the two is older than the latest disabling.
        var harness = new Harness();
        var service = harness.Build();
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "first", issuedAt: Now.AddMinutes(-3))));
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "second", issuedAt: Now.AddMinutes(-1))));

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enabled", issuedAt: Now.AddMinutes(-2))));

        Assert.Equal(SponsorBlockSource.Ssf, harness.Blocks.Stored[Human].Source);
        Assert.Equal(Now.AddMinutes(-1), harness.Blocks.Watermarks[Human]);
    }

    [Fact]
    public async Task An_out_of_order_event_is_refused_whoever_holds_the_block()
    {
        // An operator's block stands. The transmitter's events are still ordered among themselves.
        var harness = new Harness().WithBlock(Human, SponsorBlockSource.Admin);
        var service = harness.Build();
        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled, jti: "enabled", issuedAt: Now.AddMinutes(-1))));
        harness.Audit.Events.Clear();

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, jti: "late", issuedAt: Now.AddMinutes(-2))));

        Assert.Equal(SponsorBlockSource.Admin, harness.Blocks.Stored[Human].Source);
        var refusal = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SponsorBlocked, AuditDecision.Deny, SponsorSignalWriter.SignalOutOfOrder), (refusal.Event, refusal.Decision, refusal.Reason));
    }

    [Theory]
    [InlineData(SecurityEventTokenValidator.AccountDisabled, SponsorBlockKind.Disabled, SecurityEventService.AccountDisabled)]
    [InlineData(SecurityEventTokenValidator.AccountPurged, SponsorBlockKind.Deleted, SecurityEventService.AccountPurged)]
    public async Task An_account_closing_blocks_the_person_and_ends_their_tasks(string eventType, SponsorBlockKind kind, string reason)
    {
        var harness = new Harness().WithTask("task_1", Human);

        Assert.Null(await harness.Build().ReceiveAsync(Token(eventType)));

        Assert.Equal((SponsorBlockSource.Ssf, kind), (harness.Blocks.Stored[Human].Source, harness.Blocks.Stored[Human].Kind));
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(reason, harness.Task("task_1").RevocationReason);
    }

    [Fact]
    public async Task An_account_being_enabled_lifts_this_receivers_block_and_nobody_elses()
    {
        var harness = new Harness().WithBlock(Human, SponsorBlockSource.Ssf);

        Assert.Null(await harness.Build().ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled)));

        Assert.Empty(harness.Blocks.Stored);
        Assert.Contains(harness.Audit.Events, e => e.Reason == SecurityEventService.AccountEnabled && e.Sponsor == Human);
    }

    [Fact]
    public async Task An_account_being_enabled_never_lifts_an_operators_block()
    {
        var harness = new Harness().WithBlock(Human, SponsorBlockSource.Admin);

        Assert.Null(await harness.Build().ReceiveAsync(Token(SecurityEventTokenValidator.AccountEnabled)));

        Assert.Equal(SponsorBlockSource.Admin, harness.Blocks.Stored[Human].Source);
        Assert.DoesNotContain(harness.Audit.Events, e => e.Reason == SecurityEventService.AccountEnabled);

        // Refused, and the refusal is on the record, as an operator's would be.
        var refusal = Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorUnblocked);
        Assert.Equal((AuditDecision.Deny, SponsorAdminService.SponsorBlockNotOwned, Human), (refusal.Decision, refusal.Reason, refusal.Sponsor));
    }

    [Fact]
    public async Task A_disabling_never_takes_over_a_block_another_source_placed()
    {
        // If this receiver could take over an operator's block, its own account-enabled event could
        // lift it.
        var harness = new Harness().WithBlock(Human, SponsorBlockSource.Admin);

        Assert.Null(await harness.Build().ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled)));

        Assert.Equal(SponsorBlockSource.Admin, harness.Blocks.Stored[Human].Source);
        var refusal = Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorBlocked);
        Assert.Equal((AuditDecision.Deny, SponsorAdminService.SponsorBlockedElsewhere, Human), (refusal.Decision, refusal.Reason, refusal.Sponsor));
    }

    [Fact]
    public async Task The_same_event_twice_is_acted_on_once_and_answered_as_delivered_both_times()
    {
        // A transmitter resends a token whose acknowledgement it did not see. The second is answered
        // as delivered and records nothing.
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var token = Token(SecurityEventTokenValidator.AccountDisabled);

        Assert.Null(await service.ReceiveAsync(token));
        var recorded = harness.Audit.Events.Count;

        Assert.Null(await service.ReceiveAsync(token));

        Assert.Single(harness.Revocations.Stored);
        Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorSignal);
        Assert.Equal(recorded, harness.Audit.Events.Count);
    }

    [Fact]
    public async Task The_replay_record_commits_with_the_work_or_not_at_all()
    {
        // The jti is recorded inside the work's transaction. Recorded earlier, a failed commit would
        // leave it burned, and the retry would be refused as a duplicate.
        var harness = new Harness().WithTask("task_1", Human);

        Assert.Null(await harness.Build().ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled)));

        Assert.True(harness.Replays.RecordedInsideTransaction, "the replay record was written outside the transaction that acted on the event");
        Assert.Single(harness.Replays.Stored);
    }

    [Fact]
    public async Task An_event_that_does_not_validate_changes_nothing_and_is_recorded_naming_nobody()
    {
        var harness = new Harness().WithTask("task_1", Human);

        var rejection = await harness.Build().ReceiveAsync(Mint("RS256", "rsa1", new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["aud"] = StreamAudience,
            ["iat"] = Now.AddSeconds(-5).ToUnixTimeSeconds(),
            ["jti"] = "forged",
            ["events"] = new Dictionary<string, object?> { [SecurityEventTokenValidator.AccountDisabled] = new Dictionary<string, object?> { ["subject"] = Subject(Human) } },
        }, rsa: Rsa2));

        Assert.Equal(SecurityEventRejection.InvalidSignature, rejection);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);
        Assert.Empty(harness.Blocks.Stored);

        var denial = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SignalDenied, AuditDecision.Deny, "ssf_invalid_signature"), (denial.Event, denial.Decision, denial.Reason));
        Assert.Null(denial.Sponsor);
    }

    [Fact]
    public async Task A_refused_event_does_not_burn_its_identifier_so_the_real_one_still_works()
    {
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();

        await service.ReceiveAsync(Mint("RS256", "rsa1", new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["aud"] = StreamAudience,
            ["iat"] = Now.AddSeconds(-5).ToUnixTimeSeconds(),
            ["jti"] = "event-1",
            ["events"] = new Dictionary<string, object?> { [SecurityEventTokenValidator.AccountDisabled] = new Dictionary<string, object?> { ["subject"] = Subject(Human) } },
        }, rsa: Rsa2));

        Assert.Null(await service.ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled)));
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
    }

    [Fact]
    public async Task An_event_this_receiver_does_not_act_on_is_accepted_and_changes_nothing()
    {
        var harness = new Harness().WithTask("task_1", Human);

        Assert.Null(await harness.Build().ReceiveAsync(Mint("RS256", "rsa1", new Dictionary<string, object?>
        {
            ["iss"] = Issuer,
            ["aud"] = StreamAudience,
            ["iat"] = Now.AddSeconds(-5).ToUnixTimeSeconds(),
            ["jti"] = "event-2",
            ["events"] = new Dictionary<string, object?>
            {
                ["https://schemas.openid.net/secevent/caep/event-type/credential-change"] = new Dictionary<string, object?> { ["subject"] = Subject(Human) },
            },
        })));

        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);
        Assert.Empty(harness.Blocks.Stored);
        Assert.Empty(harness.Audit.Events);
    }

    [Fact]
    public async Task One_event_about_one_person_leaves_everybody_else_alone()
    {
        var harness = new Harness().WithTask("task_1", Human).WithTask("task_other", "somebody-else");

        Assert.Null(await harness.Build().ReceiveAsync(Token(SecurityEventTokenValidator.AccountDisabled, subject: "somebody-else")));

        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_other").Status);
        Assert.DoesNotContain(Human, harness.Blocks.Stored.Keys);
    }
}
