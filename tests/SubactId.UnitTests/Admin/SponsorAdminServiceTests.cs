using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Sponsors;
using SubactId.Server.Admin;
using SubactId.Server.Audit;
using SubactId.Server.Revocation;
using SubactId.UnitTests.Revocation;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Admin;

/// <summary>
/// The operator's side of blocking humans. A block also ends what is running, only the source
/// that placed a block may lift it, and lifting one restores nothing.
/// </summary>
public class SponsorAdminServiceTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private static readonly DateTimeOffset Now = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    private sealed class Harness
    {
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public InMemoryAudit Audit { get; } = new();
        public InMemoryRevocations Revocations { get; } = new();
        public InMemorySponsorBlocks Blocks { get; } = new();

        public SponsorAdminService Build() => new(
            Blocks,
            new InMemoryTaskRevocation(Tasks, Grants),
            Revocations,
            Audit,
            new PassThroughUnitOfWork(),
            new RenewalSummary(new DenialAggregationOptions()),
            Clock);

        /// <summary>A live task for <paramref name="sponsorKey"/>.</summary>
        public Harness WithTask(string taskId, string sponsorKey, string agentId = "jira-triage")
        {
            Tasks.Stored.Add(new DelegationTask(taskId, agentId, Human, sponsorKey, null, null, 1, "https://jira.internal", ["jira:read"], DelegationTaskStatus.Active, Now.AddMinutes(-5), Now.AddMinutes(25), null, null));
            return this;
        }

        public DelegationTask Task(string taskId) => Tasks.Stored.Single(t => t.TaskId == taskId);
    }

    [Fact]
    public async Task Blocking_a_human_ends_what_is_already_running_for_them_in_the_same_breath()
    {
        var harness = new Harness().WithTask("task_1", Human).WithTask("task_2", Human).WithTask("task_other", "somebody-else");

        var (block, revoked, failure) = await harness.Build().BlockAsync(Human);

        Assert.Null(failure);
        Assert.Equal(2, revoked);
        Assert.Equal((Human, SponsorBlockSource.Admin, SponsorBlockKind.Disabled, Now), (block!.SponsorKey, block.Source, block.Kind, block.BlockedAt));
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(SponsorAdminService.SponsorBlocked, harness.Task("task_1").RevocationReason);

        // Somebody else's task is untouched: the block is about one person.
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_other").Status);

        // The ledger carries the block itself and one record per task ended.
        Assert.Equal(AuditEvents.SponsorBlocked, harness.Audit.Events[0].Event);
        Assert.Equal((Human, AuditDecision.Allow, SponsorAdminService.SponsorBlocked), (harness.Audit.Events[0].Sponsor, harness.Audit.Events[0].Decision, harness.Audit.Events[0].Reason));
        Assert.Equal(["task_1", "task_2"], harness.Audit.Events.Skip(1).Select(e => e.TaskId).Order(StringComparer.Ordinal));
        Assert.All(harness.Audit.Events.Skip(1), e => Assert.Equal(AuditEvents.TaskRevoked, e.Event));

        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((Human, SponsorAdminService.SponsorBlocked, RevocationService.Admin), (revocation.SponsorKey, revocation.Reason, revocation.RevokedBy));
    }

    [Fact]
    public async Task A_human_with_nothing_running_can_still_be_blocked()
    {
        // A block can be placed before the person's first task.
        var harness = new Harness();

        var (block, revoked, failure) = await harness.Build().BlockAsync(Human);

        Assert.Null(failure);
        Assert.Equal(0, revoked);
        Assert.NotNull(block);
        Assert.Equal(AuditEvents.SponsorBlocked, Assert.Single(harness.Audit.Events).Event);

        // Nothing was revoked, so nothing is recorded as revoked.
        Assert.Empty(harness.Revocations.Stored);
    }

    [Fact]
    public async Task Blocking_again_is_not_an_error_and_keeps_the_block_as_it_was_placed()
    {
        var harness = new Harness();
        var service = harness.Build();
        await service.BlockAsync(Human);
        harness.WithTask("task_1", Human);
        harness.Audit.Events.Clear();
        harness.Clock.Advance(TimeSpan.FromMinutes(5));

        var (block, revoked, failure) = await service.BlockAsync(Human);

        Assert.Null(failure);
        Assert.Equal((SponsorBlockSource.Admin, Now), (block!.Source, block.BlockedAt));
        Assert.Equal(Now, harness.Blocks.Stored[Human].BlockedAt);

        // No second sponsor.blocked, but a task that slipped in is still ended.
        Assert.Equal(1, revoked);
        Assert.Equal(AuditEvents.TaskRevoked, Assert.Single(harness.Audit.Events).Event);
    }

    [Fact]
    public async Task Blocking_a_human_another_source_blocked_leaves_that_block_but_still_ends_their_tasks()
    {
        var harness = new Harness();
        var placed = new SponsorBlock(Human, SponsorBlockSource.Scim, SponsorBlockKind.Deleted, Now.AddMinutes(-10));
        await harness.Blocks.BlockAsync(placed);
        harness.WithTask("task_1", Human).WithTask("task_other", "somebody-else");
        var service = harness.Build();

        var (block, revoked, failure) = await service.BlockAsync(Human);

        Assert.Equal(SponsorAdminFailure.BlockedElsewhere, failure);
        Assert.Equal(placed, block);
        Assert.Equal(placed, harness.Blocks.Stored[Human]);

        // The kill switch still works: the person's live task is ended as a block ends it.
        Assert.Equal(1, revoked);
        Assert.Equal((DelegationTaskStatus.Revoked, SponsorAdminService.SponsorBlocked), (harness.Task("task_1").Status, harness.Task("task_1").RevocationReason));
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_other").Status);
        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((Human, SponsorAdminService.SponsorBlocked, RevocationService.Admin), (revocation.SponsorKey, revocation.Reason, revocation.RevokedBy));

        // The refused block is recorded as a denial, beside the task it ended.
        Assert.Equal(2, harness.Audit.Events.Count);
        var refused = harness.Audit.Events[0];
        Assert.Equal((AuditEvents.SponsorBlocked, Human, AuditDecision.Deny, SponsorAdminService.SponsorBlockedElsewhere), (refused.Event, refused.Sponsor, refused.Decision, refused.Reason));
        Assert.Equal((AuditEvents.TaskRevoked, "task_1"), (harness.Audit.Events[1].Event, harness.Audit.Events[1].TaskId));

        // And the operator still cannot lift it.
        Assert.Equal(SponsorAdminFailure.NotOwned, await service.UnblockAsync(Human));
        Assert.Equal(placed, harness.Blocks.Stored[Human]);
    }

    [Fact]
    public async Task Blocking_a_human_another_source_blocked_with_nothing_running_still_records_the_refusal()
    {
        var harness = new Harness();
        var placed = new SponsorBlock(Human, SponsorBlockSource.Ssf, SponsorBlockKind.Disabled, Now.AddMinutes(-10));
        await harness.Blocks.BlockAsync(placed);

        var (_, revoked, failure) = await harness.Build().BlockAsync(Human);

        Assert.Equal((SponsorAdminFailure.BlockedElsewhere, 0), (failure, revoked));
        Assert.Empty(harness.Revocations.Stored);
        var refused = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SponsorBlocked, AuditDecision.Deny, SponsorAdminService.SponsorBlockedElsewhere), (refused.Event, refused.Decision, refused.Reason));
    }

    [Fact]
    public async Task Only_the_source_that_placed_a_block_may_lift_it()
    {
        var harness = new Harness();
        await harness.Blocks.BlockAsync(new SponsorBlock(Human, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, Now));
        var service = harness.Build();

        Assert.Equal(SponsorAdminFailure.NotOwned, await service.UnblockAsync(Human));

        // Still blocked, and the refusal is on the ledger as a denial.
        Assert.True(harness.Blocks.Stored.ContainsKey(Human));
        var refused = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.SponsorUnblocked, Human, AuditDecision.Deny, SponsorAdminService.SponsorBlockNotOwned), (refused.Event, refused.Sponsor, refused.Decision, refused.Reason));
    }

    [Fact]
    public async Task An_operators_block_is_lifted_and_recorded_but_brings_no_task_back()
    {
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        await service.BlockAsync(Human);
        harness.Audit.Events.Clear();

        Assert.Null(await service.UnblockAsync(Human));

        Assert.False(harness.Blocks.Stored.ContainsKey(Human));
        Assert.Equal(AuditEvents.SponsorUnblocked, Assert.Single(harness.Audit.Events).Event);

        // Revocation is permanent, as in spec section 6.
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
    }

    [Fact]
    public async Task Lifting_a_block_nobody_placed_says_so_rather_than_answering_done()
    {
        var harness = new Harness();

        Assert.Equal(SponsorAdminFailure.NotBlocked, await harness.Build().UnblockAsync(Human));
        Assert.Empty(harness.Audit.Events);
    }

    [Fact]
    public async Task The_kill_switch_ends_the_tasks_and_leaves_the_person_able_to_start_another()
    {
        var harness = new Harness().WithTask("task_1", Human);

        var (revoked, failure) = await harness.Build().RevokeTasksAsync(Human);

        Assert.Null(failure);
        Assert.Equal(1, revoked);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(RevocationService.OperatorKillSwitch, harness.Task("task_1").RevocationReason);

        // No standing block: this ends what is running, it does not refuse the person.
        Assert.Empty(harness.Blocks.Stored);
    }

    [Fact]
    public async Task The_kill_switch_on_a_human_with_nothing_running_is_not_an_error()
    {
        // There is no registry of humans here, so this cannot answer "no such person".
        var (revoked, failure) = await new Harness().Build().RevokeTasksAsync(Human);

        Assert.Null(failure);
        Assert.Equal(0, revoked);
    }

    [Fact]
    public async Task A_sponsor_is_found_only_while_a_block_stands()
    {
        var harness = new Harness();
        var service = harness.Build();

        Assert.Equal(SponsorAdminFailure.NotBlocked, (await service.GetAsync(Human)).Failure);

        await service.BlockAsync(Human);
        var (block, failure) = await service.GetAsync(Human);

        Assert.Null(failure);
        Assert.Equal(SponsorBlockSource.Admin, block!.Source);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("has space")]
    [InlineData("has\u0000nul")]
    public async Task A_key_no_task_could_have_been_stored_under_is_refused_before_anything_is_touched(string? key)
    {
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();

        Assert.Equal(SponsorAdminFailure.InvalidKey, (await service.GetAsync(key)).Failure);
        Assert.Equal(SponsorAdminFailure.InvalidKey, (await service.BlockAsync(key)).Failure);
        Assert.Equal(SponsorAdminFailure.InvalidKey, await service.UnblockAsync(key));
        Assert.Equal(SponsorAdminFailure.InvalidKey, (await service.RevokeTasksAsync(key)).Failure);

        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);
        Assert.Empty(harness.Audit.Events);
        Assert.Empty(harness.Blocks.Stored);
    }

    [Fact]
    public async Task A_key_longer_than_a_task_could_hold_is_refused()
    {
        var tooLong = new string('k', SponsorAdminService.MaxSponsorKeyLength + 1);

        Assert.Equal(SponsorAdminFailure.InvalidKey, (await new Harness().Build().BlockAsync(tooLong)).Failure);
    }
}
