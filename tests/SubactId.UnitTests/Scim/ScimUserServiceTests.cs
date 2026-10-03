using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Scim;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Server.Admin;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Scim;
using SubactId.Server.Signals;
using SubactId.UnitTests.Revocation;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Scim;

/// <summary>
/// What a provisioning write does to a person: which writes block somebody, which lift a block,
/// and which must leave one alone.
/// </summary>
public class ScimUserServiceTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    private const string UserName = "ada@example.com";

    private static readonly DateTimeOffset Now = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    private sealed class Harness
    {
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public InMemoryAudit Audit { get; } = new();
        public InMemoryRevocations Revocations { get; } = new();
        public InMemorySponsorBlocks Blocks { get; } = new();
        public InMemoryScimUsers Users { get; } = new();
        public InMemoryTaskRevocation Revocation { get; }

        public Harness() => Revocation = new InMemoryTaskRevocation(Tasks, Grants);

        public ScimSponsorKeyAttribute KeyAttribute { get; init; } = ScimSponsorKeyAttribute.ExternalId;

        public int MaxUsers { get; init; } = ScimOptions.DefaultMaxUsers;

        public ScimUserService Build() => new(
            Users,
            new SponsorSignalWriter(Blocks, Revocation, Revocations, Audit, new RenewalSummary(new DenialAggregationOptions())),
            new PassThroughUnitOfWork(),
            new ScimOptions { BearerToken = new string('k', 32), SponsorKeyAttribute = KeyAttribute, MaxUsers = MaxUsers },
            Clock);

        /// <summary>A live task for <paramref name="sponsorKey"/>.</summary>
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

    private static ScimUserRequest Body(bool? active = null, string userName = UserName, string? externalId = Human) =>
        new() { Schemas = [ScimSchemas.User], UserName = userName, ExternalId = externalId, Active = active is { } value ? JsonSerializer.SerializeToElement(value) : null };

    private static ScimPatchRequest Patch(string op, string? path, object? value) => new()
    {
        Schemas = [ScimSchemas.PatchOp],
        Operations = [new ScimPatchOperation { Op = op, Path = path, Value = Value(value) }],
    };

    private static JsonElement? Value(object? value) =>
        value is null ? null : JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(value));

    [Fact]
    public async Task A_person_provisioned_as_inactive_is_blocked_and_their_tasks_end()
    {
        var harness = new Harness().WithTask("task_1", Human).WithTask("task_other", "somebody-else");

        var (user, failure) = await harness.Build().CreateAsync(Body(active: false));

        Assert.Null(failure);
        Assert.Equal((UserName, Human, false), (user!.UserName, user.SponsorKey, user.Active));

        var block = harness.Blocks.Stored[Human];
        Assert.Equal((SponsorBlockSource.Scim, SponsorBlockKind.Disabled), (block.Source, block.Kind));
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(ScimUserService.Deactivated, harness.Task("task_1").RevocationReason);

        // Somebody else's tasks are untouched.
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_other").Status);

        Assert.Equal(AuditEvents.SponsorSignal, harness.Audit.Events[0].Event);
        Assert.Equal((Human, AuditDecision.Allow, ScimUserService.Deactivated), (harness.Audit.Events[0].Sponsor, harness.Audit.Events[0].Decision, harness.Audit.Events[0].Reason));

        var revocation = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((Human, ScimUserService.Deactivated, ScimUserService.ProvisioningClient), (revocation.SponsorKey, revocation.Reason, revocation.RevokedBy));
    }

    [Fact]
    public async Task A_person_provisioned_as_active_is_not_blocked_and_nothing_is_recorded()
    {
        var harness = new Harness().WithTask("task_1", Human);

        var (user, failure) = await harness.Build().CreateAsync(Body());

        Assert.Null(failure);
        Assert.True(user!.Active);
        Assert.Empty(harness.Blocks.Stored);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);

        // A directory sync restates everybody it knows about. A record per restatement would be a
        // record per person per sync, in a ledger that refuses deletes.
        Assert.Empty(harness.Audit.Events);
    }

    [Theory]
    [InlineData(false)]
    [InlineData("False")]
    public async Task A_patch_setting_active_to_false_blocks_the_person_whether_it_is_sent_as_a_boolean_or_a_string(object value)
    {
        // Entra ID sends it quoted, and it must still be read as a boolean.
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        var (patched, failure) = await service.PatchAsync(created!.Id, Patch("replace", "active", value));

        Assert.Null(failure);
        Assert.False(patched!.Active);
        Assert.Equal(SponsorBlockSource.Scim, harness.Blocks.Stored[Human].Source);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
    }

    [Fact]
    public async Task A_pathless_patch_naming_active_in_its_value_blocks_the_person()
    {
        // Okta sends the attribute inside the value rather than as a path.
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        var (patched, failure) = await service.PatchAsync(created!.Id, Patch("replace", null, new Dictionary<string, object> { ["active"] = false }));

        Assert.Null(failure);
        Assert.False(patched!.Active);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
    }

    [Fact]
    public async Task A_patch_of_an_attribute_this_receiver_does_not_keep_changes_nothing_and_is_not_an_error()
    {
        // A provisioning client patches name and department together with state. Attributes nobody
        // stores are ignored, not refused.
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        var (patched, failure) = await service.PatchAsync(created!.Id, Patch("replace", "name.givenName", "Ada"));

        Assert.Null(failure);
        Assert.Equal((UserName, true), (patched!.UserName, patched.Active));
        Assert.Empty(harness.Blocks.Stored);
    }

    [Fact]
    public async Task A_body_that_is_not_a_patch_is_refused()
    {
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        Assert.Equal(ScimFailure.MalformedBody, (await service.PatchAsync(created!.Id, new ScimPatchRequest())).Failure);
        Assert.Equal(ScimFailure.MalformedBody, (await service.PatchAsync(created.Id, Patch("sprinkle", "active", false))).Failure);

        // A removal with nothing to remove, and a pathless operation whose value names nothing.
        Assert.Equal(ScimFailure.MalformedBody, (await service.PatchAsync(created.Id, Patch("remove", null, "active"))).Failure);
        Assert.Equal(ScimFailure.MalformedBody, (await service.PatchAsync(created.Id, Patch("replace", null, "active"))).Failure);
    }

    [Theory]
    [InlineData("""{"active":false,"Active":true}""")]
    [InlineData("""{"active":false,"active":true}""")]
    [InlineData("""{"userName":"a@example.com","USERNAME":"b@example.com"}""")]
    public async Task A_pathless_patch_naming_an_attribute_twice_in_any_case_is_refused(string value)
    {
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());
        var patch = new ScimPatchRequest
        {
            Schemas = [ScimSchemas.PatchOp],
            Operations = [new ScimPatchOperation { Op = "replace", Value = JsonDocument.Parse(value).RootElement.Clone() }],
        };

        var (patched, failure) = await service.PatchAsync(created!.Id, patch);

        Assert.Null(patched);
        Assert.Equal(ScimFailure.MalformedBody, failure);
        Assert.Empty(harness.Blocks.Stored);
    }

    [Fact]
    public async Task Replacing_a_user_as_inactive_blocks_them()
    {
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        var (replaced, failure) = await service.ReplaceAsync(created!.Id, Body(active: false));

        Assert.Null(failure);
        Assert.False(replaced!.Active);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
    }

    [Fact]
    public async Task Deleting_a_user_blocks_them_as_gone_and_ends_their_tasks()
    {
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        Assert.Null(await service.DeleteAsync(created!.Id));

        // The record goes; the block stays. Dropping only the row would leave their tasks running and
        // let them start another.
        Assert.Empty(harness.Users.Stored);
        Assert.Equal(SponsorBlockKind.Deleted, harness.Blocks.Stored[Human].Kind);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(ScimUserService.Deleted, harness.Task("task_1").RevocationReason);
        Assert.Equal(ScimFailure.NotFound, await service.DeleteAsync(created.Id));
    }

    [Fact]
    public async Task A_reactivation_lifts_this_receivers_block_and_lets_the_person_start_again()
    {
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body(active: false));
        Assert.NotEmpty(harness.Blocks.Stored);

        var (patched, failure) = await service.PatchAsync(created!.Id, Patch("replace", "active", true));

        Assert.Null(failure);
        Assert.True(patched!.Active);
        Assert.Empty(harness.Blocks.Stored);
        Assert.Contains(harness.Audit.Events, e => e.Reason == ScimUserService.Reactivated && e.Sponsor == Human);
    }

    [Fact]
    public async Task A_reactivation_does_not_lift_the_block_another_inactive_record_under_the_same_key_placed()
    {
        // Two records may share a key. One deactivated keeps the person blocked, whatever is said
        // about the other.
        var harness = new Harness();
        var service = harness.Build();
        var (first, _) = await service.CreateAsync(Body(active: false));
        Assert.Equal(SponsorBlockSource.Scim, harness.Blocks.Stored[Human].Source);
        var audited = harness.Audit.Events.Count;

        var (second, failure) = await service.CreateAsync(Body(active: true, userName: "ada.lovelace@example.com"));
        Assert.Null(failure);
        await service.PatchAsync(second!.Id, Patch("replace", "active", true));
        await service.ReplaceAsync(second.Id, Body(active: true, userName: "ada.lovelace@example.com"));

        Assert.Equal(SponsorBlockSource.Scim, harness.Blocks.Stored[Human].Source);
        Assert.Equal(audited, harness.Audit.Events.Count);
        Assert.Contains(harness.Revocation.Held, held => held.SequenceEqual([Human]));

        // Once the record that placed it is active too, the block lifts.
        var (reactivated, refused) = await service.PatchAsync(first!.Id, Patch("replace", "active", true));

        Assert.Null(refused);
        Assert.True(reactivated!.Active);
        Assert.Empty(harness.Blocks.Stored);
        Assert.Single(harness.Audit.Events, e => e.Reason == ScimUserService.Reactivated && e.Sponsor == Human);
    }

    [Fact]
    public async Task Every_write_holds_the_person_it_names_before_anything_else()
    {
        // Whether a block stands depends on every record naming the person, so writes to records
        // that share a key take turns from the start of their unit of work.
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());
        Assert.Equal([Human], harness.Revocation.Held[0]);

        harness.Revocation.Held.Clear();
        await service.PatchAsync(created!.Id, Patch("replace", "active", true));
        Assert.Equal([Human], harness.Revocation.Held[0]);

        harness.Revocation.Held.Clear();
        await service.ReplaceAsync(created.Id, Body(active: false));
        Assert.Equal([Human], harness.Revocation.Held[0]);

        harness.Revocation.Held.Clear();
        Assert.Null(await service.DeleteAsync(created.Id));
        Assert.Equal([Human], harness.Revocation.Held[0]);
    }

    [Fact]
    public async Task A_reactivation_never_lifts_an_operators_block()
    {
        // A block carries its source, so a provisioning feed that is behind cannot overrule a
        // deliberate block.
        var harness = new Harness().WithBlock(Human, SponsorBlockSource.Admin);
        var service = harness.Build();

        var (user, failure) = await service.CreateAsync(Body(active: true));

        Assert.Null(failure);
        Assert.NotNull(user);
        Assert.Equal(SponsorBlockSource.Admin, harness.Blocks.Stored[Human].Source);
        Assert.DoesNotContain(harness.Audit.Events, e => e.Reason == ScimUserService.Reactivated);
        var refusal = Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorUnblocked);
        Assert.Equal((AuditDecision.Deny, SponsorAdminService.SponsorBlockNotOwned, Human), (refusal.Decision, refusal.Reason, refusal.Sponsor));
    }

    [Fact]
    public async Task A_deactivation_never_takes_over_a_block_another_source_placed()
    {
        // If this receiver could take over an operator's block, its own reactivation could lift it at
        // the next sync.
        var harness = new Harness().WithBlock(Human, SponsorBlockSource.Admin);
        var service = harness.Build();

        var (user, failure) = await service.CreateAsync(Body(active: false));

        Assert.Null(failure);
        Assert.NotNull(user);
        Assert.Equal(SponsorBlockSource.Admin, harness.Blocks.Stored[Human].Source);

        var blockRefused = Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorBlocked);
        Assert.Equal((AuditDecision.Deny, SponsorAdminService.SponsorBlockedElsewhere, Human), (blockRefused.Decision, blockRefused.Reason, blockRefused.Sponsor));

        // And it still cannot be lifted from here afterwards, which is refused and recorded too.
        var (reactivated, _) = await service.ReplaceAsync(user!.Id, Body(active: true));
        Assert.NotNull(reactivated);
        Assert.Equal(SponsorBlockSource.Admin, harness.Blocks.Stored[Human].Source);
        var liftRefused = Assert.Single(harness.Audit.Events, e => e.Event == AuditEvents.SponsorUnblocked);
        Assert.Equal((AuditDecision.Deny, SponsorAdminService.SponsorBlockNotOwned), (liftRefused.Decision, liftRefused.Reason));
    }

    [Fact]
    public async Task A_sync_that_restates_a_person_records_no_new_refusal()
    {
        // A directory sync re-sends everyone's state on every cycle. An operator's block standing on
        // somebody is refused once, when their state changes, not once per sync.
        var harness = new Harness().WithBlock(Human, SponsorBlockSource.Admin);
        var service = harness.Build();
        var (user, _) = await service.CreateAsync(Body(active: true));
        var recorded = harness.Audit.Events.Count;

        for (var sync = 0; sync < 3; sync++)
        {
            var (restated, failure) = await service.ReplaceAsync(user!.Id, Body(active: true));
            Assert.Null(failure);
            Assert.NotNull(restated);
        }

        Assert.Equal(recorded, harness.Audit.Events.Count);
        Assert.Equal(SponsorBlockSource.Admin, harness.Blocks.Stored[Human].Source);
    }

    [Fact]
    public async Task Provisioning_somebody_again_after_deleting_them_leaves_them_usable()
    {
        // Deprovisioning and reprovisioning is ordinary. The block a deletion placed must not survive
        // the new record, or nothing would ever lift it.
        var harness = new Harness();
        var service = harness.Build();
        var (first, _) = await service.CreateAsync(Body());
        await service.DeleteAsync(first!.Id);
        Assert.Equal(SponsorBlockKind.Deleted, harness.Blocks.Stored[Human].Kind);

        var (second, failure) = await service.CreateAsync(Body());

        Assert.Null(failure);
        Assert.NotNull(second);
        Assert.Empty(harness.Blocks.Stored);
    }

    [Fact]
    public async Task A_deletion_holds_the_person_blocked_while_another_record_naming_them_is_rewritten_as_active()
    {
        // Two records name the person. One is deleted. The other being re-sent, replaced or patched
        // as active is not a new record: the deleted one is gone, and nothing said about the other
        // stands for it.
        var harness = new Harness();
        var service = harness.Build();
        var (deleted, _) = await service.CreateAsync(Body());
        var (other, _) = await service.CreateAsync(Body(userName: "ada.lovelace@example.com"));
        Assert.Null(await service.DeleteAsync(deleted!.Id));
        Assert.True(harness.Blocks.Stored[Human].PlacedByDeletion);
        var audited = harness.Audit.Events.Count;

        await service.ReplaceAsync(other!.Id, Body(active: true, userName: "ada.lovelace@example.com"));
        await service.PatchAsync(other.Id, Patch("replace", "active", true));
        await service.PatchAsync(other.Id, Patch("replace", "active", false));
        await service.PatchAsync(other.Id, Patch("replace", "active", true));

        Assert.Equal((SponsorBlockSource.Scim, true), (harness.Blocks.Stored[Human].Source, harness.Blocks.Stored[Human].PlacedByDeletion));
        Assert.DoesNotContain(harness.Audit.Events.Skip(audited), e => e.Reason == ScimUserService.Reactivated);
    }

    [Fact]
    public async Task A_new_record_naming_the_person_lifts_a_block_a_deletion_placed()
    {
        var harness = new Harness();
        var service = harness.Build();
        var (deleted, _) = await service.CreateAsync(Body());
        await service.CreateAsync(Body(userName: "ada.lovelace@example.com"));
        await service.DeleteAsync(deleted!.Id);

        var (created, failure) = await service.CreateAsync(Body(userName: "ada.byron@example.com"));

        Assert.Null(failure);
        Assert.NotNull(created);
        Assert.Empty(harness.Blocks.Stored);
        Assert.Single(harness.Audit.Events, e => e.Reason == ScimUserService.Reactivated && e.Sponsor == Human);
    }

    [Fact]
    public async Task A_new_record_while_another_is_inactive_takes_the_deletion_off_and_leaves_that_record_holding_the_block()
    {
        // Deleted, then another record deactivated, then a new one created. The deletion is
        // answered; the inactive record still holds the block, and its reactivation lifts it.
        var harness = new Harness();
        var service = harness.Build();
        var (deleted, _) = await service.CreateAsync(Body());
        var (inactive, _) = await service.CreateAsync(Body(userName: "ada.lovelace@example.com"));
        await service.DeleteAsync(deleted!.Id);
        await service.PatchAsync(inactive!.Id, Patch("replace", "active", false));

        await service.CreateAsync(Body(userName: "ada.byron@example.com"));

        Assert.Equal((SponsorBlockSource.Scim, false), (harness.Blocks.Stored[Human].Source, harness.Blocks.Stored[Human].PlacedByDeletion));

        await service.PatchAsync(inactive.Id, Patch("replace", "active", true));

        Assert.Empty(harness.Blocks.Stored);
    }

    [Fact]
    public async Task A_deactivation_after_a_deletion_does_not_take_the_deletion_off()
    {
        // The kind follows the latest write, as before; the deletion still waits for a new record.
        var harness = new Harness();
        var service = harness.Build();
        var (deleted, _) = await service.CreateAsync(Body());
        var (other, _) = await service.CreateAsync(Body(userName: "ada.lovelace@example.com"));
        await service.DeleteAsync(deleted!.Id);

        await service.PatchAsync(other!.Id, Patch("replace", "active", false));
        await service.PatchAsync(other.Id, Patch("replace", "active", true));

        Assert.True(harness.Blocks.Stored[Human].PlacedByDeletion);
    }

    [Fact]
    public async Task A_write_that_deactivates_and_renames_at_once_ends_the_tasks_under_both_identifiers()
    {
        // A client sending the whole resource sends the new identifier with the deactivation. Tasks
        // running under the old key must still end.
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());
        harness.Revocation.Held.Clear();

        var (replaced, failure) = await service.ReplaceAsync(created!.Id, Body(active: false, externalId: "oid-renamed"));

        Assert.Null(failure);
        Assert.Equal("oid-renamed", replaced!.SponsorKey);
        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.Equal(SponsorBlockSource.Scim, harness.Blocks.Stored[Human].Source);
        Assert.Equal(SponsorBlockSource.Scim, harness.Blocks.Stored["oid-renamed"].Source);

        // Both people are held together, before the record or either block is written, so the
        // second block's wait cannot close a cycle with an exchange or with another write naming
        // either of them (see HoldSponsorsAsync).
        Assert.Equal(["oid-renamed", Human], harness.Revocation.Held[0]);
        Assert.All(harness.Revocation.Held.Skip(1), held => Assert.Single(held));
    }

    [Fact]
    public async Task A_deactivation_under_one_key_holds_only_that_person()
    {
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        await service.ReplaceAsync(created!.Id, Body(active: false));

        Assert.Equal(DelegationTaskStatus.Revoked, harness.Task("task_1").Status);
        Assert.All(harness.Revocation.Held, held => Assert.Equal([Human], held));
    }

    [Fact]
    public async Task A_rename_on_its_own_blocks_nobody()
    {
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        var (replaced, failure) = await service.ReplaceAsync(created!.Id, Body(externalId: "oid-renamed"));

        Assert.Null(failure);
        Assert.Equal("oid-renamed", replaced!.SponsorKey);
        Assert.Empty(harness.Blocks.Stored);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);
    }

    [Fact]
    public async Task Restating_a_block_that_already_holds_records_nothing_new()
    {
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body(active: false));
        var recorded = harness.Audit.Events.Count;

        await service.ReplaceAsync(created!.Id, Body(active: false));

        Assert.Equal(recorded, harness.Audit.Events.Count);
    }

    [Fact]
    public async Task A_user_that_cannot_name_anybody_is_refused_rather_than_stored()
    {
        // A record whose deactivation would match no task is refused, so provisioning fails at setup,
        // not silently later.
        var harness = new Harness();

        Assert.Equal(ScimFailure.MissingSponsorKey, (await harness.Build().CreateAsync(Body(externalId: null))).Failure);
        Assert.Empty(harness.Users.Stored);
    }

    [Fact]
    public async Task A_deployment_keyed_by_user_name_takes_the_user_name_as_the_key()
    {
        var harness = new Harness { KeyAttribute = ScimSponsorKeyAttribute.UserName };

        var (user, failure) = await harness.Build().CreateAsync(Body(active: false, externalId: null));

        Assert.Null(failure);
        Assert.Equal(UserName, user!.SponsorKey);
        Assert.Contains(UserName, harness.Blocks.Stored.Keys);
    }

    [Fact]
    public async Task A_second_record_for_one_user_name_is_a_conflict()
    {
        var harness = new Harness();
        var service = harness.Build();
        await service.CreateAsync(Body());

        Assert.Equal(ScimFailure.UserNameTaken, (await service.CreateAsync(Body(externalId: "someone-else"))).Failure);
    }

    [Fact]
    public async Task A_user_name_that_is_missing_or_unusable_is_refused()
    {
        var harness = new Harness();

        Assert.Equal(ScimFailure.MissingUserName, (await harness.Build().CreateAsync(Body(userName: ""))).Failure);
        Assert.Equal(ScimFailure.MissingUserName, (await harness.Build().CreateAsync(new ScimUserRequest())).Failure);
        Assert.Equal(ScimFailure.MalformedBody, (await harness.Build().CreateAsync(null)).Failure);
    }

    [Fact]
    public async Task The_table_is_bounded()
    {
        // A provisioning credential cannot be used to fill the disk.
        var harness = new Harness { MaxUsers = 1 };
        var service = harness.Build();
        await service.CreateAsync(Body());

        Assert.Equal(ScimFailure.Capacity, (await service.CreateAsync(Body(userName: "grace@example.com", externalId: "another"))).Failure);
    }

    [Fact]
    public async Task A_write_decided_from_a_user_that_changed_under_it_is_decided_again_rather_than_applied()
    {
        // Two patches to one person, both reading them active: one deactivates, one renames. The
        // rename is applied to the current state, so the person stays inactive under the new name.
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());
        harness.Users.OnWrite = stored =>
        {
            // The deactivation lands between the rename's read and its write.
            harness.Users.OnWrite = null;
            stored[created!.Id] = stored[created.Id] with { Active = false };
            harness.Blocks.Stored[Human] = new SponsorBlock(Human, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, Now);
        };

        var (patched, failure) = await service.PatchAsync(created!.Id, Patch("replace", "externalId", "oid-renamed"));

        Assert.Null(failure);
        Assert.Equal(2, harness.Users.Writes);
        Assert.False(patched!.Active);
        Assert.Equal(SponsorBlockSource.Scim, harness.Blocks.Stored[Human].Source);
        Assert.Equal(SponsorBlockSource.Scim, harness.Blocks.Stored["oid-renamed"].Source);
    }

    [Fact]
    public async Task A_deletion_decided_from_a_user_that_was_renamed_under_it_blocks_the_person_under_their_new_name()
    {
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());
        harness.Users.OnWrite = stored =>
        {
            harness.Users.OnWrite = null;
            stored[created!.Id] = stored[created.Id] with { ExternalId = "oid-renamed", SponsorKey = "oid-renamed" };
        };

        Assert.Null(await service.DeleteAsync(created!.Id));

        Assert.Equal(2, harness.Users.Writes);
        Assert.Empty(harness.Users.Stored);
        Assert.Equal(SponsorBlockKind.Deleted, harness.Blocks.Stored["oid-renamed"].Kind);
        Assert.False(harness.Blocks.Stored.ContainsKey(Human));
    }

    [Fact]
    public async Task A_user_that_keeps_changing_under_a_write_is_reported_rather_than_written_over()
    {
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());
        var churn = 0;
        harness.Users.OnWrite = stored => stored[created!.Id] = stored[created.Id] with { ExternalId = "oid-" + ++churn, SponsorKey = "oid-" + churn };

        var (replaced, failure) = await service.ReplaceAsync(created!.Id, Body(active: false));

        Assert.Null(replaced);
        Assert.Equal(ScimFailure.Changed, failure);
        Assert.Equal(ScimUserService.MaxWriteAttempts, harness.Users.Writes);

        // Nothing was decided from a state that was not there: no block, no record.
        Assert.Empty(harness.Blocks.Stored);
        Assert.Empty(harness.Audit.Events);
    }

    [Theory]
    [InlineData("replace", "active", "maybe")]
    [InlineData("replace", "active", 1)]
    [InlineData("replace", "active", null)]
    [InlineData("add", "userName", 42)]
    [InlineData("remove", "userName", null)]
    [InlineData("replace", "externalId", true)]
    public async Task A_value_an_attribute_this_receiver_keeps_cannot_take_is_refused_rather_than_ignored(string op, string path, object? value)
    {
        // "active": "maybe" is not "no change": it may be a deactivation that was not applied, so a
        // 200 would mislead the client.
        var harness = new Harness().WithTask("task_1", Human);
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        var (patched, failure) = await service.PatchAsync(created!.Id, Patch(op, path, value));

        Assert.Null(patched);
        Assert.Equal(ScimFailure.InvalidValue, failure);
        Assert.Equal(created, harness.Users.Stored[created.Id]);
        Assert.Empty(harness.Blocks.Stored);
        Assert.Equal(DelegationTaskStatus.Active, harness.Task("task_1").Status);
    }

    [Fact]
    public async Task A_pathless_patch_with_an_unreadable_value_for_a_kept_attribute_is_refused_too()
    {
        var harness = new Harness();
        var service = harness.Build();
        var (created, _) = await service.CreateAsync(Body());

        var (patched, failure) = await service.PatchAsync(created!.Id, Patch("replace", null, new Dictionary<string, object> { ["name"] = "Ada", ["active"] = "maybe" }));

        Assert.Null(patched);
        Assert.Equal(ScimFailure.InvalidValue, failure);
        Assert.True(harness.Users.Stored[created.Id].Active);
    }

    [Fact]
    public async Task A_write_to_a_user_that_is_not_here_is_not_found()
    {
        var service = new Harness().Build();

        Assert.Equal(ScimFailure.NotFound, (await service.GetAsync("scim_nobody")).Failure);
        Assert.Equal(ScimFailure.NotFound, (await service.ReplaceAsync("scim_nobody", Body())).Failure);
        Assert.Equal(ScimFailure.NotFound, (await service.PatchAsync("scim_nobody", Patch("replace", "active", false))).Failure);
        Assert.Equal(ScimFailure.NotFound, await service.DeleteAsync("scim_nobody"));
        Assert.Equal(ScimFailure.NotFound, (await service.GetAsync(null)).Failure);
    }
}

/// <summary>
/// The SCIM user records over a dictionary, with the table's uniqueness and write guard: a write
/// applies to the user as the caller read it, or not at all. <see cref="OnWrite"/> runs just
/// before each guarded write and stands in for another request landing in between.
/// </summary>
internal sealed class InMemoryScimUsers : IScimUserRepository
{
    public Dictionary<string, ScimUser> Stored { get; } = new(StringComparer.Ordinal);

    /// <summary>Runs before every replace or delete, with the store, before the guard is checked.</summary>
    public Action<Dictionary<string, ScimUser>>? OnWrite { get; set; }

    /// <summary>How many guarded writes were attempted, applied or not.</summary>
    public int Writes { get; private set; }

    public Task<ScimUser?> FindAsync(string id, CancellationToken cancellationToken = default) =>
        Task.FromResult(Stored.GetValueOrDefault(id));

    public Task AddAsync(ScimUser user, CancellationToken cancellationToken = default)
    {
        if (Stored.Values.Any(u => u.UserName == user.UserName))
        {
            throw new DuplicateEntityException("scim user", user.UserName);
        }

        Stored[user.Id] = user;
        return Task.CompletedTask;
    }

    public Task<bool> ReplaceAsync(ScimUser expected, ScimUser user, CancellationToken cancellationToken = default)
    {
        if (!Guard(expected))
        {
            return Task.FromResult(false);
        }

        if (Stored.Values.Any(u => u.UserName == user.UserName && u.Id != user.Id))
        {
            throw new DuplicateEntityException("scim user", user.UserName);
        }

        Stored[user.Id] = user;
        return Task.FromResult(true);
    }

    public Task<bool> DeleteAsync(ScimUser expected, CancellationToken cancellationToken = default) =>
        Task.FromResult(Guard(expected) && Stored.Remove(expected.Id));

    /// <summary>Whether the stored user still matches <paramref name="expected"/> in every value a write decides from.</summary>
    private bool Guard(ScimUser expected)
    {
        Writes++;
        OnWrite?.Invoke(Stored);
        return Stored.TryGetValue(expected.Id, out var stored)
            && (stored.UserName, stored.ExternalId, stored.SponsorKey, stored.Active) == (expected.UserName, expected.ExternalId, expected.SponsorKey, expected.Active);
    }

    public Task<bool> AnyOtherInactiveAsync(string sponsorKey, string exceptId, CancellationToken cancellationToken = default) =>
        Task.FromResult(Stored.Values.Any(u => u.SponsorKey == sponsorKey && !u.Active && u.Id != exceptId));

    public Task<int> CountAsync(CancellationToken cancellationToken = default) => Task.FromResult(Stored.Count);

    public Task<ScimUserPage> ListAsync(ScimUserFilter filter, CancellationToken cancellationToken = default)
    {
        var matching = Stored.Values
            .Where(u => filter.UserName is null || u.UserName == filter.UserName)
            .Where(u => filter.ExternalId is null || u.ExternalId == filter.ExternalId)
            .OrderBy(u => u.Id, StringComparer.Ordinal)
            .ToList();
        return Task.FromResult(new ScimUserPage(matching.Skip(filter.StartIndex - 1).Take(filter.Count).ToList(), matching.Count));
    }
}
