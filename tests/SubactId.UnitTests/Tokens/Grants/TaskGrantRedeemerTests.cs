using System.Buffers.Text;
using SubactId.Core.Agents;
using SubactId.Core.Delegation;
using SubactId.Tokens.Grants;
using SubactId.Tokens.Issuance;
using SubactId.UnitTests.Tokens.ClientAuth;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Tokens.Grants;

public class TaskGrantRedeemerTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);
    private static readonly Agent JiraTriage = ClientAuthTestData.Agent("jira-triage");
    private static readonly Agent DbReader = ClientAuthTestData.Agent("db-reader");

    private sealed class Harness
    {
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public string Value { get; } = TaskGrantSecret.New();

        public Harness(DelegationTaskStatus taskStatus = DelegationTaskStatus.Active, DateTimeOffset? taskExpiresAt = null, DateTimeOffset? grantExpiresAt = null, DateTimeOffset? revokedAt = null)
        {
            Tasks.Stored.Add(new DelegationTask("task_1", "jira-triage", "human", "human", null, null, 1, "https://jira.internal", ["jira:read"], taskStatus, Now.AddMinutes(-5), taskExpiresAt ?? Now.AddMinutes(25), null, null));
            Grants.Stored.Add(new TaskGrant(TaskGrantSecret.Hash(Value), "task_1", "jira-triage", ["jira:read"], Now.AddMinutes(-5), grantExpiresAt ?? Now.AddMinutes(25), revokedAt, null));
        }

        public Task<TaskGrantRedemption> Redeem(Agent agent, string? value = null, DateTimeOffset? now = null) => new TaskGrantRedeemer(Grants, Tasks).RedeemAsync(agent, value ?? Value, now ?? Now);
    }

    [Fact]
    public async Task The_agent_the_grant_was_issued_to_can_redeem_it_and_gets_the_task_back()
    {
        var harness = new Harness();

        var redemption = await harness.Redeem(JiraTriage);

        Assert.True(redemption.IsAccepted);
        Assert.Equal(TaskGrantRejection.None, redemption.Reason);
        Assert.Equal("task_1", redemption.Task!.TaskId);
        Assert.Equal(TaskGrantSecret.Hash(harness.Value), redemption.Grant!.GrantHash.ToArray());
    }

    [Fact]
    public async Task A_grant_is_unusable_by_a_different_agent()
    {
        var harness = new Harness();

        var redemption = await harness.Redeem(DbReader);

        Assert.False(redemption.IsAccepted);
        Assert.Equal(TaskGrantRejection.NotFound, redemption.Reason);
        Assert.Null(redemption.Grant);
        Assert.Null(redemption.Task);
    }

    [Fact]
    public async Task The_stored_hash_cannot_be_used_as_the_grant()
    {
        var harness = new Harness();
        var storedHash = harness.Grants.Stored.Single().GrantHash.ToArray();

        Assert.Equal(TaskGrantRejection.NotFound, (await harness.Redeem(JiraTriage, TaskGrantSecret.Prefix + Base64Url.EncodeToString(storedHash))).Reason);
        Assert.Equal(TaskGrantRejection.NotFound, (await harness.Redeem(JiraTriage, Convert.ToHexString(storedHash))).Reason);
        Assert.Equal(TaskGrantRejection.NotFound, (await harness.Redeem(JiraTriage, Base64Url.EncodeToString(storedHash))).Reason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("task_grant_")]
    [InlineData("task_grant_short")]
    [InlineData("not_a_grant_at_all_but_of_exactly_the_right_length_xxx")]
    public async Task A_malformed_value_is_not_found_without_being_looked_up(string? value)
    {
        var harness = new Harness();
        var redemption = await new TaskGrantRedeemer(harness.Grants, harness.Tasks).RedeemAsync(JiraTriage, value, Now);

        Assert.Equal(TaskGrantRejection.NotFound, redemption.Reason);
        Assert.Equal(0, harness.Grants.Finds);
    }

    [Fact]
    public async Task A_value_differing_in_one_character_is_not_found()
    {
        var harness = new Harness();
        var last = harness.Value[^1];
        var tampered = harness.Value[..^1] + (last == 'A' ? 'B' : 'A');

        Assert.Equal(TaskGrantRejection.NotFound, (await harness.Redeem(JiraTriage, tampered)).Reason);
    }

    [Fact]
    public async Task A_revoked_grant_under_a_live_task_is_refused_as_revoked()
    {
        Assert.Equal(TaskGrantRejection.Revoked, (await new Harness(revokedAt: Now.AddMinutes(-1)).Redeem(JiraTriage)).Reason);
    }

    [Fact]
    public async Task A_grant_revoked_together_with_its_task_reports_the_task()
    {
        // Task revocation stamps its grants too; the reason recorded must be the task's, per spec section 5's order.
        Assert.Equal(TaskGrantRejection.TaskRevoked, (await new Harness(taskStatus: DelegationTaskStatus.Revoked, revokedAt: Now.AddMinutes(-1)).Redeem(JiraTriage)).Reason);
        Assert.Equal(TaskGrantRejection.TaskExpired, (await new Harness(taskExpiresAt: Now, grantExpiresAt: Now).Redeem(JiraTriage)).Reason);
    }

    [Fact]
    public async Task An_expired_grant_is_refused_as_expired_at_the_exact_instant()
    {
        Assert.Equal(TaskGrantRejection.Expired, (await new Harness(grantExpiresAt: Now).Redeem(JiraTriage)).Reason);
        Assert.True((await new Harness(grantExpiresAt: Now.AddSeconds(1)).Redeem(JiraTriage)).IsAccepted);
    }

    [Theory]
    [InlineData(DelegationTaskStatus.Revoked, TaskGrantRejection.TaskRevoked)]
    [InlineData(DelegationTaskStatus.Expired, TaskGrantRejection.TaskExpired)]
    public async Task A_grant_dies_with_its_task(DelegationTaskStatus status, TaskGrantRejection expected)
    {
        Assert.Equal(expected, (await new Harness(taskStatus: status).Redeem(JiraTriage)).Reason);
    }

    [Fact]
    public async Task A_task_past_its_expiry_that_the_sweeper_has_not_marked_yet_still_refuses_the_grant()
    {
        var harness = new Harness(taskExpiresAt: Now, grantExpiresAt: Now.AddMinutes(1));

        Assert.Equal(TaskGrantRejection.TaskExpired, (await harness.Redeem(JiraTriage)).Reason);
    }
}

public class TaskGrantSecretTests
{
    [Fact]
    public void Values_have_the_prefix_the_length_and_256_bits_of_base64url()
    {
        var value = TaskGrantSecret.New();

        Assert.StartsWith("task_grant_", value, StringComparison.Ordinal);
        Assert.Equal(TaskGrantSecret.Length, value.Length);
        Assert.Matches("^task_grant_[A-Za-z0-9_-]{43}$", value);
        Assert.True(TaskGrantSecret.IsWellFormed(value));
    }

    [Fact]
    public void Values_are_unique_and_hashes_are_deterministic_32_byte_sha256()
    {
        var values = Enumerable.Range(0, 10_000).Select(_ => TaskGrantSecret.New()).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(10_000, values.Count);

        var value = values.First();
        Assert.Equal(32, TaskGrantSecret.Hash(value).Length);
        Assert.Equal(TaskGrantSecret.Hash(value), TaskGrantSecret.Hash(value));
        Assert.NotEqual(TaskGrantSecret.Hash(value), TaskGrantSecret.Hash(values.Skip(1).First()));
    }

    [Theory]
    [InlineData("task_grant_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true)]
    [InlineData("task_grant_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false)]
    [InlineData("task_grant_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+", false)]
    [InlineData("TASK_GRANT_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false)]
    [InlineData("", false)]
    public void Well_formedness_is_exact(string value, bool wellFormed)
    {
        Assert.Equal(wellFormed, TaskGrantSecret.IsWellFormed(value));
    }
}
