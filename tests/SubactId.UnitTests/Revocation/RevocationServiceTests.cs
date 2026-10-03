using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Core.Tokens;
using SubactId.Server.Audit;
using SubactId.Server.Contracts;
using SubactId.Server.Revocation;
using SubactId.Server.Tokens;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Issuance;
using SubactId.Tokens.Signing;
using SubactId.UnitTests.Tokens.ClientAuth;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;
using static SubactId.UnitTests.NoAggregationHelper;
using static SubactId.UnitTests.Tokens.Upstream.UpstreamTestData;

namespace SubactId.UnitTests.Revocation;

public class RevocationServiceTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    private static readonly Uri Issuer = new(ClientAuthTestData.SubactIdIssuer);

    /// <summary>A three-level tree across two agents: jira-triage's root, db-reader's child, jira-triage's grandchild, each with a grant.</summary>
    private sealed class Harness
    {
        public FakeTimeProvider Clock { get; } = new(Now);
        public InMemoryTasks Tasks { get; } = new();
        public InMemoryGrants Grants { get; } = new();
        public InMemoryAudit Audit { get; } = new();
        public InMemoryRevocations Revocations { get; } = new();
        public InMemoryReplayStore Replays { get; } = new();
        public SigningKeySet Keys { get; } = SigningKeySet.CreateEphemeral();
        public Agent JiraTriage { get; init; } = ClientAuthTestData.Agent("jira-triage") with { AllowedScopes = ["jira:read", "jira:comment"] };
        public Agent DbReader { get; } = ClientAuthTestData.Agent("db-reader") with { AllowedScopes = ["jira:read"] };
        public Dictionary<string, string> GrantValues { get; } = new(StringComparer.Ordinal);

        public Harness()
        {
            Add("task_root", "jira-triage", null, 1);
            Add("task_child", "db-reader", "task_root", 2);
            Add("task_grandchild", "jira-triage", "task_child", 3);
            Add("task_other", "jira-triage", null, 1);
        }

        public RevocationService Build()
        {
            var agents = new InMemoryAgentRepository(JiraTriage, DbReader);
            var actors = new ClientAssertionAuthenticator(agents, new StaticAgentKeys(ClientAuthTestData.Snapshot(Jwks(RsaJwk(Rsa2, "agent-key")))), Replays, Issuer, Clock);
            return new RevocationService(agents, Grants, new InMemoryTaskRevocation(Tasks, Grants), Revocations, actors, Audit, new PassThroughUnitOfWork(), new TokenAudit(Audit, Clock, NoAggregation(Clock)), new RenewalSummary(new DenialAggregationOptions()), Keys, Clock);
        }

        /// <summary>Sets how many times the task's grant has been used to refresh.</summary>
        public void Renewed(string taskId, int times)
        {
            var index = Grants.Stored.FindIndex(g => g.TaskId == taskId);
            Grants.Stored[index] = Grants.Stored[index] with { Renewals = times };
        }

        public string TaskToken(string taskId, string agentId, string jti = "tok_1")
        {
            var task = Tasks.Stored.Single(t => t.TaskId == taskId);
            var agent = agentId == "jira-triage" ? JiraTriage : DbReader;
            ActorClaim? from = task.DelegationDepth == 1 ? null : task.DelegationDepth == 2 ? ActorClaim.ForAgent("jira-triage", null, null) : ActorClaim.ForAgent("db-reader", null, ActorClaim.ForAgent("jira-triage", null, null));
            return TaskTokenSerializer.Sign(Keys, TaskTokenClaims.Issue(Issuer, task, agent, ["jira:read"], null, from, TimeSpan.FromMinutes(5), Now, jti));
        }

        public string Status(string taskId) => Tasks.Stored.Single(t => t.TaskId == taskId).Status.ToString().ToLowerInvariant();

        private void Add(string taskId, string agentId, string? parent, int depth)
        {
            Tasks.Stored.Add(new DelegationTask(taskId, agentId, Human, Human, null, parent, depth, "https://jira.internal", ["jira:read"], DelegationTaskStatus.Active, Now.AddMinutes(-5), Now.AddMinutes(25), null, null));
            var value = TaskGrantSecret.New();
            GrantValues[taskId] = value;
            Grants.Stored.Add(new TaskGrant(TaskGrantSecret.Hash(value), taskId, agentId, ["jira:read"], Now.AddMinutes(-5), Now.AddMinutes(25), null, null));
        }
    }

    private static string Assertion(string agentId) => Mint("RS256", "agent-key", ClientAuthTestData.Assertion(agentId), rsa: Rsa2);

    private static RevokeTokenRequest Request(string token, string agentId = "jira-triage", string? hint = null) =>
        new(token, hint, Assertion(agentId), RefreshTokenRequest.JwtBearerAssertionType, null);

    [Fact]
    public async Task A_task_renewed_more_than_once_is_revoked_with_its_renewal_summary_first()
    {
        var harness = new Harness();
        harness.Renewed("task_root", times: 3);
        harness.Renewed("task_child", times: 1);

        var result = await harness.Build().RevokeTaskAsync("task_root");

        Assert.Equal((true, 3), (result.Found, result.RevokedTasks));
        Assert.Equal([AuditEvents.TokenRefreshed, AuditEvents.TaskRevoked, AuditEvents.TaskRevoked, AuditEvents.TaskRevoked], harness.Audit.Events.Select(e => e.Event));
        var summary = harness.Audit.Events[0];
        var revoked = harness.Audit.Events[1];
        Assert.Equal(("task_root", "task_root", "jira-triage", Human, 2, AuditDecision.Allow, null, null, Now), (summary.TaskId, revoked.TaskId, summary.AgentId, summary.Sponsor, summary.Count, summary.Decision, summary.Jti, summary.Reason, summary.Ts));
        Assert.Equal((revoked.Audience, revoked.Scope, revoked.DelegationDepth), (summary.Audience, summary.Scope, summary.DelegationDepth));
        Assert.All(harness.Audit.Events.Skip(1), e => Assert.Null(e.Count));
    }

    [Fact]
    public async Task Revoking_a_task_revokes_its_whole_tree_across_agents_and_records_each_task()
    {
        var harness = new Harness();

        var result = await harness.Build().RevokeTaskAsync("task_root");

        Assert.Equal((true, 3), (result.Found, result.RevokedTasks));
        Assert.Equal(("revoked", "revoked", "revoked", "active"), (harness.Status("task_root"), harness.Status("task_child"), harness.Status("task_grandchild"), harness.Status("task_other")));
        Assert.All(harness.Grants.Stored.Where(g => g.TaskId != "task_other"), g => Assert.NotNull(g.RevokedAt));
        Assert.Null(harness.Grants.Stored.Single(g => g.TaskId == "task_other").RevokedAt);

        Assert.Equal(["task_root", "task_child", "task_grandchild"], harness.Audit.Events.Select(e => e.TaskId));
        Assert.All(harness.Audit.Events, e => Assert.Equal(AuditEvents.TaskRevoked, e.Event));
        Assert.Equal(["operator_kill_switch", "parent_revoked", "parent_revoked"], harness.Audit.Events.Select(e => e.Reason));
        Assert.Equal(["jira-triage", "db-reader", "jira-triage"], harness.Audit.Events.Select(e => e.AgentId));
        Assert.All(harness.Audit.Events, e => Assert.Equal(Human, e.Sponsor));
        var record = Assert.Single(harness.Revocations.Stored);
        Assert.Equal((null, "task_root", null, "operator_kill_switch", "admin"), (record.Jti, record.TaskId, record.AgentId, record.Reason, record.RevokedBy));
    }

    [Fact]
    public async Task Revoking_again_is_idempotent_and_records_nothing_while_an_unknown_task_is_not_found()
    {
        var harness = new Harness();
        var service = harness.Build();

        await service.RevokeTaskAsync("task_root");
        var again = await service.RevokeTaskAsync("task_root");
        var missing = await service.RevokeTaskAsync("task_nope");

        Assert.Equal((true, 0), (again.Found, again.RevokedTasks));
        Assert.Equal((false, 0), (missing.Found, missing.RevokedTasks));
        Assert.Equal(3, harness.Audit.Events.Count);
        Assert.Single(harness.Revocations.Stored);
    }

    [Fact]
    public async Task Revoking_an_agents_tasks_takes_every_live_task_and_its_descendants()
    {
        var harness = new Harness();

        var result = await harness.Build().RevokeAgentTasksAsync("jira-triage");

        Assert.Equal((true, 4), (result.Found, result.RevokedTasks));
        Assert.Equal("revoked", harness.Status("task_child"));
        Assert.Equal(["task_root", "task_other", "task_child", "task_grandchild"], harness.Audit.Events.Select(e => e.TaskId).OrderBy(id => id == "task_root" ? 0 : id == "task_other" ? 1 : id == "task_child" ? 2 : 3));
        Assert.Equal("parent_revoked", harness.Audit.Events.Single(e => e.TaskId == "task_child").Reason);
        Assert.Equal("operator_kill_switch", harness.Audit.Events.Single(e => e.TaskId == "task_other").Reason);
        Assert.Equal((true, 0), ((await harness.Build().RevokeAgentTasksAsync("jira-triage")).Found, (await harness.Build().RevokeAgentTasksAsync("jira-triage")).RevokedTasks));
        Assert.False((await harness.Build().RevokeAgentTasksAsync("nobody")).Found);
    }

    [Fact]
    public async Task An_agent_revoking_its_own_grant_revokes_the_tasks_tree_with_client_revoked()
    {
        var harness = new Harness();

        var error = await harness.Build().RevokeForClientAsync(Request(harness.GrantValues["task_root"], hint: "refresh_token"), []);

        Assert.Null(error);
        Assert.Equal(("revoked", "revoked", "revoked"), (harness.Status("task_root"), harness.Status("task_child"), harness.Status("task_grandchild")));
        Assert.Equal(["client_revoked", "parent_revoked", "parent_revoked"], harness.Audit.Events.Select(e => e.Reason));
        Assert.Equal(("task_root", "client_revoked", "jira-triage"), (harness.Revocations.Stored.Single().TaskId, harness.Revocations.Stored.Single().Reason, harness.Revocations.Stored.Single().RevokedBy));
    }

    [Theory]
    [InlineData("id_token")]
    [InlineData("access_token")]
    public async Task A_hint_that_does_not_fit_the_token_is_ignored_and_the_grant_is_still_revoked(string hint)
    {
        // RFC 7009 section 2.1: an unrecognised or wrong hint does not stop the search.
        var harness = new Harness();

        var error = await harness.Build().RevokeForClientAsync(Request(harness.GrantValues["task_other"], hint: hint), []);

        Assert.Null(error);
        Assert.Equal("revoked", harness.Status("task_other"));
    }

    [Fact]
    public async Task A_disabled_agent_may_still_revoke_its_own_grant_and_gets_the_same_empty_success()
    {
        var harness = new Harness { JiraTriage = ClientAuthTestData.Agent("jira-triage") with { Enabled = false } };
        var service = harness.Build();

        Assert.Null(await service.RevokeForClientAsync(Request(harness.GrantValues["task_other"]), []));
        Assert.Null(await service.RevokeForClientAsync(Request(harness.GrantValues["task_child"]), []));

        // Its own is revoked and recorded. Another agent's is left alone and recorded as a denial.
        Assert.Equal(("revoked", "active"), (harness.Status("task_other"), harness.Status("task_child")));
        Assert.Equal(
            [(AuditEvents.TaskRevoked, RevocationService.ClientRevoked), (AuditEvents.TokenDenied, RevocationService.NotOwner)],
            harness.Audit.Events.Select(e => (e.Event, e.Reason)));
    }

    [Fact]
    public async Task Another_agents_grant_a_garbage_token_and_an_unknown_grant_are_all_the_same_empty_success()
    {
        var harness = new Harness();
        var service = harness.Build();

        Assert.Null(await service.RevokeForClientAsync(Request(harness.GrantValues["task_child"], agentId: "jira-triage"), []));
        Assert.Null(await service.RevokeForClientAsync(Request("not-a-token"), []));
        Assert.Null(await service.RevokeForClientAsync(Request(TaskGrantSecret.New()), []));
        Assert.Null(await service.RevokeForClientAsync(Request(harness.TaskToken("task_child", "db-reader"), agentId: "jira-triage"), []));

        Assert.Equal("active", harness.Status("task_child"));
        Assert.Empty(harness.Revocations.Stored);
        Assert.Equal(4, harness.Audit.Events.Count);
        Assert.All(harness.Audit.Events, e => Assert.Equal((AuditEvents.TokenDenied, AuditDecision.Deny, RevocationService.NotOwner, "jira-triage"), (e.Event, e.Decision, e.Reason, e.AgentId)));
    }

    [Fact]
    public async Task An_agent_killing_its_own_delegated_task_gets_the_operator_reason_on_it_not_parent_revoked()
    {
        // db-reader's task_child was delegated from jira-triage's root, which stays alive; db-reader is the one named.
        var harness = new Harness();

        var result = await harness.Build().RevokeAgentTasksAsync("db-reader");

        Assert.Equal(2, result.RevokedTasks);
        Assert.Equal("active", harness.Status("task_root"));
        Assert.Equal(["operator_kill_switch", "parent_revoked"], harness.Audit.Events.Select(e => e.Reason));
        Assert.Equal(["task_child", "task_grandchild"], harness.Audit.Events.Select(e => e.TaskId));
        Assert.Equal("operator_kill_switch", harness.Tasks.Stored.Single(t => t.TaskId == "task_child").RevocationReason);
        Assert.Equal("parent_revoked", harness.Tasks.Stored.Single(t => t.TaskId == "task_grandchild").RevocationReason);
    }

    [Fact]
    public async Task An_agent_revoking_its_own_task_token_records_the_jti_once_and_leaves_the_task_alive()
    {
        var harness = new Harness();
        var service = harness.Build();
        var token = harness.TaskToken("task_root", "jira-triage", "tok_abc");

        Assert.Null(await service.RevokeForClientAsync(Request(token, hint: "access_token"), []));
        Assert.Null(await service.RevokeForClientAsync(Request(token), []));

        Assert.Equal("active", harness.Status("task_root"));
        var record = Assert.Single(harness.Revocations.Stored);
        Assert.Equal(("tok_abc", null, "client_revoked", "jira-triage", Now.AddMinutes(5)), (record.Jti, record.TaskId, record.Reason, record.RevokedBy, record.ExpiresAt));
        var audit = Assert.Single(harness.Audit.Events);
        Assert.Equal((AuditEvents.TokenRevoked, "task_root", "jira-triage", Human, "https://jira.internal", "jira:read", "tok_abc", 1, "client_revoked"), (audit.Event, audit.TaskId, audit.AgentId, audit.Sponsor, audit.Audience, audit.Scope, audit.Jti, audit.DelegationDepth, audit.Reason));
    }

    [Fact]
    public async Task A_token_signed_by_another_key_is_not_a_token_of_ours()
    {
        var harness = new Harness();
        using var otherKeys = SigningKeySet.CreateEphemeral();
        var task = harness.Tasks.Stored.Single(t => t.TaskId == "task_root");
        var forged = TaskTokenSerializer.Sign(otherKeys, TaskTokenClaims.Issue(Issuer, task, harness.JiraTriage, ["jira:read"], null, null, TimeSpan.FromMinutes(5), Now, "tok_forged"));

        Assert.Null(await harness.Build().RevokeForClientAsync(Request(forged), []));

        Assert.Empty(harness.Revocations.Stored);
        Assert.Equal(RevocationService.NotOwner, Assert.Single(harness.Audit.Events).Reason);
    }

    [Fact]
    public async Task Bad_requests_and_bad_clients_are_errors_with_a_denial_record()
    {
        var harness = new Harness();
        var service = harness.Build();

        var missing = await service.RevokeForClientAsync(new RevokeTokenRequest(null, null, null, null, null), []);
        Assert.Equal(OAuthErrorResponse.InvalidRequest, missing!.Error);

        var forged = await service.RevokeForClientAsync(new RevokeTokenRequest("x", null, Mint("RS256", "agent-key", ClientAuthTestData.Assertion(), rsa: Rsa1), RefreshTokenRequest.JwtBearerAssertionType, null), []);
        Assert.Equal(OAuthErrorResponse.InvalidClient, forged!.Error);

        Assert.Equal(["invalid_request", "actor_invalid_signature"], harness.Audit.Events.Select(e => e.Reason));
        Assert.All(harness.Audit.Events, e => Assert.Equal(AuditEvents.TokenDenied, e.Event));
    }
}

/// <summary>Tree revocation over the in-memory task list, following the storage contract: only active tasks flip, descendants at any depth, grants revoked.</summary>
internal sealed class InMemoryTaskRevocation(InMemoryTasks tasks, InMemoryGrants grants) : ITaskRevocation
{
    /// <summary>Every <see cref="HoldSponsorsAsync"/> call, in order.</summary>
    public List<IReadOnlyCollection<string>> Held { get; } = [];

    public Task HoldSponsorsAsync(IReadOnlyCollection<string> sponsorKeys, CancellationToken cancellationToken = default)
    {
        Held.Add(sponsorKeys);
        return Task.CompletedTask;
    }

    public Task<TaskRevocationOutcome> RevokeTreeAsync(string rootTaskId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default)
    {
        if (tasks.Stored.All(t => t.TaskId != rootTaskId)) return Task.FromResult(new TaskRevocationOutcome(false, []));
        return Task.FromResult(new TaskRevocationOutcome(true, Revoke([rootTaskId], at, reason)));
    }

    public Task<IReadOnlyList<RevokedTask>> RevokeAgentTasksAsync(string agentId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default) =>
        Task.FromResult(Revoke(tasks.Stored.Where(t => t.AgentId == agentId && t.Status == DelegationTaskStatus.Active).Select(t => t.TaskId).ToList(), at, reason));

    public Task<IReadOnlyList<RevokedTask>> RevokeSponsorTasksAsync(string sponsorKey, DateTimeOffset at, string reason, CancellationToken cancellationToken = default) =>
        Task.FromResult(Revoke(tasks.Stored.Where(t => t.SponsorKey == sponsorKey && t.Status == DelegationTaskStatus.Active).Select(t => t.TaskId).ToList(), at, reason));

    public Task<IReadOnlyList<RevokedTask>> RevokeSubjectTasksAsync(string subject, DateTimeOffset at, string reason, CancellationToken cancellationToken = default) =>
        Task.FromResult(Revoke(tasks.Stored.Where(t => t.Sponsor == subject && t.Status == DelegationTaskStatus.Active).Select(t => t.TaskId).ToList(), at, reason));

    public Task<IReadOnlyList<RevokedTask>> RevokeSessionTasksAsync(string sessionId, DateTimeOffset at, string reason, CancellationToken cancellationToken = default) =>
        Task.FromResult(Revoke(tasks.Stored.Where(t => t.SessionId == sessionId && t.Status == DelegationTaskStatus.Active).Select(t => t.TaskId).ToList(), at, reason));

    private IReadOnlyList<RevokedTask> Revoke(List<string> roots, DateTimeOffset at, string reason)
    {
        var tree = new List<string>();
        var frontier = new Queue<string>(roots);
        while (frontier.Count > 0)
        {
            var id = frontier.Dequeue();
            if (tree.Contains(id)) continue;
            tree.Add(id);
            foreach (var child in tasks.Stored.Where(t => t.ParentTaskId == id)) frontier.Enqueue(child.TaskId);
        }

        var revoked = new List<RevokedTask>();
        foreach (var id in tree)
        {
            var index = tasks.Stored.FindIndex(t => t.TaskId == id && t.Status == DelegationTaskStatus.Active);
            if (index < 0) continue;
            var task = tasks.Stored[index];
            var isRoot = roots.Contains(id);
            tasks.Stored[index] = task with { Status = DelegationTaskStatus.Revoked, RevokedAt = at, RevocationReason = isRoot ? reason : ITaskRevocation.ParentRevoked };
            for (var g = 0; g < grants.Stored.Count; g++)
            {
                if (grants.Stored[g].TaskId == id && grants.Stored[g].RevokedAt is null) grants.Stored[g] = grants.Stored[g] with { RevokedAt = at };
            }

            var renewals = grants.Stored.Where(g => g.TaskId == id).Sum(g => g.Renewals);
            revoked.Add(new RevokedTask(task.TaskId, task.AgentId, task.Sponsor, task.Audience, task.Scopes, task.DelegationDepth, task.ParentTaskId, isRoot, renewals));
        }

        return revoked;
    }
}

internal sealed class InMemoryRevocations : IRevocationRepository
{
    public List<SubactId.Core.Revocation.Revocation> Stored { get; } = [];

    public Task<bool> AddAsync(SubactId.Core.Revocation.Revocation revocation, CancellationToken cancellationToken = default)
    {
        if (revocation.Jti is not null && Stored.Any(r => r.Jti == revocation.Jti)) return Task.FromResult(false);
        Stored.Add(revocation);
        return Task.FromResult(true);
    }

    public Task<SubactId.Core.Revocation.Revocation?> FindTokenAsync(string jti, CancellationToken cancellationToken = default) => Task.FromResult(Stored.FirstOrDefault(r => r.Jti == jti));

    /// <summary>How many times an exchange asked whether its sign-in was signed out.</summary>
    public int SignOutChecks { get; private set; }

    /// <summary>Runs as an exchange asks, before the answer is read; stands in for a logout committing first.</summary>
    public Action? OnSignOutCheck { get; set; }

    public Task<bool> IsSignedOutAsync(SignIn signIn, CancellationToken cancellationToken = default)
    {
        SignOutChecks++;
        OnSignOutCheck?.Invoke();
        return Task.FromResult(Stored.Any(r =>
            (signIn.SessionId is not null && r.SessionId == signIn.SessionId)
            || (r.IssuedBefore is { } floor
                && (r.Subject == signIn.Subject || r.SponsorKey == signIn.SponsorKey)
                && (signIn.IssuedAt is not { } issuedAt || floor > issuedAt))));
    }

    /// <summary>The cutoff and batch size of each prune, in order.</summary>
    public List<(DateTimeOffset Before, int BatchSize)> Prunes { get; } = [];

    public Task<int> PruneSignOutsAsync(DateTimeOffset before, int batchSize, CancellationToken cancellationToken = default)
    {
        Prunes.Add((before, batchSize));
        var due = Stored
            .Where(r => (r.SessionId is not null || r.IssuedBefore is not null) && r.RevokedAt < before)
            .OrderBy(r => r.RevokedAt)
            .Take(batchSize)
            .ToList();
        foreach (var revocation in due)
        {
            Stored.Remove(revocation);
        }

        return Task.FromResult(due.Count);
    }
}
