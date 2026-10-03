using Microsoft.Extensions.Time.Testing;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Sponsors;
using SubactId.Core.Storage;
using SubactId.Server.Admin;
using SubactId.Server.Audit;
using SubactId.Server.Contracts;
using SubactId.UnitTests.Revocation;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Admin;

/// <summary>
/// A refused admin write is recorded even when the caller goes away after the refusal was decided:
/// the denial is not cancellable by the request, and the refusal still stands as the answer.
/// </summary>
public class AdminDenialCancellationTests
{
    private const string Human = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    private static readonly DateTimeOffset Now = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task A_refused_registration_is_recorded_when_the_caller_disconnects_after_the_insert_failed()
    {
        using var request = new CancellationTokenSource();
        var audit = new CancellationHonouringAudit();
        var service = new AgentAdminService(new DisconnectingAgents(request), new EmptyAgentQuery(), audit, new CommittingUnitOfWork(), AgentRegistrationLimits.Default, new FakeTimeProvider(Now));

        var registration = new RegisterAgentRequest("jira-triage", "Jira triage", null, ["jira:read"], ["https://jira.internal"], null, null, 1, null, "https://jira-triage.example/jwks.json", null);
        var result = await service.RegisterAsync(registration, request.Token);

        Assert.Equal(AdminFailure.AlreadyExists, result.Failure);
        var refused = Assert.Single(audit.Events);
        Assert.Equal((AuditEvents.AgentRegistered, "jira-triage", AuditDecision.Deny, AgentAdminService.AgentAlreadyExists), (refused.Event, refused.AgentId, refused.Decision, refused.Reason));
    }

    [Fact]
    public async Task A_refused_deletion_is_recorded_when_the_caller_disconnects_after_the_delete_failed()
    {
        using var request = new CancellationTokenSource();
        var audit = new CancellationHonouringAudit();
        var service = new AgentAdminService(new DisconnectingAgents(request), new EmptyAgentQuery(), audit, new CommittingUnitOfWork(), AgentRegistrationLimits.Default, new FakeTimeProvider(Now));

        var failure = await service.DeleteAsync("jira-triage", request.Token);

        Assert.Equal(AdminFailure.InUse, failure);
        var refused = Assert.Single(audit.Events);
        Assert.Equal((AuditEvents.AgentDeleted, "jira-triage", AuditDecision.Deny, AgentAdminService.AgentHasTasks), (refused.Event, refused.AgentId, refused.Decision, refused.Reason));
    }

    [Fact]
    public async Task A_refused_unblock_is_recorded_when_the_caller_disconnects_after_the_block_was_read()
    {
        using var request = new CancellationTokenSource();
        var audit = new CancellationHonouringAudit();
        var blocks = new DisconnectingSponsors(request, new SponsorBlock(Human, SponsorBlockSource.Scim, SponsorBlockKind.Disabled, Now.AddHours(-1)));
        var service = new SponsorAdminService(
            blocks,
            new InMemoryTaskRevocation(new InMemoryTasks(), new InMemoryGrants()),
            new InMemoryRevocations(),
            audit,
            new CommittingUnitOfWork(),
            new RenewalSummary(new DenialAggregationOptions()),
            new FakeTimeProvider(Now));

        var failure = await service.UnblockAsync(Human, request.Token);

        Assert.Equal(SponsorAdminFailure.NotOwned, failure);
        var refused = Assert.Single(audit.Events);
        Assert.Equal((AuditEvents.SponsorUnblocked, Human, AuditDecision.Deny, SponsorAdminService.SponsorBlockNotOwned), (refused.Event, refused.Sponsor, refused.Decision, refused.Reason));
    }

    /// <summary>An agent store whose writes fail as a conflict, with the caller going away at that moment.</summary>
    private sealed class DisconnectingAgents(CancellationTokenSource request) : IAgentRepository
    {
        public Task<Agent?> FindAsync(string agentId, CancellationToken cancellationToken = default) => Task.FromResult<Agent?>(null);

        public Task<Agent?> FindForUpdateAsync(string agentId, CancellationToken cancellationToken = default) => Task.FromResult<Agent?>(null);

        public Task AddAsync(Agent agent, CancellationToken cancellationToken = default)
        {
            request.Cancel();
            throw new DuplicateEntityException("agent", agent.AgentId);
        }

        public Task<bool> UpdateAsync(Agent agent, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<bool> DeleteAsync(string agentId, CancellationToken cancellationToken = default)
        {
            request.Cancel();
            throw new DependentEntitiesException("agent", agentId);
        }
    }

    /// <summary>A registry with nothing to list.</summary>
    private sealed class EmptyAgentQuery : IAgentQuery
    {
        public Task<TimeSpan?> LongestMaxTokenTtlAsync(CancellationToken cancellationToken = default) => Task.FromResult<TimeSpan?>(null);

        public Task<IReadOnlyList<Agent>> ListAsync(string? afterId, int limit, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<Agent>>([]);
    }

    /// <summary>A block store holding another source's block, with the caller going away once it is read.</summary>
    private sealed class DisconnectingSponsors(CancellationTokenSource request, SponsorBlock standing) : ISponsorRepository
    {
        public Task<SponsorBlock?> FindAsync(string sponsorKey, CancellationToken cancellationToken = default)
        {
            request.Cancel();
            return Task.FromResult<SponsorBlock?>(standing);
        }

        public Task<SponsorBlockWrite> BlockAsync(SponsorBlock block, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<bool> UnblockAsync(string sponsorKey, SponsorBlockSource source, bool unlessPlacedByDeletion = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task ForgetDeletionAsync(string sponsorKey, SponsorBlockSource source, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<bool> AdvanceSignalWatermarkAsync(string sponsorKey, DateTimeOffset eventAt, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    /// <summary>A ledger that, like the database, refuses a write whose token is cancelled.</summary>
    private sealed class CancellationHonouringAudit : IAuditWriter
    {
        public List<AuditEvent> Events { get; } = [];

        public Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.Add(auditEvent);
            return Task.FromResult((long)Events.Count);
        }

        public Task AppendAsync(IReadOnlyList<AuditEvent> auditEvents, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Events.AddRange(auditEvents);
            return Task.CompletedTask;
        }
    }

    /// <summary>A unit of work whose commit, like the database's, refuses a cancelled token.</summary>
    private sealed class CommittingUnitOfWork : IUnitOfWork
    {
        public async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> work, CancellationToken cancellationToken = default)
        {
            var result = await work(cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
    }
}
