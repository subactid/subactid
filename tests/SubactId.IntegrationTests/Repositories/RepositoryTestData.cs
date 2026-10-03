using SubactId.Core.Agents;
using SubactId.Core.Delegation;

namespace SubactId.IntegrationTests.Repositories;

/// <summary>Builders for test entities with unique ids.</summary>
internal static class RepositoryTestData
{
    public static readonly DateTimeOffset Now = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

    public static string UniqueId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..Math.Min(40, prefix.Length + 33)];

    public static Agent NewAgent(string? agentId = null) => new(
        agentId ?? UniqueId("agent"),
        "Jira triage agent",
        SponsorRequired: true,
        AllowedScopes: ["jira:read", "jira:comment", "confluence:read"],
        AllowedAudiences: ["https://jira.internal", "https://confluence.internal"],
        MaxTaskTtl: TimeSpan.FromMinutes(30),
        MaxTokenTtl: TimeSpan.FromMinutes(5),
        MaxDelegationDepth: 2,
        HighRiskAudiences: ["https://db.internal"],
        JwksUri: new Uri("https://jira-triage.agents.internal/.well-known/jwks.json"),
        Jwks: null,
        Enabled: true,
        CreatedAt: Now,
        UpdatedAt: Now);

    /// <summary>The human every seeded task acts for, and the key it is stored under.</summary>
    public const string Sponsor = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

    /// <param name="sponsor">The human, when a test needs its own. Tasks otherwise share a sponsor, so acting on a human would reach other tests' rows.</param>
    /// <param name="sessionId">The provider session the task came from, for a test about a logout.</param>
    public static DelegationTask NewTask(string agentId, string? taskId = null, string? parentTaskId = null, string? sponsor = null, string? sessionId = null) => new(
        taskId ?? UniqueId("task"),
        agentId,
        Sponsor: sponsor ?? Sponsor,
        SponsorKey: sponsor ?? Sponsor,
        SessionId: sessionId,
        ParentTaskId: parentTaskId,
        DelegationDepth: parentTaskId is null ? 1 : 2,
        Audience: "https://jira.internal",
        Scopes: ["jira:read", "jira:comment"],
        Status: DelegationTaskStatus.Active,
        CreatedAt: Now,
        ExpiresAt: Now.AddMinutes(30),
        RevokedAt: null,
        RevocationReason: null);

    /// <summary>The scopes every seeded grant holds.</summary>
    public static readonly IReadOnlyList<string> GrantScopes = ["jira:read"];

    public static TaskGrant NewGrant(string agentId, string taskId) => new(
        Guid.NewGuid().ToByteArray().Concat(Guid.NewGuid().ToByteArray()).ToArray(),
        taskId,
        agentId,
        Scopes: GrantScopes,
        CreatedAt: Now,
        ExpiresAt: Now.AddMinutes(30),
        RevokedAt: null,
        LastUsedAt: null);
}
