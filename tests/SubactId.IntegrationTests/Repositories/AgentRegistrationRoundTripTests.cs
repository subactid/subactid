using System.Text.Json;
using SubactId.Core.Agents;
using SubactId.IntegrationTests.Storage;
using SubactId.Server.Contracts;
using SubactId.Storage.Ef.Repositories;
using SubactId.Storage.Postgres.Repositories;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Repositories;

public abstract class AgentRegistrationRoundTripTests(IStorageFixture storage)
{
    [Fact]
    public async Task A_registration_payload_round_trips_through_storage_unchanged()
    {
        await storage.EnsureMigratedAsync();
        var agentId = UniqueId("jira-triage");
        var payload = $$"""
            {
              "agent_id": "{{agentId}}",
              "display_name": "Jira triage agent",
              "sponsor_required": true,
              "allowed_scopes": ["jira:read", "jira:comment", "confluence:read"],
              "allowed_audiences": ["https://jira.internal", "https://confluence.internal"],
              "max_task_ttl": "PT30M",
              "max_token_ttl": "PT5M",
              "max_delegation_depth": 2,
              "high_risk_audiences": ["https://db.internal"],
              "jwks_uri": "https://jira-triage.agents.internal/.well-known/jwks.json"
            }
            """;
        var request = JsonSerializer.Deserialize<RegisterAgentRequest>(payload, SubactIdJson.CreateOptions())!;
        Assert.Empty(request.TryToAgent(AgentRegistrationLimits.Default, Now, out var agent));

        await using (var db = storage.CreateDbContext())
        {
            await new EfAgentRepository(db, storage.Dialect).AddAsync(agent!);
        }

        await using var read = storage.CreateDbContext();
        var stored = await new EfAgentRepository(read, storage.Dialect).FindAsync(agentId);

        Assert.NotNull(stored);
        Assert.Equal(agent! with { AllowedScopes = [], AllowedAudiences = [], HighRiskAudiences = [] },
            stored with { AllowedScopes = [], AllowedAudiences = [], HighRiskAudiences = [] });
        Assert.Equal(agent.AllowedScopes, stored.AllowedScopes);
        Assert.Equal(agent.AllowedAudiences, stored.AllowedAudiences);
        Assert.Equal(agent.HighRiskAudiences, stored.HighRiskAudiences);
        Assert.Empty(AgentValidator.Validate(stored, AgentRegistrationLimits.Default));
    }
}

/// <summary>The same tests against Postgres.</summary>
[Collection(PostgresCollection.Name)]
public sealed class PostgresAgentRegistrationRoundTripTests(PostgresDatabaseFixture storage) : AgentRegistrationRoundTripTests(storage);

/// <summary>The same tests against the embedded database.</summary>
[Collection(SqliteCollection.Name)]
public sealed class SqliteAgentRegistrationRoundTripTests(SqliteDatabaseFixture storage) : AgentRegistrationRoundTripTests(storage);
