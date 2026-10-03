using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.IntegrationTests.Admin;
using SubactId.IntegrationTests.Endpoints;
using SubactId.Server.Audit;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef.Repositories;
using SubactId.Tokens.Signing;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

/// <summary>
/// Spec section 7.1 over HTTP: checkpoints are paged, a sealed record's proof folds to the root
/// its checkpoint signed, and anything that is not a sealed record (unsealed, past the end, or a
/// hole left by a rolled-back append) is a <c>404</c>.
/// </summary>
[Collection(PostgresCollection.Name)]
public class AuditCheckpointEndpointTests(PostgresDatabaseFixture postgres) : IAsyncLifetime
{
    private DatabaseServerFactory factory = null!;
    private HttpClient client = null!;

    public async Task InitializeAsync()
    {
        await postgres.EnsureMigratedAsync();
        factory = new DatabaseServerFactory(postgres);
        client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);
    }

    public async Task DisposeAsync()
    {
        client.Dispose();
        await factory.DisposeAsync();
    }

    [Fact]
    public async Task The_checkpoints_are_published_in_pages_and_every_sealed_record_proves_itself_into_its_root()
    {
        var agentId = UniqueId("proof");
        var sealedSeqs = await AppendAsync(agentId, 3);
        await SealAsync();

        // A number taken by a rolled-back append: inside the next checkpoint's range, held by no record.
        long hole;
        await using (var db = postgres.CreateDbContext())
        {
            var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
            await using var transaction = await db.Database.BeginTransactionAsync();
            hole = await writer.AppendAsync(new AuditEvent(Now, AuditEvents.TokenIssued, "task_rolled_back", agentId, "human", Decision: AuditDecision.Allow));
            await transaction.RollbackAsync();
        }

        sealedSeqs.AddRange(await AppendAsync(agentId, 2));
        await SealAsync();
        var unsealed = (await AppendAsync(agentId, 1))[0];

        // Paged a checkpoint at a time, oldest first, and the pages run on from each other.
        var checkpoints = new List<JsonElement>();
        long? after = null;
        do
        {
            using var response = await client.GetAsync(after is null ? "/audit/checkpoints?limit=1" : $"/audit/checkpoints?limit=1&after={after}");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
            var page = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(["checkpoints", "next_after"], page.EnumerateObject().Select(p => p.Name));
            var one = Assert.Single(page.GetProperty("checkpoints").EnumerateArray());
            checkpoints.Add(one.Clone());
            var next = page.GetProperty("next_after");
            after = next.ValueKind == JsonValueKind.Null ? null : next.GetInt64();
            if (after is { } id)
            {
                Assert.Equal(one.GetProperty("checkpoint_id").GetInt64(), id);
            }
        }
        while (after is not null);

        Assert.True(checkpoints.Count >= 2, "Two sealing passes over new records should have written at least two checkpoints.");
        for (var i = 1; i < checkpoints.Count; i++)
        {
            Assert.True(checkpoints[i].GetProperty("checkpoint_id").GetInt64() > checkpoints[i - 1].GetProperty("checkpoint_id").GetInt64(), "Checkpoints came back out of id order.");
            Assert.Equal(checkpoints[i - 1].GetProperty("last_seq").GetInt64() + 1, checkpoints[i].GetProperty("first_seq").GetInt64());
        }

        var byId = checkpoints.ToDictionary(c => c.GetProperty("checkpoint_id").GetInt64());
        IReadOnlyList<AuditLedgerRecord> records;
        await using (var db = postgres.CreateDbContext())
        {
            records = await new EfAuditLedgerReader(db).ReadBySeqAsync(sealedSeqs);
        }

        Assert.Equal(sealedSeqs.Count, records.Count);
        foreach (var record in records)
        {
            using var response = await client.GetAsync($"/audit/records/{record.Seq}/proof");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var proof = await response.Content.ReadFromJsonAsync<JsonElement>();
            Assert.Equal(["seq", "checkpoint", "leaf_index", "audit_path"], proof.EnumerateObject().Select(p => p.Name));
            Assert.Equal(record.Seq, proof.GetProperty("seq").GetInt64());

            // The checkpoint in the proof is the published one, field for field.
            var checkpoint = proof.GetProperty("checkpoint");
            var published = byId[checkpoint.GetProperty("checkpoint_id").GetInt64()];
            Assert.True(JsonElement.DeepEquals(published, checkpoint), $"The proof for {record.Seq} carries a checkpoint that differs from the published one.");
            Assert.InRange(record.Seq, published.GetProperty("first_seq").GetInt64(), published.GetProperty("last_seq").GetInt64());

            // And the path, folded over the leaf rebuilt from the record, reaches the signed root.
            var path = proof.GetProperty("audit_path").EnumerateArray().Select(step => Convert.FromHexString(step.GetString()!)).ToList();
            var root = MerkleTree.RootFromPath(AuditCheckpointHash.Leaf(record.Event), proof.GetProperty("leaf_index").GetInt64(), published.GetProperty("tree_size").GetInt64(), path);
            Assert.NotNull(root);
            Assert.Equal(published.GetProperty("root_hash").GetString(), Convert.ToHexStringLower(root!));
        }

        // The audit query agrees on which checkpoint seals each record, and that the last one is not
        // sealed yet.
        using var query = await client.GetAsync($"/audit?agent_id={agentId}");
        var listed = (await query.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("records").EnumerateArray().ToDictionary(r => r.GetProperty("seq").GetInt64());
        foreach (var seq in sealedSeqs)
        {
            Assert.True(byId.ContainsKey(listed[seq].GetProperty("checkpoint").GetInt64()), $"Record {seq} names a checkpoint the listing did not publish.");
        }

        Assert.Equal(JsonValueKind.Null, listed[unsealed].GetProperty("checkpoint").ValueKind);

        // No proof for anything that is not a sealed record. A hole inside a sealed range is a 404, not a fault.
        using var forHole = await client.GetAsync($"/audit/records/{hole}/proof");
        Assert.Equal(HttpStatusCode.NotFound, forHole.StatusCode);
        using var forUnsealed = await client.GetAsync($"/audit/records/{unsealed}/proof");
        Assert.Equal(HttpStatusCode.NotFound, forUnsealed.StatusCode);
        using var forNothing = await client.GetAsync($"/audit/records/{unsealed + 1_000_000}/proof");
        Assert.Equal(HttpStatusCode.NotFound, forNothing.StatusCode);
        using var forZero = await client.GetAsync("/audit/records/0/proof");
        Assert.Equal(HttpStatusCode.BadRequest, forZero.StatusCode);
    }

    [Fact]
    public async Task A_bad_page_request_answers_every_field_error_at_once()
    {
        using var response = await client.GetAsync("/audit/checkpoints?after=-1&limit=0");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(["after", "limit"], body.GetProperty("errors").EnumerateObject().Select(p => p.Name));
    }

    [Fact]
    public async Task Both_endpoints_need_the_admin_key_and_a_refusal_is_audited()
    {
        using var anonymous = factory.CreateClient();

        using var checkpoints = await anonymous.GetAsync("/audit/checkpoints");
        Assert.Equal(HttpStatusCode.Unauthorized, checkpoints.StatusCode);
        using var proof = await anonymous.GetAsync("/audit/records/1/proof");
        Assert.Equal(HttpStatusCode.Unauthorized, proof.StatusCode);
        Assert.Equal("Bearer realm=\"subactid-admin\"", proof.Headers.WwwAuthenticate.ToString());

        // One record or two: a denial that names nobody is written once per reason per window and
        // counted after that. Either way the latest record is the refusal.
        await using var db = postgres.CreateDbContext();
        var latest = await db.AuditEvents.AsNoTracking().OrderByDescending(e => e.Seq).FirstAsync();
        Assert.Equal((AuditEvents.AdminDenied, "deny", "missing_api_key"), (latest.Event, latest.Decision, latest.Reason));
    }

    /// <summary>Appends <paramref name="count"/> records for one agent, each its own transaction, and returns their sequence numbers.</summary>
    private async Task<List<long>> AppendAsync(string agentId, int count)
    {
        await using var db = postgres.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
        var seqs = new List<long>(count);
        for (var i = 0; i < count; i++)
        {
            seqs.Add(await writer.AppendAsync(new AuditEvent(Now.AddSeconds(seqs.Count), AuditEvents.TokenIssued, $"task_{agentId}_{i}", agentId, "human", Decision: AuditDecision.Allow)));
        }

        return seqs;
    }

    /// <summary>One sealing pass with the server's own key, as the hosted service runs it.</summary>
    private async Task SealAsync()
    {
        using var keys = SigningKeySetLoader.Load([new SigningKeySource(Kid: "test-key", Pem: ServerFactory.SigningKeyPem, Path: null)], activeKid: "test-key");
        await using var services = postgres.Services();
        var sealer = new AuditCheckpointSealer(
            services.GetRequiredService<IServiceScopeFactory>(),
            Options(),
            keys,
            TimeProvider.System,
            NullLogger<AuditCheckpointSealer>.Instance);

        await sealer.SealAsync();
    }

    private SubactIdOptions Options() => new()
    {
        Issuer = new Uri("https://subactid.internal.example.com"),
        UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
        Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = postgres.ApplicationConnectionString },
        Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromMinutes(30), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
        Agents = AgentRegistrationLimits.Default,
        Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 20 },
        Signing = new SigningOptions { Keys = [new ConfiguredSigningKey(0, new SigningKeySource(Kid: "test-key", Pem: ServerFactory.SigningKeyPem, Path: null))], ActiveKid = "test-key" },
        Admin = new AdminOptions(),
        Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
    };
}
