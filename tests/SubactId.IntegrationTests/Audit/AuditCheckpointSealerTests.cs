using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Commands;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef.Repositories;
using SubactId.Tokens.Signing;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

/// <summary>
/// The sealing pass. Each test gets its own database, because a pass covers everything ever written.
/// </summary>
public sealed class AuditCheckpointSealerTests : IAsyncLifetime
{
    private readonly PostgresDatabaseFixture postgres = new();
    private readonly string signingPem = ECDsa.Create(ECCurve.NamedCurves.nistP256).ExportPkcs8PrivateKeyPem();

    public async Task InitializeAsync()
    {
        await postgres.InitializeAsync();
        await postgres.EnsureMigratedAsync();
    }

    public Task DisposeAsync() => postgres.DisposeAsync();

    [Fact]
    public async Task A_pass_seals_every_record_written_before_it_and_the_next_one_carries_on_where_it_stopped()
    {
        await AppendAsync("first", 3);

        Assert.Equal((1, 3L), await SealAsync());

        await using (var db = postgres.CreateDbContext())
        {
            var checkpoint = Assert.Single(await new EfAuditCheckpointQuery(db).ReadAsync(0, 10));
            Assert.Equal((1L, 1L, 3L, 3L), (checkpoint.CheckpointId, checkpoint.FirstSeq, checkpoint.LastSeq, checkpoint.TreeSize));
            Assert.Null(checkpoint.PrevCheckpointHash);
            Assert.Equal("seal-test", checkpoint.Kid);
        }

        // Nothing new to seal, so no checkpoint is written.
        Assert.Equal((0, 0L), await SealAsync());

        await AppendAsync("second", 2);
        Assert.Equal((1, 2L), await SealAsync());

        await using (var db = postgres.CreateDbContext())
        {
            var checkpoints = await new EfAuditCheckpointQuery(db).ReadAsync(0, 10);
            Assert.Equal(2, checkpoints.Count);

            // The second range starts where the first ended and links to it by the hash of its signed
            // bytes, so no record is sealed twice or not at all.
            Assert.Equal(checkpoints[0].LastSeq + 1, checkpoints[1].FirstSeq);
            Assert.Equal(AuditCheckpointHash.LinkHash(checkpoints[0]), checkpoints[1].PrevCheckpointHash!.Value.ToArray());
        }

        Assert.True((await VerifyAsync()).Report.IsIntact);
    }

    /// <summary>
    /// A sequence number is taken at <c>INSERT</c> but becomes visible only at <c>COMMIT</c>. Without
    /// the seal fence, a pass could seal a range around an append still in flight and leave that
    /// record outside the tree. Here one append is held open at a low number while a later one
    /// commits above it, and the pass must wait for the open one.
    /// </summary>
    [Fact]
    public async Task A_pass_waits_for_an_append_still_in_flight_beneath_the_mark_it_would_seal()
    {
        await AppendAsync("settled", 2);

        await using var slow = postgres.CreateDbContext();
        var slowWriter = new EfAuditWriter(slow, new EfUnitOfWork(slow, postgres.Dialect), postgres.Dialect);
        await using var held = await postgres.Dialect.BeginTransactionAsync(slow, CancellationToken.None);

        // Takes its sequence number, and the seal fence with it, but does not commit.
        var heldSeq = await slowWriter.AppendAsync(new AuditEvent(Now.AddSeconds(3), AuditEvents.TokenIssued, "task_held", "agent_held", "human", Decision: AuditDecision.Allow));

        // Committed above it, so the ledger's visible maximum is already past the held record.
        await AppendAsync("after", 1);

        var pass = Task.Run(() => SealAsync());
        var finishedEarly = await Task.WhenAny(pass, Task.Delay(TimeSpan.FromSeconds(2))) == pass;
        Assert.False(finishedEarly, "The pass sealed while an append below its high-water mark was still in flight; the fence did not hold.");

        await held.CommitAsync();
        var (checkpoints, records) = await pass;

        Assert.Equal((1, 4L), (checkpoints, records));
        await using (var db = postgres.CreateDbContext())
        {
            var checkpoint = Assert.Single(await new EfAuditCheckpointQuery(db).ReadAsync(0, 10));
            Assert.True(checkpoint.LastSeq >= heldSeq, "The record that committed late is not inside the range that was sealed.");
        }

        // The held record is sealed, and everything verifies.
        Assert.True((await VerifyAsync()).Report.IsIntact);
        await using (var db = postgres.CreateDbContext())
        {
            Assert.NotNull(await new EfAuditCheckpointQuery(db).SealingAsync(heldSeq));
        }
    }

    /// <summary>
    /// A range with more records than one checkpoint holds is sealed as several checkpoints, which
    /// still run on from each other and chain. Verification is unchanged.
    /// </summary>
    [Fact]
    public async Task A_range_larger_than_one_checkpoint_is_sealed_as_several_that_still_chain()
    {
        await AppendAsync("bulk", 7);

        var (checkpoints, records) = await SealAsync(maxRecords: 3);

        Assert.Equal((3, 7L), (checkpoints, records));
        await using (var db = postgres.CreateDbContext())
        {
            var written = await new EfAuditCheckpointQuery(db).ReadAsync(0, 10);
            Assert.Equal(new[] { 3L, 3L, 1L }, written.Select(c => c.TreeSize).ToArray());

            // Still one continuous cover: each range starts where the last ended and links to the one before it.
            Assert.Equal(1L, written[0].FirstSeq);
            for (var i = 1; i < written.Count; i++)
            {
                Assert.Equal(written[i - 1].LastSeq + 1, written[i].FirstSeq);
                Assert.Equal(AuditCheckpointHash.LinkHash(written[i - 1]), written[i].PrevCheckpointHash!.Value.ToArray());
            }
        }

        Assert.True((await VerifyAsync()).Report.IsIntact);
    }

    [Fact]
    public async Task A_records_checkpoint_is_null_until_a_pass_reaches_it_and_its_id_afterwards()
    {
        await AppendAsync("published", 1);
        long seq;
        await using (var db = postgres.CreateDbContext())
        {
            seq = await db.AuditEvents.AsNoTracking().MaxAsync(e => e.Seq);
            Assert.Null(await new EfAuditCheckpointQuery(db).SealingAsync(seq));
        }

        await SealAsync();

        await using (var db = postgres.CreateDbContext())
        {
            var checkpoint = await new EfAuditCheckpointQuery(db).SealingAsync(seq);
            Assert.Equal(1L, checkpoint!.CheckpointId);

            // The batch lookup the audit query uses answers the same thing for a page of records.
            var page = await new EfAuditCheckpointQuery(db).SealingAsync([seq]);
            Assert.Equal(1L, page[seq]);
        }
    }

    [Fact]
    public async Task The_batch_lookup_finds_each_records_checkpoint_across_several_and_skips_the_unsealed()
    {
        // Three checkpoints: records 1-2, 3-5 and 6-7. Record 8 is not sealed yet.
        await AppendAsync("a", 2);
        await SealAsync();
        await AppendAsync("b", 3);
        await SealAsync();
        await AppendAsync("c", 2);
        await SealAsync();
        await AppendAsync("d", 1);

        await using var db = postgres.CreateDbContext();
        var page = await new EfAuditCheckpointQuery(db).SealingAsync([6, 1, 8, 4, 6, 5, 3]);

        Assert.Equal(
            new Dictionary<long, long> { [1] = 1, [3] = 2, [4] = 2, [5] = 2, [6] = 3 },
            page.OrderBy(p => p.Key).ToDictionary());
    }

    private async Task AppendAsync(string marker, int count)
    {
        await using var db = postgres.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
        for (var i = 0; i < count; i++)
        {
            await writer.AppendAsync(new AuditEvent(Now.AddSeconds(i), AuditEvents.TokenIssued, $"task_{marker}_{i}", $"agent_{marker}", "human", Decision: AuditDecision.Allow));
        }
    }

    private async Task<(int Checkpoints, long Records)> SealAsync(int? maxRecords = null)
    {
        using var keys = SigningKeys();
        await using var services = postgres.Services();
        var sealer = new AuditCheckpointSealer(
            services.GetRequiredService<IServiceScopeFactory>(),
            Options(),
            keys,
            TimeProvider.System,
            NullLogger<AuditCheckpointSealer>.Instance)
        {
            MaxRecords = maxRecords ?? AuditCheckpointSealer.MaxRecordsPerCheckpoint,
        };

        return await sealer.SealAsync();
    }

    private async Task<(AuditCheckpointReport Report, AuditCheckpointMark? Mark)> VerifyAsync()
    {
        await using var db = postgres.CreateDbContext();
        using var keys = SigningKeys();
        return await AuditVerifyCommand.VerifyAsync(new EfAuditCheckpointQuery(db), new EfAuditLedgerReader(db), new SigningKeyCheckpointSignatures(keys));
    }

    private SigningKeySet SigningKeys() => SigningKeySetLoader.Load([new SigningKeySource(Kid: "seal-test", Pem: signingPem, Path: null)], activeKid: "seal-test");

    private SubactIdOptions Options() => new()
    {
        Issuer = new Uri("https://subactid.internal.example.com"),
        UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
        Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = postgres.ApplicationConnectionString },
        Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromMinutes(30), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
        Agents = AgentRegistrationLimits.Default,
        Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 20 },
        Signing = new SigningOptions { Keys = [new ConfiguredSigningKey(0, new SigningKeySource(Kid: "seal-test", Pem: signingPem, Path: null))], ActiveKid = "seal-test" },
        Admin = new AdminOptions(),
        Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
    };
}
