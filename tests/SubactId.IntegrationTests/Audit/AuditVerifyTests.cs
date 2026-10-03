using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Server.Audit;
using SubactId.Server.Commands;
using SubactId.Server.Configuration;
using SubactId.Storage.Ef;
using SubactId.Storage.Ef.Repositories;
using SubactId.Tokens.Signing;
using Xunit;
using static SubactId.IntegrationTests.Repositories.RepositoryTestData;

namespace SubactId.IntegrationTests.Audit;

/// <summary>
/// Verification detects a tampered, missing or inserted row, a forged or unsigned checkpoint,
/// and a broken checkpoint chain. Uses its own database, because the command walks the whole ledger.
/// </summary>
public sealed class AuditVerifyTests : IAsyncLifetime
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
    public async Task The_seal_holds_across_rollback_holes_then_every_kind_of_tampering_inside_a_checkpoint_is_detected()
    {
        var agentId = UniqueId("verify");
        long first;
        await using (var db = postgres.CreateDbContext())
        {
            var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
            first = await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentRegistered, AgentId: agentId, Decision: AuditDecision.Allow));
            for (var i = 1; i <= 4; i++)
            {
                await writer.AppendAsync(new AuditEvent(Now.AddSeconds(i), AuditEvents.TokenDenied, $"task_{i}", agentId, "human", "https://jira.internal", "jira:read", Decision: AuditDecision.Deny, Reason: "invalid_scope"));
            }

            // A rolled-back append leaves a hole in the sequence. A checkpoint covers a range, so the
            // hole is inside it and must not count as a fault.
            await using (var transaction = await db.Database.BeginTransactionAsync())
            {
                await writer.AppendAsync(new AuditEvent(Now, AuditEvents.AgentDeleted, AgentId: agentId));
                await transaction.RollbackAsync();
            }

            await writer.AppendAsync(new AuditEvent(Now.AddSeconds(9), AuditEvents.AgentUpdated, AgentId: agentId));
        }

        await SealAsync();
        var (intact, mark) = await VerifyAsync();
        Assert.True(intact.IsIntact, $"{intact.Fault} at {intact.FaultCheckpointId}");
        Assert.Equal((1L, 6L), (intact.Verified, intact.SealedRecords));
        Assert.NotNull(mark);

        // The table owner lifts the append-only trigger and revoked privileges to simulate an attacker with the database.
        await TamperAsync($"UPDATE audit_events SET reason = 'invalid_target' WHERE seq = {first + 2}");
        Assert.Equal(AuditCheckpointFault.TamperedRecords, (await VerifyAsync()).Report.Fault);

        await TamperAsync($"UPDATE audit_events SET reason = 'invalid_scope' WHERE seq = {first + 2}");
        Assert.True((await VerifyAsync()).Report.IsIntact);

        // Removed: one leaf fewer than the signed tree size.
        await TamperAsync($"DELETE FROM audit_events WHERE seq = {first + 3}");
        Assert.Equal(AuditCheckpointFault.TamperedRecords, (await VerifyAsync()).Report.Fault);

        // And put back byte for byte, which a leaf count alone would miss.
        await TamperAsync(
            $"INSERT INTO audit_events (seq, ts, event, task_id, agent_id, sponsor, audience, scope, decision, reason) OVERRIDING SYSTEM VALUE "
            + $"VALUES ({first + 3}, '{Now.AddSeconds(3):yyyy-MM-dd HH:mm:ss.fff}+00', 'token.denied', 'task_3', '{agentId}', 'human', 'https://jira.internal', 'jira:read', 'deny', 'invalid_scope')");
        Assert.True((await VerifyAsync()).Report.IsIntact, "A record restored exactly as it was sealed should verify again.");

        // Inserted into the hole the rolled-back append left: a number inside a sealed range that
        // held nothing when the root was taken.
        await TamperAsync(
            $"INSERT INTO audit_events (seq, ts, event, agent_id, decision, reason) OVERRIDING SYSTEM VALUE "
            + $"VALUES ({first + 5}, '{Now:yyyy-MM-dd HH:mm:ss.fff}+00', 'token.issued', '{agentId}', 'allow', NULL)");
        Assert.Equal(AuditCheckpointFault.TamperedRecords, (await VerifyAsync()).Report.Fault);
    }

    [Fact]
    public async Task A_forged_checkpoint_and_a_broken_checkpoint_chain_are_both_caught()
    {
        await AppendAsync(UniqueId("forge"), 3);
        await SealAsync();
        await AppendAsync(UniqueId("forge"), 3);
        await SealAsync();

        Assert.True((await VerifyAsync()).Report.IsIntact);

        string root;
        await using (var db = postgres.CreateDbContext())
        {
            var second = (await new EfAuditCheckpointQuery(db).ReadAsync(0, 10))[1];
            root = Convert.ToHexStringLower(second.RootHash.Span);
        }

        // A root swapped for one this key never signed.
        await TamperCheckpointsAsync($"UPDATE audit_checkpoints SET root_hash = decode('{new string('0', 64)}', 'hex') WHERE checkpoint_id = 2");
        var forged = (await VerifyAsync()).Report;
        Assert.Equal((AuditCheckpointFault.BadSignature, 2L), (forged.Fault, forged.FaultCheckpointId));

        // Put back, so the next step tests the chain. The signature check runs first and would hide it.
        await TamperCheckpointsAsync($"UPDATE audit_checkpoints SET root_hash = decode('{root}', 'hex') WHERE checkpoint_id = 2");
        Assert.True((await VerifyAsync()).Report.IsIntact);

        // A checkpoint removed from the middle: the one after it no longer links to anything.
        await TamperCheckpointsAsync("DELETE FROM audit_checkpoints WHERE checkpoint_id = 1");
        var broken = (await VerifyAsync()).Report;
        Assert.Equal((AuditCheckpointFault.BrokenChain, 2L), (broken.Fault, broken.FaultCheckpointId));
    }

    /// <summary>
    /// Cutting the tail leaves a seal that verifies cleanly. Only a checkpoint kept from an earlier
    /// run, outside the database, can detect it.
    /// </summary>
    [Fact]
    public async Task A_cut_tail_walks_clean_and_only_the_mark_from_an_earlier_run_exposes_it()
    {
        await AppendAsync(UniqueId("tail"), 2);
        await SealAsync();
        await AppendAsync(UniqueId("tail"), 2);
        await SealAsync();
        var (_, mark) = await VerifyAsync();
        Assert.NotNull(mark);

        await TamperCheckpointsAsync("DELETE FROM audit_checkpoints WHERE checkpoint_id = 2");

        Assert.True((await VerifyAsync()).Report.IsIntact);
        var exposed = (await VerifyAsync(mark)).Report;
        Assert.Equal((AuditCheckpointFault.Truncated, mark!.CheckpointId), (exposed.Fault, exposed.FaultCheckpointId));
    }

    [Fact]
    public async Task The_command_prints_the_last_checkpoint_exits_zero_when_intact_three_when_broken_and_two_for_a_bad_mark()
    {
        await AppendAsync(UniqueId("cmd"), 2, sponsor: "human");
        await SealAsync();

        var options = Options();
        var output = new StringWriter();
        Assert.Equal(0, await AuditVerifyCommand.RunAsync(options, [], output));
        var text = output.ToString();
        Assert.StartsWith("Audit ledger intact: 1 checkpoint(s) verified sealing 2 record(s) up to seq 2, last checkpoint 1:", text, StringComparison.Ordinal);
        Assert.DoesNotContain("human", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Password", text, StringComparison.Ordinal);
        var mark = text.Split("last checkpoint ")[1].Trim().TrimEnd('.');

        Assert.Equal(0, await AuditVerifyCommand.RunAsync(options, [mark], new StringWriter()));
        Assert.Equal(AuditVerifyCommand.UsageExitCode, await AuditVerifyCommand.RunAsync(options, ["1:nothex"], new StringWriter()));

        await TamperAsync("UPDATE audit_events SET reason = 'edited' WHERE seq = 2");
        var broken = new StringWriter();
        Assert.Equal(AuditVerifyCommand.BrokenExitCode, await AuditVerifyCommand.RunAsync(options, [], broken));
        Assert.StartsWith("Audit ledger BROKEN at checkpoint 1:", broken.ToString(), StringComparison.Ordinal);
        Assert.Contains("a record was edited, removed or inserted", broken.ToString(), StringComparison.Ordinal);

        await TamperAsync("UPDATE audit_events SET reason = NULL WHERE seq = 2");
        await TamperCheckpointsAsync("DELETE FROM audit_checkpoints WHERE checkpoint_id = 1");
        Assert.Equal(0, await AuditVerifyCommand.RunAsync(options, [], new StringWriter()));
        var truncated = new StringWriter();
        Assert.Equal(AuditVerifyCommand.BrokenExitCode, await AuditVerifyCommand.RunAsync(options, [mark], truncated));
        Assert.Contains("tail cut or rewritten", truncated.ToString(), StringComparison.Ordinal);
    }

    /// <summary>Appends <paramref name="count"/> records for one agent, each its own transaction.</summary>
    private async Task AppendAsync(string agentId, int count, string? sponsor = null)
    {
        await using var db = postgres.CreateDbContext();
        var writer = new EfAuditWriter(db, new EfUnitOfWork(db, postgres.Dialect), postgres.Dialect);
        for (var i = 0; i < count; i++)
        {
            await writer.AppendAsync(new AuditEvent(Now.AddSeconds(i), AuditEvents.TokenIssued, $"task_{i}", agentId, sponsor, Decision: AuditDecision.Allow));
        }
    }

    /// <summary>One sealing pass, as the hosted service runs it.</summary>
    private async Task SealAsync()
    {
        using var keys = SigningKeys();
        await using var services = postgres.Services();
        var sealer = new AuditCheckpointSealer(
            services.GetRequiredService<IServiceScopeFactory>(),
            Options(),
            keys,
            TimeProvider.System,
            NullLogger<AuditCheckpointSealer>.Instance);

        await sealer.SealAsync();
    }

    private async Task<(AuditCheckpointReport Report, AuditCheckpointMark? Mark)> VerifyAsync(AuditCheckpointMark? expected = null)
    {
        await using var db = postgres.CreateDbContext();
        using var keys = SigningKeys();
        return await AuditVerifyCommand.VerifyAsync(
            new EfAuditCheckpointQuery(db),
            new EfAuditLedgerReader(db),
            new SigningKeyCheckpointSignatures(keys),
            expected is null ? null : [expected]);
    }

    private SigningKeySet SigningKeys() => SigningKeySetLoader.Load([new SigningKeySource(Kid: "verify-test", Pem: signingPem, Path: null)], activeKid: "verify-test");

    /// <summary>Runs <paramref name="sql"/> as the table owner with the ledger's append-only guards lifted, and always restores them.</summary>
    private Task TamperAsync(string sql) => TamperAsync("audit_events", "audit_events_no_update_or_delete", sql);

    /// <summary>The same, for the checkpoints, which are guarded like the ledger.</summary>
    private Task TamperCheckpointsAsync(string sql) => TamperAsync("audit_checkpoints", "audit_checkpoints_no_update_or_delete", sql);

    private async Task TamperAsync(string table, string trigger, string sql)
    {
        await using var connection = new NpgsqlConnection(postgres.ApplicationConnectionString);
        await connection.OpenAsync();
        await ExecuteAsync(connection, $"ALTER TABLE {table} DISABLE TRIGGER {trigger}");
        await ExecuteAsync(connection, $"GRANT UPDATE, DELETE ON {table} TO CURRENT_USER");
        try
        {
            await ExecuteAsync(connection, sql);
        }
        finally
        {
            await ExecuteAsync(connection, $"REVOKE UPDATE, DELETE ON {table} FROM CURRENT_USER");
            await ExecuteAsync(connection, $"ALTER TABLE {table} ENABLE TRIGGER {trigger}");
        }
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    private SubactIdOptions Options() => new()
    {
        Issuer = new Uri("https://subactid.internal.example.com"),
        UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
        Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = postgres.ApplicationConnectionString },
        Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromMinutes(30), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
        Agents = AgentRegistrationLimits.Default,
        Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 20 },
        Signing = new SigningOptions { Keys = [new ConfiguredSigningKey(0, new SigningKeySource(Kid: "verify-test", Pem: signingPem, Path: null))], ActiveKid = "verify-test" },
        Admin = new AdminOptions(),
        Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
    };
}
