using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Revocation;
using SubactId.Storage.Ef;

namespace SubactId.IntegrationTests.Storage;

/// <summary>
/// A migrated database for repository tests. Every test written against it runs once per provider.
/// </summary>
public interface IStorageFixture
{
    /// <summary>The dialect of this database.</summary>
    IStorageDialect Dialect { get; }

    /// <summary>Applies the migrations once per fixture.</summary>
    Task EnsureMigratedAsync();

    /// <summary>A fresh context on the test database.</summary>
    SubactIdDbContext CreateDbContext();

    /// <summary>This provider's expiry sweep.</summary>
    ITaskExpirySweep ExpirySweep(SubactIdDbContext db);

    /// <summary>This provider's revocation walk.</summary>
    ITaskRevocation Revocation(SubactIdDbContext db);

    /// <summary>This provider's outbox.</summary>
    IAuditOutboxQueue OutboxQueue(SubactIdDbContext db);
}
