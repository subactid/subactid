namespace SubactId.Storage.Ef;

/// <summary>
/// The service key for the storage services readiness uses, kept apart from the ones requests use.
/// </summary>
/// <remarks>
/// A provider with a connection pool registers a small separate pool under this key, so a busy
/// request pool does not fail the readiness probe.
/// </remarks>
public static class StorageReadiness
{
    /// <summary>The service key readiness resolves its storage services under.</summary>
    public const string ServiceKey = "subactid-readiness";

    /// <summary>
    /// Maximum connections in the readiness pool. A probe takes two, so two probes can run at once.
    /// Nothing else uses the pool.
    /// </summary>
    public const int PoolSize = 4;
}
