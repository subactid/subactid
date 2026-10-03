namespace SubactId.Storage.Ef;

/// <summary>
/// Tells transient database faults (connection refused, failover, pool timeout, a transaction
/// aborted for retry) apart from other errors. Each provider registers its own.
/// </summary>
/// <remarks>
/// A transient fault is answered as retryable. Anything else stays a 500.
/// </remarks>
public interface IStorageFaults
{
    /// <summary>Whether <paramref name="exception"/>, or anything it wraps, means the database is unavailable or busy.</summary>
    /// <param name="exception">What the request threw.</param>
    bool IsUnavailable(Exception exception);
}
