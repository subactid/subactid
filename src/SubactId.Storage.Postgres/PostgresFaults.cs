using Npgsql;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Postgres;

/// <summary>
/// Postgres faults Npgsql considers transient: connection failures, timeouts, pool exhaustion,
/// restart or failover states, deadlocks and serialization failures. The whole exception chain is
/// checked, since EF Core wraps driver exceptions.
/// </summary>
public sealed class PostgresFaults : IStorageFaults
{
    /// <inheritdoc />
    public bool IsUnavailable(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is NpgsqlException { IsTransient: true })
            {
                return true;
            }
        }

        return false;
    }
}
