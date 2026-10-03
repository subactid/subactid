using Microsoft.Data.Sqlite;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Sqlite;

/// <summary>
/// Treats SQLite busy and locked errors as transient. Nothing else is retried.
/// </summary>
public sealed class SqliteFaults : IStorageFaults
{
    private const int Busy = 5;
    private const int Locked = 6;

    /// <inheritdoc />
    public bool IsUnavailable(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is SqliteException { SqliteErrorCode: Busy or Locked })
            {
                return true;
            }
        }

        return false;
    }
}
