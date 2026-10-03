using SubactId.Core.Storage;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>Transactions over the scoped <see cref="SubactIdDbContext"/>. Nested calls join the current transaction.</summary>
public sealed class EfUnitOfWork(SubactIdDbContext db, IStorageDialect dialect) : IUnitOfWork
{
    /// <inheritdoc />
    public async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> work, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(work);

        if (db.Database.CurrentTransaction is not null)
        {
            return await work(cancellationToken);
        }

        await using var transaction = await dialect.BeginTransactionAsync(db, cancellationToken);
        var result = await work(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return result;
    }
}
