namespace SubactId.Core.Storage;

/// <summary>
/// Runs work inside one storage transaction so a mutation and its audit record commit or
/// roll back together. Nested calls join the outer transaction.
/// </summary>
public interface IUnitOfWork
{
    /// <summary>Runs <paramref name="work"/> in a transaction, committing when it completes and rolling back when it throws.</summary>
    Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> work, CancellationToken cancellationToken = default);
}
