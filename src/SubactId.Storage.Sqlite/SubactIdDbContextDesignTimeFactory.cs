using Microsoft.EntityFrameworkCore.Design;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Sqlite;

/// <summary>
/// Lets <c>dotnet ef migrations add</c> build the model without real configuration. The file
/// named here is never created.
/// </summary>
public sealed class SubactIdDbContextDesignTimeFactory : IDesignTimeDbContextFactory<SubactIdDbContext>
{
    /// <inheritdoc />
    public SubactIdDbContext CreateDbContext(string[] args) => SubactIdSqliteDbContextFactory.Create("subactid-design-time.db");
}
