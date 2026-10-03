using Microsoft.EntityFrameworkCore.Design;
using SubactId.Storage.Ef;

namespace SubactId.Storage.Postgres;

/// <summary>
/// Lets <c>dotnet ef migrations add</c> build the model without a server or real configuration.
/// The connection string is a placeholder and is never opened.
/// </summary>
public sealed class SubactIdDbContextDesignTimeFactory : IDesignTimeDbContextFactory<SubactIdDbContext>
{
    /// <inheritdoc />
    public SubactIdDbContext CreateDbContext(string[] args) => SubactIdDbContextFactory.Create("Host=localhost;Database=subactid_design_time");
}
