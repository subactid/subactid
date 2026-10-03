using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using SubactId.IntegrationTests.Endpoints;

namespace SubactId.IntegrationTests.Admin;

/// <summary>The in-process server, pointed at the test database.</summary>
public class DatabaseServerFactory(PostgresDatabaseFixture postgres) : ServerFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<NpgsqlDataSource>();
            services.AddSingleton(_ => new NpgsqlDataSourceBuilder(postgres.ApplicationConnectionString).Build());
        });
    }
}
