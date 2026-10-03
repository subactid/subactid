using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using SubactId.Storage.Ef;
using SubactId.Storage.Postgres;
using SubactId.Storage.Sqlite;
using Xunit;

namespace SubactId.UnitTests.Storage;

/// <summary>
/// Which storage faults a caller is told to retry: an unreachable database, but not a fault in
/// the request or the server.
/// </summary>
public class StorageFaultsTests
{
    [Fact]
    public async Task A_database_nobody_is_listening_for_is_unavailable()
    {
        await using var dataSource = new NpgsqlDataSourceBuilder(PostgresHealthCheckTests.UnreachableConnectionString()).Build();

        var refused = await Assert.ThrowsAnyAsync<Exception>(async () => await dataSource.OpenConnectionAsync());

        Assert.True(new PostgresFaults().IsUnavailable(refused));
    }

    [Fact]
    public void Unavailability_is_found_however_deeply_it_is_wrapped()
    {
        // EF Core wraps what the driver throws, sometimes twice.
        var driver = new NpgsqlException("The operation has timed out", new TimeoutException());
        var wrapped = new InvalidOperationException("outer", new InvalidOperationException("middle", driver));

        Assert.True(new PostgresFaults().IsUnavailable(wrapped));
    }

    [Theory]
    [InlineData("57P01")] // admin_shutdown: the server is stopping
    [InlineData("57P03")] // cannot_connect_now: the server is starting or in recovery
    [InlineData("53300")] // too_many_connections
    public void A_server_that_is_restarting_or_full_is_unavailable(string sqlState)
    {
        var fault = new PostgresException("down", "FATAL", "FATAL", sqlState);

        Assert.True(new PostgresFaults().IsUnavailable(fault));
    }

    [Theory]
    [InlineData("23505")] // unique_violation
    [InlineData("42P01")] // undefined_table
    [InlineData("22001")] // string_data_right_truncation
    public void A_fault_in_the_request_or_the_schema_is_not(string sqlState)
    {
        var fault = new PostgresException("wrong", "ERROR", "ERROR", sqlState);

        Assert.False(new PostgresFaults().IsUnavailable(fault));
    }

    [Fact]
    public void A_fault_that_is_not_the_driver_is_not()
    {
        Assert.False(new PostgresFaults().IsUnavailable(new InvalidOperationException("a bug")));
        Assert.False(new PostgresFaults().IsUnavailable(new TimeoutException("not from the database")));
    }

    [Theory]
    [InlineData(5, true)] // SQLITE_BUSY
    [InlineData(6, true)] // SQLITE_LOCKED
    [InlineData(19, false)] // SQLITE_CONSTRAINT
    [InlineData(1, false)] // SQLITE_ERROR
    public void An_embedded_database_is_unavailable_only_while_busy_or_locked(int code, bool unavailable)
    {
        Assert.Equal(unavailable, new SqliteFaults().IsUnavailable(new SqliteException("sqlite", code)));
    }

    [Fact]
    public async Task Readiness_has_a_small_pool_of_its_own()
    {
        const string connectionString = "Host=db.example.test;Username=subactid;Password=x;Database=subactid;Maximum Pool Size=100";
        await using var provider = new ServiceCollection().AddLogging().AddPostgresStorage(connectionString).BuildServiceProvider();

        var requests = provider.GetRequiredService<NpgsqlDataSource>();
        var readiness = provider.GetRequiredKeyedService<NpgsqlDataSource>(StorageReadiness.ServiceKey);

        Assert.NotSame(requests, readiness);
        Assert.Equal(StorageReadiness.PoolSize, new NpgsqlConnectionStringBuilder(readiness.ConnectionString).MaxPoolSize);
        Assert.Equal(100, new NpgsqlConnectionStringBuilder(requests.ConnectionString).MaxPoolSize);
    }
}
