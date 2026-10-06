using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SubactId.Server.Hosting;
using SubactId.Storage.Ef;
using SubactId.Storage.Postgres;
using Xunit;

namespace SubactId.UnitTests.Hosting;

/// <summary>
/// What a caller is told when a request throws. An unreachable database is a retryable 503 with
/// the spec's error body. Anything else is a 500 with no detail, since retrying a bug never helps.
/// </summary>
public class UnhandledFaultMiddlewareTests
{
    private static DefaultHttpContext Request(string path = "/oauth2/token")
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton<IStorageFaults, PostgresFaults>()
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static async Task RunAsync(HttpContext context, Exception fault) =>
        await new UnhandledFaultMiddleware(_ => throw fault, NullLogger<UnhandledFaultMiddleware>.Instance).InvokeAsync(context);

    private static string BodyOf(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return new StreamReader(context.Response.Body).ReadToEnd();
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/introspect")]
    [InlineData("/admin/agents")]
    public async Task An_unreachable_database_is_answered_as_retryable(string path)
    {
        var context = Request(path);

        await RunAsync(context, new InvalidOperationException("wrapped", new NpgsqlException("refused", new TimeoutException())));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, context.Response.StatusCode);
        Assert.Equal(UnhandledFaultMiddleware.StorageRetryAfter.TotalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture), context.Response.Headers.RetryAfter.ToString());
        using var body = JsonDocument.Parse(BodyOf(context));
        Assert.Equal("temporarily_unavailable", body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task The_answer_names_nothing_about_the_database()
    {
        var context = Request();

        await RunAsync(context, new NpgsqlException("Failed to connect to 10.1.2.3:5432 as subactid", new TimeoutException()));

        var body = BodyOf(context);
        Assert.DoesNotContain("10.1.2.3", body, StringComparison.Ordinal);
        Assert.DoesNotContain("5432", body, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/oauth2/introspect")]
    [InlineData("/oauth2/revoke")]
    public async Task A_body_the_host_refused_keeps_its_status_and_is_never_cached(string path)
    {
        var context = Request(path);
        context.Response.Headers.CacheControl = "no-store";

        await RunAsync(context, new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge));

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, context.Response.StatusCode);
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
        Assert.Equal("no-cache", context.Response.Headers.Pragma.ToString());
    }

    [Fact]
    public async Task Any_other_fault_is_still_a_500()
    {
        var context = Request();

        await RunAsync(context, new InvalidOperationException("a bug"));

        Assert.Equal(StatusCodes.Status500InternalServerError, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Retry-After"));
    }

    [Fact]
    public async Task A_fault_in_the_request_is_still_a_500_when_it_comes_from_the_driver()
    {
        var context = Request();

        await RunAsync(context, new PostgresException("duplicate key", "ERROR", "ERROR", "23505"));

        Assert.Equal(StatusCodes.Status500InternalServerError, context.Response.StatusCode);
    }

    [Fact]
    public async Task The_log_line_cannot_be_forged_by_the_request()
    {
        var logger = new RecordingLogger();
        var context = Request("/oauth2/token\r\n[forged] a second line");
        context.Request.Method = "POST\nGET";

        await new UnhandledFaultMiddleware(_ => throw new InvalidOperationException("a bug"), logger).InvokeAsync(context);

        var line = Assert.Single(logger.Lines);
        Assert.DoesNotContain('\r', line);
        Assert.DoesNotContain('\n', line);
        Assert.Contains("POST?GET /oauth2/token??[forged] a second line", line, StringComparison.Ordinal);
    }

    private sealed class RecordingLogger : ILogger<UnhandledFaultMiddleware>
    {
        public List<string> Lines { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Add(formatter(state, exception));
    }
}
