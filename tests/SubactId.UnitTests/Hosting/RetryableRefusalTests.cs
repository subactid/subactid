using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SubactId.Server.Contracts;
using SubactId.Server.Hosting;
using Xunit;

namespace SubactId.UnitTests.Hosting;

/// <summary>
/// The retryable refusals, <c>503 temporarily_unavailable</c> and <c>429 slow_down</c>, are
/// written the same way: an OAuth error body from the contracts, or the RFC 7644 shape on
/// <c>/scim</c>, with <c>Retry-After</c> and never cached.
/// </summary>
public class RetryableRefusalTests
{
    private static DefaultHttpContext Request(string path)
    {
        var context = new DefaultHttpContext { RequestServices = new ServiceCollection().AddLogging().BuildServiceProvider() };
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static JsonElement Body(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return JsonDocument.Parse(context.Response.Body).RootElement;
    }

    [Theory]
    [InlineData("/oauth2/token")]
    [InlineData("/admin/agents")]
    [InlineData("/events")]
    public async Task A_slow_down_is_an_oauth_error_with_retry_after_and_never_cached(string path)
    {
        var context = Request(path);

        Assert.True(await TemporarilyUnavailable.WriteRefusalAsync(
            context, StatusCodes.Status429TooManyRequests, OAuthErrorResponse.SlowDown, TimeSpan.FromSeconds(7), "Too many requests."));

        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
        Assert.Equal("7", context.Response.Headers.RetryAfter.ToString());
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
        var body = Body(context);
        Assert.Equal("slow_down", body.GetProperty("error").GetString());
        Assert.Equal("Too many requests.", body.GetProperty("error_description").GetString());
    }

    [Fact]
    public async Task On_scim_a_slow_down_uses_the_scim_error_shape()
    {
        var context = Request("/scim/v2/Users");

        Assert.True(await TemporarilyUnavailable.WriteRefusalAsync(
            context, StatusCodes.Status429TooManyRequests, OAuthErrorResponse.SlowDown, TimeSpan.FromSeconds(3), "Too many requests."));

        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
        var body = Body(context);
        Assert.Equal("429", body.GetProperty("status").GetString());
        Assert.Contains(
            "urn:ietf:params:scim:api:messages:2.0:Error",
            body.GetProperty("schemas").EnumerateArray().Select(s => s.GetString()));
        Assert.False(body.TryGetProperty("error", out _));
    }

    [Fact]
    public async Task A_temporarily_unavailable_is_written_as_it_was()
    {
        var context = Request("/oauth2/introspect");

        Assert.True(await TemporarilyUnavailable.WriteAsync(context, TimeSpan.FromSeconds(1), "Busy."));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, context.Response.StatusCode);
        Assert.Equal("temporarily_unavailable", Body(context).GetProperty("error").GetString());
    }
}
