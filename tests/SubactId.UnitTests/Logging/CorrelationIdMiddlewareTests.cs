using Microsoft.AspNetCore.Http;
using SubactId.Server.Logging;
using Xunit;

namespace SubactId.UnitTests.Logging;

public class CorrelationIdMiddlewareTests
{
    [Fact]
    public async Task Honours_a_well_formed_caller_supplied_id()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CorrelationIdMiddleware.HeaderName] = "req-42.abc_DEF";

        await Invoke(context);

        Assert.Equal("req-42.abc_DEF", context.TraceIdentifier);
        Assert.Equal("req-42.abc_DEF", context.Response.Headers[CorrelationIdMiddleware.HeaderName]);
    }

    [Fact]
    public async Task Generates_an_id_when_none_is_supplied()
    {
        var context = new DefaultHttpContext();

        await Invoke(context);

        var id = context.TraceIdentifier;
        Assert.Equal(32, id.Length);
        Assert.True(id.All(char.IsAsciiHexDigitLower));
        Assert.Equal(id, context.Response.Headers[CorrelationIdMiddleware.HeaderName]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("new\nline")]
    [InlineData("{\"json\":true}")]
    [InlineData("0123456789012345678901234567890123456789012345678901234567890123x")]
    public async Task Replaces_an_unacceptable_caller_supplied_id(string supplied)
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CorrelationIdMiddleware.HeaderName] = supplied;

        await Invoke(context);

        Assert.NotEqual(supplied, context.TraceIdentifier);
        Assert.Equal(32, context.TraceIdentifier.Length);
    }

    [Fact]
    public async Task Replaces_multiple_supplied_ids()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CorrelationIdMiddleware.HeaderName] = new[] { "one", "two" };

        await Invoke(context);

        Assert.Equal(32, context.TraceIdentifier.Length);
    }

    [Fact]
    public async Task Calls_the_next_middleware_with_the_id_already_set()
    {
        var context = new DefaultHttpContext();
        string? observed = null;

        var middleware = new CorrelationIdMiddleware(ctx =>
        {
            observed = ctx.TraceIdentifier;
            return Task.CompletedTask;
        });
        await middleware.InvokeAsync(context);

        Assert.Equal(context.TraceIdentifier, observed);
    }

    private static Task Invoke(HttpContext context) =>
        new CorrelationIdMiddleware(_ => Task.CompletedTask).InvokeAsync(context);
}
