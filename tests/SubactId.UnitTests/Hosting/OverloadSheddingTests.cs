using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SubactId.Core.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Hosting;
using SubactId.Server.Logging;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Hosting;

/// <summary>
/// The limit on concurrent work. Excess is refused at once and retryably, kinds of work do not
/// starve each other, a slow sender never holds a turn, abandoned work is not run, every refusal
/// is recorded, and health and readiness are never limited.
/// </summary>
public class OverloadSheddingTests
{
    private const string FormMediaType = "application/x-www-form-urlencoded";

    private static OverloadOptions Options(int limit = 1, int queue = 1, double queueSeconds = 5) => new()
    {
        ConcurrencyLimit = limit,
        QueueLimit = queue,
        QueueTimeout = TimeSpan.FromSeconds(queueSeconds),
    };

    private static DefaultHttpContext Request(string path, InMemoryAudit? audit = null, bool routed = true)
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton(TimeProvider.System)
            .AddSingleton(NoAggregationHelper.NoAggregation(TimeProvider.System))
            .AddSingleton<IAuditWriter>(audit ?? new InMemoryAudit())
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        if (routed)
        {
            context.SetEndpoint(new Endpoint(_ => Task.CompletedTask, EndpointMetadataCollection.Empty, path));
        }

        return context;
    }

    private static DefaultHttpContext Form(string path, Stream body)
    {
        var context = Request(path);
        context.Request.Method = HttpMethods.Post;
        context.Request.ContentType = FormMediaType;
        context.Request.Body = body;
        return context;
    }

    /// <summary>A pipeline that holds each request until it is released, and counts what it ran.</summary>
    private sealed class Gate
    {
        private readonly TaskCompletionSource release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int ran;

        public int Ran => Volatile.Read(ref ran);

        public RequestDelegate Next => async _ =>
        {
            Interlocked.Increment(ref ran);
            await release.Task;
        };

        public void Release() => release.TrySetResult();
    }

    /// <summary>A request body that arrives only when it is let through, as a slow sender's does.</summary>
    private sealed class SlowBody(byte[] content) : Stream
    {
        private readonly TaskCompletionSource arrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int position;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => content.Length;

        public override long Position { get => position; set => throw new NotSupportedException(); }

        public void Arrive() => arrived.TrySetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await arrived.Task.WaitAsync(cancellationToken);
            var count = Math.Min(buffer.Length, content.Length - position);
            content.AsMemory(position, count).CopyTo(buffer);
            position += count;
            return count;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static async Task<JsonElement> BodyOf(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return (await JsonDocument.ParseAsync(context.Response.Body)).RootElement;
    }

    [Theory]
    [InlineData("/oauth2/token", OverloadPartition.Token)]
    [InlineData("/oauth2/introspect", OverloadPartition.Introspection)]
    [InlineData("/oauth2/revoke", OverloadPartition.Revocation)]
    [InlineData("/backchannel-logout", OverloadPartition.Revocation)]
    [InlineData("/scim/v2/Users", OverloadPartition.Revocation)]
    [InlineData("/events", OverloadPartition.Revocation)]
    [InlineData("/admin/agents", OverloadPartition.Revocation)]
    [InlineData("/.well-known/jwks.json", OverloadPartition.Other)]
    [InlineData("/.well-known/openid-configuration", OverloadPartition.Other)]
    [InlineData("/audit", OverloadPartition.Other)]
    public void Each_path_is_counted_against_its_own_kind_of_work(string path, OverloadPartition expected)
    {
        Assert.Equal(expected, OverloadShedding.PartitionOf(path));
    }

    [Theory]
    [InlineData("/healthz")]
    [InlineData("/readyz")]
    public void Health_and_readiness_are_never_limited(string path)
    {
        Assert.Null(OverloadShedding.PartitionOf(path));
    }

    [Fact]
    public async Task Past_the_limit_and_the_queue_a_request_is_refused_at_once_and_retryably()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 1));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);
        var queued = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);

        var refused = Request("/oauth2/token");
        await shedding.InvokeAsync(refused, gate.Next);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refused.Response.StatusCode);
        Assert.Equal("1", refused.Response.Headers.RetryAfter.ToString());
        Assert.Equal("temporarily_unavailable", (await BodyOf(refused)).GetProperty("error").GetString());
        Assert.Equal(1, gate.Ran);

        gate.Release();
        await Task.WhenAll(running, queued);
        Assert.Equal(2, gate.Ran);
    }

    [Fact]
    public async Task With_no_queue_a_request_that_finds_no_turn_free_is_refused()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 0));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);

        var refused = Request("/oauth2/token");
        await shedding.InvokeAsync(refused, gate.Next);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refused.Response.StatusCode);
        gate.Release();
        await running;
    }

    [Fact]
    public async Task A_refusal_keeps_the_correlation_id_and_is_never_cached()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 0));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/backchannel-logout"), gate.Next);

        var refused = Request("/backchannel-logout");
        refused.Response.Headers[CorrelationIdMiddleware.HeaderName] = "req-0123";
        await shedding.InvokeAsync(refused, gate.Next);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refused.Response.StatusCode);
        Assert.Equal("req-0123", refused.Response.Headers[CorrelationIdMiddleware.HeaderName].ToString());
        Assert.Equal("no-store", refused.Response.Headers.CacheControl.ToString());
        gate.Release();
        await running;
    }

    [Fact]
    public async Task A_refusal_under_scim_is_in_the_shape_scim_clients_read()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 0));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/scim/v2/Users"), gate.Next);

        var refused = Request("/scim/v2/Users");
        await shedding.InvokeAsync(refused, gate.Next);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, refused.Response.StatusCode);
        Assert.StartsWith("application/scim+json", refused.Response.ContentType, StringComparison.Ordinal);
        var body = await BodyOf(refused);
        Assert.Equal("urn:ietf:params:scim:api:messages:2.0:Error", body.GetProperty("schemas")[0].GetString());
        Assert.Equal("503", body.GetProperty("status").GetString());
        gate.Release();
        await running;
    }

    [Fact]
    public async Task A_request_that_waits_longer_than_the_queue_timeout_is_refused()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 10, queueSeconds: 0.2));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);

        var waited = Request("/oauth2/token");
        await shedding.InvokeAsync(waited, gate.Next);

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, waited.Response.StatusCode);
        Assert.Equal(1, gate.Ran);
        gate.Release();
        await running;
    }

    [Fact]
    public async Task A_caller_that_leaves_while_waiting_is_never_run_and_never_answered()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 10));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);

        using var leaving = new CancellationTokenSource();
        var gone = Request("/oauth2/token");
        gone.RequestAborted = leaving.Token;
        var waiting = shedding.InvokeAsync(gone, gate.Next);
        await leaving.CancelAsync();
        await waiting;

        gate.Release();
        await running;
        Assert.Equal(1, gate.Ran);
        Assert.Equal(0, gone.Response.Body.Length);
        Assert.Equal(StatusCodes.Status499ClientClosedRequest, gone.Response.StatusCode);
    }

    [Fact]
    public async Task A_slow_sender_does_not_hold_a_turn_while_its_form_arrives()
    {
        // Guards against a stranger opening as many token requests as there are turns and sending each
        // body a byte at a time. The body is read before a turn is taken.
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 0));
        var gate = new Gate();
        var body = new SlowBody(Encoding.ASCII.GetBytes("grant_type=refresh_token"));
        var slow = shedding.InvokeAsync(Form("/oauth2/token", body), gate.Next);

        var prompt = Request("/oauth2/token");
        var served = false;
        await shedding.InvokeAsync(prompt, _ =>
        {
            served = true;
            return Task.CompletedTask;
        });

        Assert.True(served);
        Assert.Equal(0, gate.Ran);

        body.Arrive();
        gate.Release();
        await slow;
        Assert.Equal(1, gate.Ran);
    }

    [Fact]
    public async Task The_endpoint_gets_the_form_that_was_read_first()
    {
        using var shedding = new OverloadShedding(Options());
        var body = new SlowBody(Encoding.ASCII.GetBytes("grant_type=refresh_token&scope=a+b"));
        body.Arrive();
        var request = Form("/oauth2/token", body);

        IFormCollection? seen = null;
        await shedding.InvokeAsync(request, async context => seen = await context.Request.ReadFormAsync());

        Assert.Equal("refresh_token", seen!["grant_type"].ToString());
        Assert.Equal("a b", seen["scope"].ToString());
    }

    [Fact]
    public async Task A_form_that_cannot_be_read_fails_the_endpoint_the_same_way()
    {
        // The endpoint answers an unreadable form itself, as invalid_request, and records it. Reading
        // the body first must leave that failure to the endpoint.
        using var shedding = new OverloadShedding(Options());
        var tooLongAKey = new string('k', 4096) + "=v";
        var body = new SlowBody(Encoding.ASCII.GetBytes(tooLongAKey));
        body.Arrive();
        var request = Form("/oauth2/token", body);

        Exception? met = null;
        await shedding.InvokeAsync(request, async context =>
        {
            try
            {
                await context.Request.ReadFormAsync();
            }
            catch (Exception exception)
            {
                met = exception;
            }
        });

        Assert.IsType<InvalidDataException>(met);
    }

    [Fact]
    public async Task The_body_limit_is_set_before_the_form_is_read_first()
    {
        using var shedding = new OverloadShedding(Options());
        var body = new SlowBody(Encoding.ASCII.GetBytes("grant_type=refresh_token"));
        body.Arrive();
        var request = Form("/oauth2/token", body);
        var limit = new BodySizeLimit();
        request.Features.Set<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>(limit);

        await shedding.InvokeAsync(request, _ => Task.CompletedTask);

        Assert.Equal(64 * 1024, limit.MaxRequestBodySize);
        Assert.Equal(1, limit.TimesSet);
    }

    [Fact]
    public async Task A_body_declared_over_the_limit_is_not_read_first_and_is_left_to_the_endpoint()
    {
        using var shedding = new OverloadShedding(Options());
        var body = new SlowBody(Encoding.ASCII.GetBytes("grant_type=refresh_token"));
        var request = Form("/oauth2/token", body);
        request.Request.ContentLength = SubactId.Server.Tokens.FormEndpoints.MaxBodyBytes + 1;

        // Nothing has arrived, so a read would wait for ever.
        var ran = false;
        await shedding.InvokeAsync(request, _ =>
        {
            ran = true;
            return Task.CompletedTask;
        }).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(ran);
    }

    /// <summary>The host's body limit, recording how many times it was set.</summary>
    private sealed class BodySizeLimit : Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature
    {
        private long? value;

        public int TimesSet { get; private set; }

        public bool IsReadOnly => false;

        public long? MaxRequestBodySize
        {
            get => value;
            set
            {
                this.value = value;
                TimesSet++;
            }
        }
    }

    [Fact]
    public async Task A_request_no_endpoint_answers_is_not_limited()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 0));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/.well-known/jwks.json"), gate.Next);

        var unrouted = Request("/no/such/path", routed: false);
        var passed = false;
        await shedding.InvokeAsync(unrouted, _ =>
        {
            passed = true;
            return Task.CompletedTask;
        });

        Assert.True(passed);
        gate.Release();
        await running;
    }

    [Fact]
    public async Task A_full_token_endpoint_does_not_hold_up_introspection()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 1));
        var gate = new Gate();
        var running = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);
        var queued = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);

        var introspection = Request("/oauth2/introspect");
        var served = false;
        await shedding.InvokeAsync(introspection, _ =>
        {
            served = true;
            return Task.CompletedTask;
        });

        Assert.True(served);
        Assert.Equal(StatusCodes.Status200OK, introspection.Response.StatusCode);
        gate.Release();
        await Task.WhenAll(running, queued);
    }

    [Fact]
    public async Task A_flood_of_anything_else_does_not_hold_up_a_revocation()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 1));
        var gate = new Gate();
        var flood = new[] { "/.well-known/jwks.json", "/.well-known/jwks.json" }
            .Select(path => shedding.InvokeAsync(Request(path), gate.Next))
            .ToList();

        var logout = Request("/backchannel-logout");
        var served = false;
        await shedding.InvokeAsync(logout, _ =>
        {
            served = true;
            return Task.CompletedTask;
        });

        Assert.True(served);
        gate.Release();
        await Task.WhenAll(flood);
    }

    [Fact]
    public async Task Health_is_answered_however_full_the_instance_is()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 1));
        var gate = new Gate();
        var busy = new[] { "/oauth2/token", "/oauth2/token", "/oauth2/introspect", "/oauth2/introspect", "/audit", "/audit", "/admin/agents", "/admin/agents" }
            .Select(path => shedding.InvokeAsync(Request(path), gate.Next))
            .ToList();

        var probed = false;
        await shedding.InvokeAsync(Request("/readyz"), _ =>
        {
            probed = true;
            return Task.CompletedTask;
        });

        Assert.True(probed);
        gate.Release();
        await Task.WhenAll(busy);
    }

    [Fact]
    public async Task Every_refusal_is_recorded_as_a_denial()
    {
        using var shedding = new OverloadShedding(Options(limit: 1, queue: 1));
        var gate = new Gate();
        var audit = new InMemoryAudit();
        var running = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);
        var queued = shedding.InvokeAsync(Request("/oauth2/token"), gate.Next);

        await shedding.InvokeAsync(Request("/oauth2/token", audit), gate.Next);

        gate.Release();
        await Task.WhenAll(running, queued);

        var record = Assert.Single(audit.Events);
        Assert.Equal(AuditEvents.TokenDenied, record.Event);
        Assert.Equal(AuditDecision.Deny, record.Decision);
        Assert.Equal(OverloadShedding.Reason, record.Reason);
    }
}
