using System.Threading.RateLimiting;
using Microsoft.Net.Http.Headers;
using SubactId.Server.Configuration;

namespace SubactId.Server.Hosting;

/// <summary>Which of the separately limited kinds of work a request is.</summary>
public enum OverloadPartition
{
    /// <summary><c>POST /oauth2/token</c>: exchanges and refreshes. The most expensive path.</summary>
    Token,

    /// <summary><c>POST /oauth2/introspect</c>: a tool server's token check.</summary>
    Introspection,

    /// <summary>
    /// The paths that take access away: <c>/oauth2/revoke</c>, <c>/backchannel-logout</c>,
    /// <c>/scim</c>, <c>/events</c> and the admin API. Kept separate so other traffic cannot
    /// delay a revocation.
    /// </summary>
    Revocation,

    /// <summary>Everything else that is limited: discovery, key sets, the audit query.</summary>
    Other,
}

/// <summary>
/// Per-partition concurrency limits. Work this instance cannot start in time is refused at once.
/// See <see cref="OverloadOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// A refusal is <c>503 temporarily_unavailable</c> with <c>Retry-After</c>, given before any work
/// is done. It is audited through the denial aggregator with reason <see cref="Reason"/>.
/// </para>
/// <para>
/// Form bodies are read before a turn is taken, so a slow sender cannot hold a turn. The endpoint
/// later sees the same form, or the same read failure.
/// </para>
/// <para>
/// A request whose caller disconnects while queued is dropped without running. Health and
/// readiness probes, and requests with no matching endpoint, are never limited.
/// </para>
/// </remarks>
public sealed class OverloadShedding : IDisposable
{
    /// <summary>Audit reason recorded when a request is refused because the instance is at capacity.</summary>
    public const string Reason = "overloaded";

    /// <summary>How long a refused caller is told to wait.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(1);

    private const string Description = "The control plane is at capacity. Retry after the interval in Retry-After.";

    /// <summary>The media type of the forms read before a turn is taken.</summary>
    private const string FormMediaType = "application/x-www-form-urlencoded";

    /// <summary>The paths whose form bodies are read before a turn is taken.</summary>
    private static readonly string[] FormPaths =
    [
        Tokens.TokenEndpoints.Path,
        Introspection.IntrospectionEndpoints.Path,
        Revocation.RevocationEndpoints.Path,
        Logout.LogoutEndpoints.LogoutPath,
    ];

    /// <summary>The paths counted as <see cref="OverloadPartition.Revocation"/>.</summary>
    private static readonly string[] RevocationPaths =
    [
        Revocation.RevocationEndpoints.Path,
        Logout.LogoutEndpoints.LogoutPath,
        Scim.ScimEndpoints.Prefix,
        Signals.SecurityEventEndpoints.EventsPath,
        "/admin",
    ];

    private readonly OverloadOptions options;
    private readonly Dictionary<OverloadPartition, ConcurrencyLimiter> limiters;

    /// <summary>Builds a limiter for each partition, as <paramref name="options"/> describes.</summary>
    /// <param name="options">The limits.</param>
    public OverloadShedding(OverloadOptions options)
    {
        this.options = options ?? throw new ArgumentNullException(nameof(options));
        limiters = Enum.GetValues<OverloadPartition>().ToDictionary(partition => partition, _ => Create(options));
    }

    /// <summary>Which kind of work <paramref name="path"/> is, or <c>null</c> for a path that is never limited.</summary>
    /// <param name="path">The request path.</param>
    public static OverloadPartition? PartitionOf(PathString path)
    {
        if (path.StartsWithSegments(Health.HealthEndpoints.LivenessPath) || path.StartsWithSegments(Health.HealthEndpoints.ReadinessPath))
        {
            return null;
        }

        if (path.StartsWithSegments(Tokens.TokenEndpoints.Path))
        {
            return OverloadPartition.Token;
        }

        if (path.StartsWithSegments(Introspection.IntrospectionEndpoints.Path))
        {
            return OverloadPartition.Introspection;
        }

        return RevocationPaths.Any(prefix => path.StartsWithSegments(prefix))
            ? OverloadPartition.Revocation
            : OverloadPartition.Other;
    }

    /// <summary>Runs <paramref name="next"/> when there is room for it in time, and refuses the request otherwise.</summary>
    /// <param name="context">The request.</param>
    /// <param name="next">The rest of the pipeline.</param>
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        if (PartitionOf(context.Request.Path) is not { } partition || context.GetEndpoint() is null)
        {
            await next(context);
            return;
        }

        if (!await ReadFormFirstAsync(context))
        {
            return;
        }

        var limiter = limiters[partition];
        var lease = limiter.AttemptAcquire();
        if (!lease.IsAcquired)
        {
            // No permit free: queue for up to QueueTimeout.
            lease.Dispose();
            using var waiting = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            waiting.CancelAfter(options.QueueTimeout);
            try
            {
                lease = await limiter.AcquireAsync(1, waiting.Token);
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                CallerLeft(context);
                return;
            }
            catch (OperationCanceledException)
            {
                await RefuseAsync(context);
                return;
            }
        }

        using (lease)
        {
            if (!lease.IsAcquired)
            {
                await RefuseAsync(context);
                return;
            }

            await next(context);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var limiter in limiters.Values)
        {
            limiter.Dispose();
        }
    }

    /// <summary>
    /// Reads the form body of a request to a form endpoint before it takes a turn. Returns
    /// <c>false</c> when the caller disconnected while sending it.
    /// </summary>
    private static async Task<bool> ReadFormFirstAsync(HttpContext context)
    {
        var request = context.Request;
        if (!HttpMethods.IsPost(request.Method)
            || !FormPaths.Any(path => request.Path.StartsWithSegments(path))
            || !MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
            || !contentType.MediaType.Equals(FormMediaType, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Held to the endpoints' limit before the first read, which is this one. A body declared
        // over it is not read at all: the endpoint refuses it.
        if (!Tokens.FormEndpoints.LimitBody(context))
        {
            return true;
        }

        try
        {
            await request.ReadFormAsync(context.RequestAborted);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            CallerLeft(context);
            return false;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Ignored here. The endpoint's own read hits the same failure and answers it.
        }

        return true;
    }

    /// <summary>Marks the request as 499 in the request log, since the caller disconnected.</summary>
    private static void CallerLeft(HttpContext context)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status499ClientClosedRequest;
        }
    }

    private static ConcurrencyLimiter Create(OverloadOptions options) => new(new ConcurrencyLimiterOptions
    {
        PermitLimit = options.ConcurrencyLimit,
        QueueLimit = options.QueueLimit,
        // Oldest first, so the request closest to timing out runs first.
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
    });

    private static async Task RefuseAsync(HttpContext context)
    {
        await RateLimiting.RecordAsync(context, Reason);
        await TemporarilyUnavailable.WriteAsync(context, RetryAfter, Description);
    }
}

/// <summary>Adds <see cref="OverloadShedding"/> to the services and the pipeline.</summary>
public static class OverloadSheddingExtensions
{
    /// <summary>Registers the limiter <paramref name="options"/> describes, when it is enabled.</summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">The limits.</param>
    public static IServiceCollection AddSubactIdOverloadShedding(this IServiceCollection services, OverloadOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);

        if (options.Enabled)
        {
            services.AddSingleton(new OverloadShedding(options));
        }

        return services;
    }

    /// <summary>Applies the limiter, when it is enabled.</summary>
    /// <param name="app">The application.</param>
    /// <param name="options">The limits.</param>
    public static IApplicationBuilder UseSubactIdOverloadShedding(this IApplicationBuilder app, OverloadOptions options)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(options);

        if (!options.Enabled)
        {
            return app;
        }

        var shedding = app.ApplicationServices.GetRequiredService<OverloadShedding>();
        return app.Use((context, next) => shedding.InvokeAsync(context, next));
    }
}
