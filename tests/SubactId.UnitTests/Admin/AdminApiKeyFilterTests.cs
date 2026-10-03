using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Server.Admin;
using SubactId.Server.Configuration;
using SubactId.Tokens.Signing;
using SubactId.UnitTests.Tokens.Exchange;
using Xunit;

namespace SubactId.UnitTests.Admin;

public class AdminApiKeyFilterTests
{
    // Built at runtime so no literal in the repository looks like a credential.
    private static readonly string Key = string.Concat(Enumerable.Repeat("k0", 20));

    [Theory]
    [InlineData(null, AdminApiKeyFilter.MissingApiKey)]
    [InlineData("", AdminApiKeyFilter.MissingApiKey)]
    [InlineData("Basic abc", AdminApiKeyFilter.MissingApiKey)]
    [InlineData("Bearer", AdminApiKeyFilter.MissingApiKey)]
    [InlineData("Bearer ", AdminApiKeyFilter.MissingApiKey)]
    [InlineData("bearer {key}", null)]
    [InlineData("BEARER {key}", null)]
    [InlineData("Bearer wrong", AdminApiKeyFilter.InvalidApiKey)]
    [InlineData("Bearer {key}x", AdminApiKeyFilter.InvalidApiKey)]
    [InlineData("Bearer {key}", null)]
    [InlineData("Bearer  {key} ", null)]
    public void Check_reports_missing_invalid_or_ok(string? header, string? expected)
    {
        var values = header is null ? StringValues.Empty : new StringValues(header.Replace("{key}", Key, StringComparison.Ordinal));

        Assert.Equal(expected, AdminApiKeyFilter.Check(values, Key));
    }

    [Fact]
    public void Two_authorization_headers_are_treated_as_missing()
    {
        Assert.Equal(AdminApiKeyFilter.MissingApiKey, AdminApiKeyFilter.Check(new StringValues(["Bearer " + Key, "Bearer " + Key]), Key));
    }

    [Fact]
    public async Task Answers_503_when_no_key_is_configured_without_running_the_endpoint()
    {
        var services = new ServiceCollection().AddLogging().AddSingleton(Options(apiKey: null)).BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Response.Body = new MemoryStream();
        var ran = false;

        var result = await new AdminApiKeyFilter().InvokeAsync(
            new DefaultEndpointFilterInvocationContext(context),
            _ => { ran = true; return ValueTask.FromResult<object?>(Results.Ok()); });

        await ((IResult)result!).ExecuteAsync(context);
        Assert.Equal(StatusCodes.Status503ServiceUnavailable, context.Response.StatusCode);
        Assert.False(ran);
    }

    [Fact]
    public async Task The_middleware_refuses_a_wrong_key_before_the_rest_of_the_pipeline_and_records_it()
    {
        var audit = new InMemoryAudit();
        var context = Operator("/admin/agents", "Bearer wrong", audit);
        var ran = false;

        await new AdminApiKeyMiddleware(_ => { ran = true; return Task.CompletedTask; }).InvokeAsync(context);

        Assert.False(ran);
        Assert.Equal(StatusCodes.Status401Unauthorized, context.Response.StatusCode);
        Assert.Equal("Bearer realm=\"subactid-admin\"", context.Response.Headers.WWWAuthenticate);
        var record = Assert.Single(audit.Events);
        Assert.Equal((AuditEvents.AdminDenied, AuditDecision.Deny, AdminApiKeyFilter.InvalidApiKey), (record.Event, record.Decision, record.Reason));
    }

    [Fact]
    public async Task The_middleware_lets_the_configured_key_through_and_records_nothing()
    {
        var audit = new InMemoryAudit();
        var context = Operator("/audit", "Bearer " + Key, audit);
        var ran = false;

        await new AdminApiKeyMiddleware(_ => { ran = true; return Task.CompletedTask; }).InvokeAsync(context);

        Assert.True(ran);
        Assert.Empty(audit.Events);
    }

    [Theory]
    [InlineData("/admin", true)]
    [InlineData("/admin/agents", true)]
    [InlineData("/admin/tasks/task_1", true)]
    [InlineData("/audit", true)]
    [InlineData("/administrator", false)]
    [InlineData("/auditor", false)]
    [InlineData("/oauth2/token", false)]
    [InlineData("/", false)]
    public void Only_the_operator_paths_are_challenged_before_routing(string path, bool challenged)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;

        Assert.Equal(challenged, AdminApiKeyMiddlewareExtensions.IsOperatorRequest(context));
    }

    private static DefaultHttpContext Operator(string path, string authorization, InMemoryAudit audit)
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddSingleton(Options(apiKey: Key))
            .AddSingleton(TimeProvider.System)
            .AddSingleton(NoAggregationHelper.NoAggregation(TimeProvider.System))
            .AddSingleton<IAuditWriter>(audit)
            .BuildServiceProvider();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Path = path;
        context.Request.Headers.Authorization = authorization;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static SubactIdOptions Options(string? apiKey) => new()
    {
        Issuer = new Uri("https://subactid.example.test"),
        UpstreamIdp = new UpstreamIdpOptions { SponsorKeyClaim = UpstreamIdpOptions.DefaultSponsorKeyClaim, SponsorCheckMode = SponsorCheckMode.Poll, MetadataUrl = new Uri("https://idp.example.test/.well-known/openid-configuration"), Audience = "subactid", SponsorCheck = new SponsorCheckOptions { UsersUrl = new Uri("https://idp.example.test/admin/realms/main/users"), TokenUrl = new Uri("https://idp.example.test/realms/main/protocol/openid-connect/token"), ClientId = "subactid", CacheTtl = TimeSpan.FromSeconds(30) } },
        Database = new DatabaseOptions { Provider = StorageProvider.Postgres, ConnectionString = "Host=db" },
        Tokens = new TokenOptions { DefaultTaskTtl = TimeSpan.FromMinutes(30), DefaultTokenTtl = TimeSpan.FromMinutes(5) },
        Agents = AgentRegistrationLimits.Default,
        Tasks = new TaskSweepOptions { SweepInterval = TimeSpan.FromMinutes(1), BatchSize = 100 },
        Signing = new SigningOptions { Keys = [] },
        Admin = new AdminOptions { ApiKey = apiKey },
        Audit = new AuditOptions { DrainInterval = TimeSpan.FromSeconds(5), DrainBatchSize = 100, CheckpointInterval = AuditOptions.DefaultCheckpointInterval },
    };
}
