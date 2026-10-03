using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Xunit;

namespace SubactId.IntegrationTests.Endpoints;

/// <summary>
/// The real server with an unreachable database. A request that needs the database gets
/// <c>503 temporarily_unavailable</c> with <c>Retry-After</c>, not a 500.
/// </summary>
public class StorageOutageTests : IClassFixture<ServerFactory>
{
    private readonly ServerFactory factory;

    public StorageOutageTests(ServerFactory factory) => this.factory = factory;

    [Fact]
    public async Task A_request_that_needs_the_database_is_told_to_retry()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/admin/agents");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ServerFactory.AdminApiKey);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.NotNull(response.Headers.RetryAfter);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("temporarily_unavailable", body.RootElement.GetProperty("error").GetString());
    }
}
