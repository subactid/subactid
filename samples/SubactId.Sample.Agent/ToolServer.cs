using System.Net.Http.Headers;
using System.Text.Json;

namespace SubactId.Sample.Agent;

/// <summary>Client for the sample tool server. Sends the task token as a bearer token.</summary>
internal sealed class ToolServer(HttpClient http, Uri baseUrl)
{
    /// <summary>Whether the tool server is answering.</summary>
    public async Task<bool> IsUpAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.GetAsync(new Uri(baseUrl, "/healthz"), cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return false;
        }
    }

    /// <summary>The tool server's description of its tools, or <c>null</c> if it is not up yet.</summary>
    public async Task<string?> DescribeAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.GetAsync(baseUrl, cancellationToken);
            return response.IsSuccessStatusCode ? await response.Content.ReadAsStringAsync(cancellationToken) : null;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return null;
        }
    }

    /// <summary>Calls one tool and returns its result, or the status and error if refused.</summary>
    public async Task<ToolCall> CallAsync(string tool, string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUrl, $"/tools/{tool}"))
        {
            Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await http.SendAsync(request, cancellationToken);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var body = document.RootElement;
        return response.IsSuccessStatusCode
            ? new ToolCall((int)response.StatusCode, Text(body, "result"), null, null)
            : new ToolCall((int)response.StatusCode, null, Text(body, "error"), Text(body, "error_description"));
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

/// <summary>What one tool call came back as.</summary>
internal sealed record ToolCall(int Status, string? Result, string? Error, string? Description);
