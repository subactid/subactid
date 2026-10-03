using System.Net.Http;
using System.Text.Json;

namespace SubactId.Sample.ToolServer;

/// <summary>
/// Step 4 of spec section 9: for a high-risk tool, or a token carrying <c>introspect_required</c>,
/// introspect the token with the control plane, so a revocation applies on the next call. The
/// token is the only credential sent.
/// </summary>
internal sealed class Introspection(HttpClient http, Uri issuer)
{
    /// <summary>Asks the control plane whether <paramref name="token"/> is live. Any failure counts as inactive.</summary>
    public async Task<(bool Active, string? Reason)> CheckAsync(string token, CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token });
        try
        {
            using var response = await http.PostAsync(new Uri(issuer, "/oauth2/introspect"), form, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return (false, "introspection_unavailable");
            }

            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            var root = document.RootElement;
            if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("active", out var active) && active.ValueKind == JsonValueKind.True)
            {
                return (true, null);
            }

            var reason = root.ValueKind == JsonValueKind.Object && root.TryGetProperty("revocation_reason", out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : "inactive";
            return (false, reason);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or TaskCanceledException)
        {
            return (false, "introspection_unavailable");
        }
    }
}
