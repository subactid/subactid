using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace SubactId.Bench;

// The control plane client for the load generator: register, exchange, refresh, introspect and
// the unauthenticated reads. Calls return an outcome instead of throwing, so refusals are counted.
internal sealed class ControlPlane(HttpClient http, Uri issuer, string adminKey)
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> answers = new(StringComparer.Ordinal);

    // Every token endpoint response in this process, by grant and outcome. stress.sh reconciles
    // the audit ledger against it.
    public IReadOnlyDictionary<string, int> TokenAnswers => new SortedDictionary<string, int>(answers, StringComparer.Ordinal);

    public string TokenEndpoint { get; } = new Uri(issuer, "/oauth2/token").AbsoluteUri;

    public async Task<bool> IsReadyAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.GetAsync(new Uri(issuer, "/readyz"), cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return false;
        }
    }

    // Registers the agent, or leaves the existing registration alone. Returns whether it created one.
    public async Task<bool> RegisterAsync(AgentKey key, string audience, IReadOnlyList<string> scopes, string? maxTaskTtl, string? maxTokenTtl, CancellationToken cancellationToken)
    {
        var registration = new Dictionary<string, object?>
        {
            ["agent_id"] = key.AgentId,
            ["display_name"] = key.AgentId,
            ["sponsor_required"] = true,
            ["allowed_scopes"] = scopes,
            ["allowed_audiences"] = new[] { audience },
            ["max_delegation_depth"] = 1,
            ["jwks"] = key.Jwks,
        };

        if (maxTaskTtl is not null)
        {
            registration["max_task_ttl"] = maxTaskTtl;
        }

        if (maxTokenTtl is not null)
        {
            registration["max_token_ttl"] = maxTokenTtl;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(issuer, "/admin/agents"))
        {
            Content = JsonContent.Create(registration),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminKey);
        using var response = await http.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            return false;
        }

        if (response.StatusCode != HttpStatusCode.Created)
        {
            throw new InvalidOperationException($"The control plane answered {(int)response.StatusCode} registering {key.AgentId}: {await response.Content.ReadAsStringAsync(cancellationToken)}");
        }

        return true;
    }

    public async Task<Outcome> ExchangeAsync(string subjectToken, string assertion, string resource, string scope, CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = assertion,
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["resource"] = resource,
            ["scope"] = scope,
        });

        return Count("exchange", await SendAsync(new Uri(issuer, "/oauth2/token"), form, wantsGrant: true, cancellationToken));
    }

    public async Task<Outcome> RefreshAsync(string grant, string assertion, string resource, string scope, CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = grant,
            ["resource"] = resource,
            ["scope"] = scope,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = assertion,
        });

        return Count("refresh", await SendAsync(new Uri(issuer, "/oauth2/token"), form, wantsGrant: true, cancellationToken));
    }

    public async Task<Outcome> IntrospectAsync(string token, string assertion, CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = assertion,
        });

        return await SendAsync(new Uri(issuer, "/oauth2/introspect"), form, wantsGrant: false, cancellationToken);
    }

    // A plain GET, for the cached discovery and JWKS reads.
    public async Task<Outcome> GetAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.GetAsync(new Uri(issuer, path), cancellationToken);
            using var content = response.Content;
            _ = await content.ReadAsByteArrayAsync(cancellationToken);
            return new Outcome((int)response.StatusCode, null, null, null, null);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            return new Outcome(0, Classify(exception), null, null, null);
        }
    }

    // A token request with no valid credentials, to measure the denial path.
    public async Task<Outcome> DeniedAsync(CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = "not-a-token",
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = "not-an-assertion",
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        });

        return await SendAsync(new Uri(issuer, "/oauth2/token"), form, wantsGrant: false, cancellationToken);
    }

    private Outcome Count(string grant, Outcome outcome)
    {
        var key = outcome.Error is { } error ? $"{grant}:{outcome.Status}:{error}" : $"{grant}:{outcome.Status}";
        answers.AddOrUpdate(key, 1, static (_, count) => count + 1);
        return outcome;
    }

    private async Task<Outcome> SendAsync(Uri url, HttpContent form, bool wantsGrant, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await http.PostAsync(url, form, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return new Outcome((int)response.StatusCode, ErrorOf(body), null, null, null);
            }

            if (!wantsGrant)
            {
                return new Outcome((int)response.StatusCode, null, null, null, null);
            }

            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            return new Outcome(
                (int)response.StatusCode,
                null,
                Text(root, "access_token"),
                Text(root, "refresh_token"),
                Text(root, "task_id"));
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new Outcome(0, Classify(exception), null, null, null);
        }
    }

    private static string Classify(Exception exception) => exception switch
    {
        TaskCanceledException => "timeout",
        JsonException => "unparseable",
        _ => "transport",
    };

    private static string? ErrorOf(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var error = Text(document.RootElement, "error") ?? "unknown_error";

            // temporarily_unavailable has three causes: capacity, identity provider, or database.
            // Only the database case writes no audit record, so reconciliation needs to tell
            // them apart by the description.
            if (error == "temporarily_unavailable" && Text(document.RootElement, "error_description") is { } description)
            {
                if (description.Contains("database", StringComparison.OrdinalIgnoreCase))
                {
                    return error + "(database)";
                }

                if (description.Contains("capacity", StringComparison.OrdinalIgnoreCase))
                {
                    return error + "(capacity)";
                }
            }

            return error;
        }
        catch (JsonException)
        {
            return "unparseable";
        }
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

// One request's result: status, error class on failure, and values later requests need.
// Status 0 means no response.
internal sealed record Outcome(int Status, string? Error, string? AccessToken, string? Grant, string? TaskId);
