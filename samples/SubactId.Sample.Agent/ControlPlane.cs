using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SubactId.Sample.Agent;

/// <summary>
/// Control plane client: the RFC 8693 exchange and refresh, plus the admin calls the demo needs
/// (registration, revocation, audit query). A real agent would not hold the admin key. Tokens and
/// grants are returned to the caller and never logged.
/// </summary>
internal sealed class ControlPlane(HttpClient http, Uri issuer, string adminKey)
{
    /// <summary>The <c>aud</c> of every client assertion: the token endpoint of this control plane.</summary>
    public string TokenEndpoint { get; } = new Uri(issuer, "/oauth2/token").AbsoluteUri;

    /// <summary>Whether the instance is up and its own dependencies answer.</summary>
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

    /// <summary>Registers the agent. Returns <c>false</c> if it is already registered.</summary>
    public async Task<bool> RegisterAsync(object registration, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(issuer, "/admin/agents"))
        {
            Content = JsonContent.Create(registration),
        };
        Authorize(request);
        using var response = await http.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
        {
            return false;
        }

        await ThrowUnless(response, HttpStatusCode.Created, "registering the agent");
        return true;
    }

    /// <summary>An agent's current registration, or <c>null</c> if it is not registered.</summary>
    public async Task<JsonElement?> GetAgentAsync(string agentId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(issuer, $"/admin/agents/{Uri.EscapeDataString(agentId)}"));
        Authorize(request);
        using var response = await http.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        await ThrowUnless(response, HttpStatusCode.OK, "reading the registration");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return document.RootElement.Clone();
    }

    /// <summary>Updates an existing registration to match what this build expects.</summary>
    public async Task UpdateAsync(string agentId, object registration, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Patch, new Uri(issuer, $"/admin/agents/{Uri.EscapeDataString(agentId)}"))
        {
            Content = JsonContent.Create(registration),
        };
        Authorize(request);
        using var response = await http.SendAsync(request, cancellationToken);
        await ThrowUnless(response, HttpStatusCode.OK, "updating the registration");
    }

    /// <summary>Exchanges the human's token for a scoped task token, or returns the refusal.</summary>
    public async Task<ExchangeResult> ExchangeAsync(string subjectToken, string assertion, string resource, string scope, CancellationToken cancellationToken)
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

        using var response = await http.PostAsync(new Uri(issuer, "/oauth2/token"), form, cancellationToken);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var body = document.RootElement;
        if (!response.IsSuccessStatusCode)
        {
            return new ExchangeResult(null, Text(body, "error") ?? "unknown_error", Text(body, "error_description") ?? "The control plane refused the exchange.");
        }

        return new ExchangeResult(Session(body), null, null);
    }

    /// <summary>
    /// Gets a new token for the task with the requested scope, which must be the same or narrower.
    /// The control plane enforces this.
    /// </summary>
    public async Task<ExchangeResult> RefreshAsync(string grant, string assertion, string resource, string scope, CancellationToken cancellationToken)
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

        using var response = await http.PostAsync(new Uri(issuer, "/oauth2/token"), form, cancellationToken);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var body = document.RootElement;
        return response.IsSuccessStatusCode
            ? new ExchangeResult(Session(body), null, null)
            : new ExchangeResult(null, Text(body, "error") ?? "unknown_error", Text(body, "error_description") ?? "The control plane refused the refresh.");
    }

    private static TaskSession Session(JsonElement body) =>
        new(
            Text(body, "access_token")!,
            Text(body, "refresh_token")!,
            Text(body, "task_id")!,
            DateTimeOffset.Parse(Text(body, "task_expires_at")!, null, System.Globalization.DateTimeStyles.RoundtripKind),
            body.GetProperty("expires_in").GetInt64(),
            Text(body, "scope")!);

    /// <summary>Revokes a task, its delegated tasks, and their grants.</summary>
    public async Task<int> RevokeTaskAsync(string taskId, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Delete, new Uri(issuer, $"/admin/tasks/{Uri.EscapeDataString(taskId)}"));
        Authorize(request);
        using var response = await http.SendAsync(request, cancellationToken);
        await ThrowUnless(response, HttpStatusCode.OK, "revoking the task");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        return document.RootElement.GetProperty("revoked_tasks").GetInt32();
    }

    /// <summary>Audit records for one human since <paramref name="from"/>, oldest first.</summary>
    public async Task<IReadOnlyList<AuditRecord>> AuditAsync(string sponsor, string from, int limit, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(issuer, $"/audit?sponsor={Uri.EscapeDataString(sponsor)}&from={Uri.EscapeDataString(from)}&limit={limit}"));
        Authorize(request);
        using var response = await http.SendAsync(request, cancellationToken);
        await ThrowUnless(response, HttpStatusCode.OK, "reading the audit ledger");
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

        var records = new List<AuditRecord>();
        foreach (var record in document.RootElement.GetProperty("records").EnumerateArray())
        {
            records.Add(new AuditRecord(
                record.GetProperty("seq").GetInt64(),
                Text(record, "event") ?? string.Empty,
                Text(record, "decision"),
                Text(record, "reason"),
                Text(record, "scope"),
                Text(record, "task_id")));
        }

        return records;
    }

    private void Authorize(HttpRequestMessage request) =>
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", adminKey);

    private static async Task ThrowUnless(HttpResponseMessage response, HttpStatusCode expected, string what)
    {
        if (response.StatusCode != expected)
        {
            throw new InvalidOperationException($"The control plane answered {(int)response.StatusCode} while {what}: {await response.Content.ReadAsStringAsync()}");
        }
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

/// <summary>A live task: one short-lived token, the grant that renews it, and the task itself.</summary>
internal sealed record TaskSession(string AccessToken, string Grant, string TaskId, DateTimeOffset TaskExpiresAt, long ExpiresIn, string Scope);

/// <summary>Either a task or the reason the control plane refused to start one.</summary>
internal sealed record ExchangeResult(TaskSession? Session, string? Error, string? Description);

/// <summary>One audit record, with the fields the demo shows.</summary>
internal sealed record AuditRecord(long Seq, string Event, string? Decision, string? Reason, string? Scope, string? TaskId);
