using System.Net.Http.Headers;
using System.Net.Http.Json;
using SubactId.Core.Audit;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;

namespace SubactId.Server.Audit;

/// <summary>
/// Posts each batch of ledger records to the configured sink as one JSON document. Any non-2xx
/// answer is a failed delivery. The response body is never read or logged.
/// </summary>
public sealed class HttpAuditSink(IHttpClientFactory clients, AuditOptions options) : IAuditSink
{
    /// <summary>Name of the HTTP client used for deliveries.</summary>
    public const string HttpClientName = "audit-sink";

    private static readonly System.Text.Json.JsonSerializerOptions Json = SubactIdJson.CreateOptions();

    /// <inheritdoc />
    public async Task DeliverAsync(IReadOnlyList<AuditLedgerRecord> records, IReadOnlyDictionary<long, long> sealing, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(sealing);

        if (records.Count == 0)
        {
            return;
        }

        var sinkUrl = options.SinkUrl ?? throw new InvalidOperationException("No audit sink is configured.");
        using var client = clients.CreateClient(HttpClientName);
        using var request = new HttpRequestMessage(HttpMethod.Post, sinkUrl);
        if (options.SinkBearerToken is { } token)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        var payload = new AuditDeliveryPayload
        {
            Records = records.Select(record => AuditRecordPayload.From(record, sealing.TryGetValue(record.Seq, out var checkpoint) ? checkpoint : null)).ToList(),
        };

        request.Content = JsonContent.Create(payload, options: Json);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            throw new AuditSinkException($"The audit sink answered {(int)response.StatusCode}.");
        }
    }
}

/// <summary>The sink refused a delivery. The message names the status only, never the sink's body or credentials.</summary>
public sealed class AuditSinkException(string message) : Exception(message);
