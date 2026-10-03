using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using SubactId.Core.Scim;

namespace SubactId.Server.Contracts;

/// <summary>
/// The query string of <c>GET /scim/v2/Users</c>: an optional <c>filter</c>, and <c>startIndex</c>
/// and <c>count</c> to page. Only <c>attribute eq "value"</c> on <c>userName</c> or
/// <c>externalId</c> is supported. Any other filter is refused.
/// </summary>
public sealed class ListScimUsersRequest
{
    /// <summary>Page size when none is asked for.</summary>
    public const int DefaultCount = 100;

    /// <summary>Largest page returned, whatever is asked for.</summary>
    public const int MaxCount = 200;

    /// <summary>The filter, for example <c>userName eq "ada@example.com"</c>.</summary>
    [FromQuery(Name = "filter")]
    public string? Filter { get; init; }

    /// <summary>One-based index of the first user returned.</summary>
    [FromQuery(Name = "startIndex")]
    public string? StartIndex { get; init; }

    /// <summary>How many to return, at most <see cref="MaxCount"/>.</summary>
    [FromQuery(Name = "count")]
    public string? Count { get; init; }

    /// <summary>Reads the query into a domain filter.</summary>
    /// <param name="filter">The filter. <c>null</c> when the query cannot be served.</param>
    /// <returns><c>true</c> when the query was understood.</returns>
    public bool TryToFilter(out ScimUserFilter? filter)
    {
        filter = null;

        // startIndex is one-based. A count of zero is allowed and returns only the total.
        var startIndex = Number(StartIndex, 1, minimum: 1);
        var count = Number(Count, DefaultCount, minimum: 0);
        if (startIndex is null || count is null)
        {
            return false;
        }

        string? userName = null;
        string? externalId = null;
        if (!string.IsNullOrWhiteSpace(Filter))
        {
            if (!TryReadEquality(Filter, out var attribute, out var value))
            {
                return false;
            }

            if (string.Equals(attribute, "userName", StringComparison.OrdinalIgnoreCase))
            {
                userName = value;
            }
            else if (string.Equals(attribute, "externalId", StringComparison.OrdinalIgnoreCase))
            {
                externalId = value;
            }
            else
            {
                return false;
            }
        }

        filter = new ScimUserFilter(userName, externalId, startIndex.Value, Math.Min(count.Value, MaxCount));
        return true;
    }

    /// <summary>
    /// Reads <c>attribute eq "value"</c>. The value is parsed as a JSON string, so escaped quotes work.
    /// </summary>
    private static bool TryReadEquality(string expression, out string attribute, out string value)
    {
        attribute = string.Empty;
        value = string.Empty;

        var parts = expression.Trim().Split(' ', 3, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 3 || !string.Equals(parts[1], "eq", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var quoted = parts[2];
        if (quoted.Length < 2 || quoted[0] != '"' || quoted[^1] != '"')
        {
            return false;
        }

        try
        {
            if (JsonSerializer.Deserialize<string>(quoted) is not { } text)
            {
                return false;
            }

            attribute = parts[0];
            value = text;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>The parsed integer, the fallback when absent, or <c>null</c> when invalid or below the minimum.</summary>
    private static int? Number(string? value, int fallback, int minimum)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        return int.TryParse(value, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var parsed) && parsed >= minimum
            ? parsed
            : null;
    }
}

/// <summary>
/// Reads SCIM request bodies, so invalid JSON gets a SCIM-shaped error and no parser detail
/// reaches the client.
/// </summary>
public static class ScimBody
{
    /// <summary>
    /// The media types a client may send a body as (spec section 6, RFC 7644 section 8.1): SCIM's
    /// own, and plain JSON, which some provisioning clients send. Responses are always SCIM's own.
    /// </summary>
    public static readonly string[] AcceptedMediaTypes = [ScimSchemas.MediaType, "application/json"];

    /// <summary>
    /// How request bodies are read. Attribute names are case-insensitive (RFC 7643 section 2.1),
    /// so <c>"Active": false</c> is a deactivation. A name given twice, in any case, is refused
    /// rather than resolved by whichever came last. Only SCIM bodies are read this way.
    /// </summary>
    public static JsonSerializerOptions RequestOptions { get; } = CreateRequestOptions();

    /// <summary>
    /// Whether <paramref name="contentType"/> is one this receiver reads: SCIM or plain JSON, in
    /// UTF-8. JSON between systems is UTF-8 (RFC 8259 section 8.1), and the body is read as UTF-8,
    /// so a body declaring any other charset is refused rather than misread.
    /// </summary>
    /// <param name="contentType">The request's <c>Content-Type</c>.</param>
    public static bool IsAcceptedMediaType(string? contentType) =>
        MediaTypeHeaderValue.TryParse(contentType, out var parsed)
        && AcceptedMediaTypes.Contains(parsed.MediaType.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase)
        && (!parsed.Charset.HasValue || string.Equals(HeaderUtilities.RemoveQuotes(parsed.Charset).Value, "utf-8", StringComparison.OrdinalIgnoreCase));

    private static JsonSerializerOptions CreateRequestOptions()
    {
        var options = SubactIdJson.CreateOptions();
        options.PropertyNameCaseInsensitive = true;
        options.AllowDuplicateProperties = false;
        return options;
    }

    /// <summary>
    /// Reads <typeparamref name="T"/> from <paramref name="request"/>, or <c>null</c> when the
    /// body is not JSON of that shape.
    /// </summary>
    /// <typeparam name="T">The request contract.</typeparam>
    /// <param name="request">The request.</param>
    /// <param name="options">The serializer configuration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public static async Task<T?> ReadAsync<T>(HttpRequest request, JsonSerializerOptions options, CancellationToken cancellationToken)
        where T : class
    {
        ArgumentNullException.ThrowIfNull(request);

        try
        {
            return await JsonSerializer.DeserializeAsync<T>(request.Body, options, cancellationToken);
        }
        catch (Exception exception) when (exception is JsonException or BadHttpRequestException or InvalidOperationException)
        {
            // Includes an oversized body. The sender is only told the body is not valid.
            return null;
        }
    }
}
