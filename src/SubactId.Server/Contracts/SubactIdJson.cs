using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>
/// The JSON configuration every endpoint uses: snake_case names, durations as ISO 8601
/// (<c>PT5M</c>) and timestamps as UTC ISO 8601 with a <c>Z</c>. Nulls are written explicitly.
/// </summary>
public static class SubactIdJson
{
    /// <summary>Applies the configuration to <paramref name="options"/>.</summary>
    /// <param name="options">The serializer options to configure.</param>
    public static void Configure(JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
        options.DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower;
        options.DefaultIgnoreCondition = JsonIgnoreCondition.Never;
        options.Converters.Add(new Iso8601DurationConverter());
        options.Converters.Add(new UtcTimestampConverter());
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
    }

    /// <summary>
    /// A shared configured instance, for code that calls this API. Endpoints are configured
    /// through <see cref="Configure"/> instead.
    /// </summary>
    public static JsonSerializerOptions Options { get; } = CreateOptions();

    /// <summary>A fresh, configured <see cref="JsonSerializerOptions"/>.</summary>
    public static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions();
        Configure(options);
        return options;
    }
}
