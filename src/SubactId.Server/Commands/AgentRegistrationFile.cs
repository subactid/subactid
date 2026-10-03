using System.Globalization;
using System.Text.Json;
using SubactId.Core.Agents;
using SubactId.Core.Validation;
using SubactId.Server.Contracts;
using YamlDotNet.RepresentationModel;

namespace SubactId.Server.Commands;

/// <summary>
/// One agent registration stored as a file: the admin API's request body written as YAML, with
/// the spec's field names.
/// </summary>
/// <param name="Path">Where the file was read from, for error messages.</param>
/// <param name="Request">The registration, ready to validate and send.</param>
public sealed record AgentRegistrationFile(string Path, RegisterAgentRequest Request)
{
    /// <summary>Default task lifetime written by <c>agent init</c>.</summary>
    public static readonly TimeSpan DefaultTaskTtl = TimeSpan.FromMinutes(30);

    /// <summary>Default token lifetime written by <c>agent init</c>.</summary>
    public static readonly TimeSpan DefaultTokenTtl = TimeSpan.FromMinutes(5);

    /// <summary>Reads a registration from YAML text, reporting per-field errors.</summary>
    /// <param name="path">Where the text came from.</param>
    /// <param name="yaml">The file's content.</param>
    /// <param name="file">The parsed registration; <c>null</c> when there are errors.</param>
    /// <returns>Per-field errors, empty when the file parsed.</returns>
    public static IReadOnlyList<ValidationError> TryRead(string path, string yaml, out AgentRegistrationFile? file)
    {
        file = null;
        var stream = new YamlStream();
        try
        {
            stream.Load(new StringReader(yaml));
        }
        catch (YamlDotNet.Core.YamlException exception)
        {
            return [new ValidationError("file", $"is not valid YAML: {exception.Message}")];
        }

        if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            return [new ValidationError("file", "must hold exactly one YAML document, a mapping of registration fields.")];
        }

        var errors = new List<ValidationError>();
        var known = new HashSet<string>(StringComparer.Ordinal)
        {
            "agent_id", "display_name", "sponsor_required", "allowed_scopes", "allowed_audiences",
            "max_task_ttl", "max_token_ttl", "max_delegation_depth", "high_risk_audiences",
            "jwks_uri", "jwks",
        };

        foreach (var key in root.Children.Keys.OfType<YamlScalarNode>())
        {
            if (key.Value is { } name && !known.Contains(name))
            {
                // Unknown fields are errors, so a typo cannot silently drop a scope or audience.
                errors.Add(new(name, "is not a registration field."));
            }
        }

        var request = new RegisterAgentRequest(
            Scalar(root, "agent_id", errors),
            Scalar(root, "display_name", errors),
            Boolean(root, "sponsor_required", errors),
            Sequence(root, "allowed_scopes", errors),
            Sequence(root, "allowed_audiences", errors),
            Duration(root, "max_task_ttl", errors),
            Duration(root, "max_token_ttl", errors),
            Integer(root, "max_delegation_depth", errors),
            Sequence(root, "high_risk_audiences", errors),
            Scalar(root, "jwks_uri", errors),
            Jwks(root, "jwks", errors));

        if (errors.Count > 0)
        {
            return errors;
        }

        file = new AgentRegistrationFile(path, request);
        return [];
    }

    /// <summary>Writes a registration as the YAML <c>agent init</c> produces, comments and all.</summary>
    /// <param name="agentId">The agent's identifier.</param>
    /// <param name="jwks">The agent's public keys, embedded so the file needs no hosting.</param>
    /// <returns>The file's content.</returns>
    public static string Write(string agentId, AgentJwks jwks)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentId);
        ArgumentNullException.ThrowIfNull(jwks);

        var lines = new List<string>
        {
            "# A Subact ID agent registration. Apply it with:",
            $"#   SubactId.Server {AgentCommand.Name} {AgentCommand.ApplyVerb} <this file> --server https://subactid.example.com",
            "#",
            "# The defaults below are the tight ones. Fill in the two empty lists before applying:",
            "# an agent that names no scope or no audience is refused, not registered.",
            $"agent_id: {agentId}",
            $"display_name: {agentId}",
            "",
            "# No token without a human subject token. True is the only value v0.1 accepts; the",
            "# scheduled-agent path, where a service sponsor stands in for a person, is not built yet.",
            "sponsor_required: true",
            "",
            "# What this agent may ever be granted. Subact ID only ever narrows from what the human's own",
            "# token already carries, so nothing here can widen anything. Fill in both lists before",
            "# applying; apply refuses an empty one.",
            "allowed_scopes: []",
            "",
            "# The audiences it may request tokens for.",
            "allowed_audiences: []",
            "",
            "# The whole task, then each individual token. The split is what makes a long job safe:",
            "# a six-hour task never holds a six-hour credential.",
            $"max_task_ttl: {Iso8601DurationConverter.Format(DefaultTaskTtl)}",
            $"max_token_ttl: {Iso8601DurationConverter.Format(DefaultTokenTtl)}",
            "",
            "# How deep this agent may delegate onward. 1 means it may not.",
            "max_delegation_depth: 1",
            "",
            "# Audiences that force per-call introspection instead of local validation.",
            "high_risk_audiences: []",
            "",
            "# The agent's public keys, held by the control plane and served at",
            $"#   /agents/{agentId}/jwks.json",
            "# so this agent needs no public endpoint of its own and Subact ID needs no egress to reach",
            "# one. The private half is beside this file and belongs in a secret store, not here.",
            "jwks:",
            "  keys:",
        };

        foreach (var key in jwks.Keys)
        {
            lines.Add($"    - kid: {key.Kid}");
            foreach (var (name, value) in new[]
                     {
                         ("kty", key.Kty), ("crv", key.Crv), ("x", key.X), ("y", key.Y),
                         ("n", key.N), ("e", key.E), ("alg", key.Alg), ("use", key.Use),
                     })
            {
                if (value is not null)
                {
                    lines.Add($"      {name}: {value}");
                }
            }
        }

        return string.Join('\n', lines) + '\n';
    }

    private static string? Scalar(YamlMappingNode root, string field, List<ValidationError> errors) =>
        Node(root, field) is { } node
            ? node is YamlScalarNode { Value: { } value } && value.Length > 0 ? value : Fail<string>(field, "must be text.", errors)
            : null;

    private static bool? Boolean(YamlMappingNode root, string field, List<ValidationError> errors) =>
        Node(root, field) is { } node
            ? node is YamlScalarNode { Value: { } value } && bool.TryParse(value, out var parsed) ? parsed : Fail<bool?>(field, "must be true or false.", errors)
            : null;

    private static int? Integer(YamlMappingNode root, string field, List<ValidationError> errors) =>
        Node(root, field) is { } node
            ? node is YamlScalarNode { Value: { } value } && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
                ? parsed
                : Fail<int?>(field, "must be a whole number.", errors)
            : null;

    private static TimeSpan? Duration(YamlMappingNode root, string field, List<ValidationError> errors) =>
        Node(root, field) is { } node
            ? node is YamlScalarNode { Value: { } value } && Iso8601DurationConverter.TryParse(value, out var parsed)
                ? parsed
                : Fail<TimeSpan?>(field, "must be an ISO 8601 duration such as PT5M.", errors)
            : null;

    private static IReadOnlyList<string>? Sequence(YamlMappingNode root, string field, List<ValidationError> errors)
    {
        if (Node(root, field) is not { } node)
        {
            return null;
        }

        if (node is not YamlSequenceNode sequence)
        {
            return Fail<IReadOnlyList<string>>(field, "must be a list.", errors);
        }

        var values = new List<string>();
        foreach (var item in sequence)
        {
            if (item is YamlScalarNode { Value: { } value } && value.Length > 0)
            {
                values.Add(value);
            }
            else
            {
                return Fail<IReadOnlyList<string>>(field, "must be a list of non-empty text.", errors);
            }
        }

        return values;
    }

    private static JsonElement? Jwks(YamlMappingNode root, string field, List<ValidationError> errors)
    {
        if (Node(root, field) is not { } node)
        {
            return null;
        }

        // Converted to JSON and validated by the same rules as the admin API.
        try
        {
            return JsonSerializer.Deserialize<JsonElement>(ToJson(node));
        }
        catch (JsonException)
        {
            return Fail<JsonElement?>(field, "must be a JSON Web Key Set.", errors);
        }
    }

    private static string ToJson(YamlNode node) => node switch
    {
        YamlScalarNode scalar => JsonSerializer.Serialize(scalar.Value),
        YamlSequenceNode sequence => "[" + string.Join(",", sequence.Select(ToJson)) + "]",
        YamlMappingNode mapping => "{" + string.Join(",", mapping.Children.Select(
            pair => $"{JsonSerializer.Serialize((pair.Key as YamlScalarNode)?.Value ?? string.Empty)}:{ToJson(pair.Value)}")) + "}",
        _ => "null",
    };

    private static YamlNode? Node(YamlMappingNode root, string field) =>
        root.Children.TryGetValue(new YamlScalarNode(field), out var node) && node is not YamlScalarNode { Value: null } ? node : null;

    private static T? Fail<T>(string field, string message, List<ValidationError> errors)
    {
        errors.Add(new(field, message));
        return default;
    }
}
