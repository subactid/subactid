using System.Text.Json;
using SubactId.Core.Agents;
using SubactId.Core.Validation;
using SubactId.Tokens.Upstream;

namespace SubactId.Server.Contracts;

/// <summary>
/// Reads an inline <c>jwks</c> from a registration request. Shared by register and patch.
/// </summary>
internal static class AgentJwksBinding
{
    /// <summary>
    /// Parses a key set and checks that this server can verify an assertion with every key in it.
    /// Uses the same parser as client authentication.
    /// </summary>
    /// <param name="json">The key set as posted.</param>
    /// <param name="jwks">The parsed set; <c>null</c> when there are errors.</param>
    /// <returns>Per-field errors, empty when valid.</returns>
    public static IReadOnlyList<ValidationError> TryRead(JsonElement json, out AgentJwks? jwks)
    {
        var errors = AgentJwks.TryParse(json, "jwks", out jwks);
        if (errors.Count > 0)
        {
            return errors;
        }

        var keys = jwks!.Keys;
        IReadOnlyDictionary<string, UpstreamKey> usable;
        try
        {
            usable = UpstreamJwksParser.Parse(jwks.ToJson());
        }
        catch (UpstreamDiscoveryException)
        {
            jwks = null;
            return [new ValidationError("jwks", "could not be read as a key set.")];
        }

        try
        {
            // Every key must be usable, or an assertion naming a dropped key would fail as unknown.
            var unusable = new List<ValidationError>();
            for (var i = 0; i < keys.Count; i++)
            {
                if (!usable.ContainsKey(keys[i].Kid))
                {
                    unusable.Add(new ValidationError($"jwks.keys[{i}]", "is not a key this server can verify an assertion with; it needs a supported type, curve and size, and an algorithm this server accepts."));
                }
            }

            if (unusable.Count > 0)
            {
                jwks = null;
            }

            return unusable;
        }
        finally
        {
            foreach (var key in usable.Values)
            {
                key.Dispose();
            }
        }
    }
}
