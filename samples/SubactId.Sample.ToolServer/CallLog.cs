using System.Text.Json;

namespace SubactId.Sample.ToolServer;

/// <summary>
/// Step 5 of spec section 9: logs one line per call, allowed or refused, naming the human and
/// the agent. The token is never logged.
/// </summary>
internal static class CallLog
{
    private static readonly Lock Gate = new();

    /// <summary>Writes one JSON line about a call.</summary>
    public static void Write(string tool, string decision, string? reason, TaskToken? token)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("ts", DateTimeOffset.UtcNow.ToString("O"));
            writer.WriteString("tool", tool);
            writer.WriteString("decision", decision);
            writer.WriteString("reason", reason);
            writer.WriteString("sub", token?.Subject);
            writer.WriteString("act", token?.Agent);
            writer.WriteString("task_id", token?.TaskId);
            writer.WriteString("jti", token?.Jti);
            writer.WriteString("scope", token is null ? null : string.Join(' ', token.Scopes));
            writer.WriteEndObject();
        }

        lock (Gate)
        {
            Console.Out.WriteLine(System.Text.Encoding.UTF8.GetString(buffer.ToArray()));
        }
    }
}
