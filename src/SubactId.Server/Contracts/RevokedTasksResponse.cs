using System.Text.Json.Serialization;

namespace SubactId.Server.Contracts;

/// <summary>The result of an admin revocation: the number of live tasks it ended. Zero on a repeat.</summary>
/// <param name="RevokedTasks">Tasks that were live and are now revoked, descendants included.</param>
public sealed record RevokedTasksResponse([property: JsonPropertyName("revoked_tasks")] int RevokedTasks);
