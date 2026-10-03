using System.Text.Json.Serialization;
using SubactId.Core.Sponsors;

namespace SubactId.Server.Contracts;

/// <summary>
/// A human this control plane will not act for. Carries only the block's own fields.
/// </summary>
/// <param name="SponsorKey">The human, as the configured key claim names them.</param>
/// <param name="Source">What placed the block. Only that source may lift it.</param>
/// <param name="Kind">Whether the person is disabled or gone.</param>
/// <param name="BlockedAt">When the block was placed.</param>
public sealed record SponsorResponse(
    [property: JsonPropertyName("sponsor_key")] string SponsorKey,
    [property: JsonPropertyName("source")] string Source,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("blocked_at")] DateTimeOffset BlockedAt)
{
    /// <summary>The block as the admin API reports it.</summary>
    /// <param name="block">The stored block.</param>
    public static SponsorResponse From(SponsorBlock block)
    {
        ArgumentNullException.ThrowIfNull(block);

        return new SponsorResponse(block.SponsorKey, Name(block.Source), Name(block.Kind), block.BlockedAt);
    }

    /// <summary>The wire name of a source. Spelt out so renaming an enum member does not change the API.</summary>
    private static string Name(SponsorBlockSource source) => source switch
    {
        SponsorBlockSource.Admin => "admin",
        SponsorBlockSource.Poll => "poll",
        SponsorBlockSource.Logout => "logout",
        SponsorBlockSource.Scim => "scim",
        SponsorBlockSource.Ssf => "ssf",
        _ => throw new ArgumentOutOfRangeException(nameof(source), source, "Unknown sponsor block source."),
    };

    /// <summary>The wire name of a kind, for the same reason.</summary>
    private static string Name(SponsorBlockKind kind) => kind switch
    {
        SponsorBlockKind.Disabled => "disabled",
        SponsorBlockKind.Deleted => "deleted",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown sponsor block kind."),
    };
}

/// <summary>The result of blocking a human: the block and the number of tasks it ended.</summary>
/// <param name="Sponsor">The block.</param>
/// <param name="RevokedTasks">Tasks that were live and are now revoked, descendants included.</param>
public sealed record SponsorBlockedResponse(
    [property: JsonPropertyName("sponsor")] SponsorResponse Sponsor,
    [property: JsonPropertyName("revoked_tasks")] int RevokedTasks);
