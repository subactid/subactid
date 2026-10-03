using Microsoft.EntityFrameworkCore;
using SubactId.Core.Agents;
using SubactId.Core.Audit;
using SubactId.Core.Delegation;
using SubactId.Core.Scim;
using SubactId.Core.Sponsors;
using SubactId.Storage.Ef.Schema;

namespace SubactId.Storage.Ef.Repositories;

/// <summary>Conversions between domain records and persistence rows.</summary>
internal static class RowMapping
{
    /// <summary>
    /// Reads back a stored key set written by <see cref="AgentJwks.ToJson"/>. A row that does not
    /// parse is treated as corrupt.
    /// </summary>
    private static AgentJwks? ParseJwks(string? json)
    {
        if (json is null)
        {
            return null;
        }

        var errors = AgentJwks.TryParse(json, "jwks", out var jwks);
        return errors.Count == 0
            ? jwks
            : throw new InvalidOperationException("A stored agent key set could not be read back.");
    }

    public static Agent ToDomain(this AgentRow row) => new(
        row.AgentId,
        row.DisplayName,
        row.SponsorRequired,
        row.AllowedScopes,
        row.AllowedAudiences,
        row.MaxTaskTtl,
        row.MaxTokenTtl,
        row.MaxDelegationDepth,
        row.HighRiskAudiences,
        row.JwksUri is null ? null : new Uri(row.JwksUri),
        ParseJwks(row.Jwks),
        row.Enabled,
        row.CreatedAt,
        row.UpdatedAt);

    public static AgentRow ToRow(this Agent agent) => new()
    {
        AgentId = agent.AgentId,
        DisplayName = agent.DisplayName,
        SponsorRequired = agent.SponsorRequired,
        AllowedScopes = [.. agent.AllowedScopes],
        AllowedAudiences = [.. agent.AllowedAudiences],
        MaxTaskTtl = agent.MaxTaskTtl,
        MaxTokenTtl = agent.MaxTokenTtl,
        MaxDelegationDepth = agent.MaxDelegationDepth,
        HighRiskAudiences = [.. agent.HighRiskAudiences],
        JwksUri = agent.JwksUri?.ToString(),
        Jwks = agent.Jwks?.ToJson(),
        Enabled = agent.Enabled,
        CreatedAt = agent.CreatedAt.ToUniversalTime(),
        UpdatedAt = agent.UpdatedAt.ToUniversalTime(),
    };

    public static void CopyFrom(this AgentRow row, Agent agent)
    {
        row.DisplayName = agent.DisplayName;
        row.SponsorRequired = agent.SponsorRequired;
        row.AllowedScopes = [.. agent.AllowedScopes];
        row.AllowedAudiences = [.. agent.AllowedAudiences];
        row.MaxTaskTtl = agent.MaxTaskTtl;
        row.MaxTokenTtl = agent.MaxTokenTtl;
        row.MaxDelegationDepth = agent.MaxDelegationDepth;
        row.HighRiskAudiences = [.. agent.HighRiskAudiences];
        row.JwksUri = agent.JwksUri?.ToString();
        row.Jwks = agent.Jwks?.ToJson();
        row.Enabled = agent.Enabled;
        row.CreatedAt = agent.CreatedAt.ToUniversalTime();
        row.UpdatedAt = agent.UpdatedAt.ToUniversalTime();
    }

    public static DelegationTask ToDomain(this TaskRow row) => new(
        row.TaskId,
        row.AgentId,
        row.Sponsor,
        row.SponsorKey,
        row.SessionId,
        row.ParentTaskId,
        row.DelegationDepth,
        row.Audience,
        row.Scopes,
        ToStatus(row.Status),
        row.CreatedAt,
        row.ExpiresAt,
        row.RevokedAt,
        row.RevocationReason);

    public static TaskRow ToRow(this DelegationTask task) => new()
    {
        TaskId = task.TaskId,
        AgentId = task.AgentId,
        Sponsor = task.Sponsor,
        SponsorKey = task.SponsorKey,
        SessionId = task.SessionId,
        ParentTaskId = task.ParentTaskId,
        DelegationDepth = task.DelegationDepth,
        Audience = task.Audience,
        Scopes = [.. task.Scopes],
        Status = ToColumn(task.Status),
        CreatedAt = task.CreatedAt.ToUniversalTime(),
        ExpiresAt = task.ExpiresAt.ToUniversalTime(),
        RevokedAt = task.RevokedAt?.ToUniversalTime(),
        RevocationReason = task.RevocationReason,
    };

    public static TaskGrant ToDomain(this TaskGrantRow row) => new(
        row.GrantHash,
        row.TaskId,
        row.AgentId,
        row.Scopes,
        row.CreatedAt,
        row.ExpiresAt,
        row.RevokedAt,
        row.LastUsedAt,
        row.Renewals);

    public static TaskGrantRow ToRow(this TaskGrant grant) => new()
    {
        GrantHash = grant.GrantHash.ToArray(),
        TaskId = grant.TaskId,
        AgentId = grant.AgentId,
        Scopes = [.. grant.Scopes],
        CreatedAt = grant.CreatedAt.ToUniversalTime(),
        ExpiresAt = grant.ExpiresAt.ToUniversalTime(),
        RevokedAt = grant.RevokedAt?.ToUniversalTime(),
        LastUsedAt = grant.LastUsedAt?.ToUniversalTime(),
        Renewals = grant.Renewals,
    };

    public static string ToColumn(DelegationTaskStatus status) => status switch
    {
        DelegationTaskStatus.Active => TaskRow.StatusActive,
        DelegationTaskStatus.Expired => TaskRow.StatusExpired,
        DelegationTaskStatus.Revoked => TaskRow.StatusRevoked,
        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown task status."),
    };

    private static DelegationTaskStatus ToStatus(string column) => column switch
    {
        TaskRow.StatusActive => DelegationTaskStatus.Active,
        TaskRow.StatusExpired => DelegationTaskStatus.Expired,
        TaskRow.StatusRevoked => DelegationTaskStatus.Revoked,
        _ => throw new InvalidOperationException($"Unknown task status '{column}' in the database."),
    };

    public static SponsorBlock ToDomain(this SponsorBlockRow row) => new(
        row.SponsorKey,
        ToSource(row.Source),
        ToKind(row.Kind),
        row.BlockedAt,
        row.PlacedByDeletion);

    public static SponsorBlockRow ToRow(this SponsorBlock block) => new()
    {
        SponsorKey = block.SponsorKey,
        Source = ToColumn(block.Source),
        Kind = ToColumn(block.Kind),
        BlockedAt = block.BlockedAt.ToUniversalTime(),
        PlacedByDeletion = block.PlacedByDeletion,
    };

    public static string ToColumn(SponsorBlockSource source) => source switch
    {
        SponsorBlockSource.Admin => SponsorBlockRow.SourceAdmin,
        SponsorBlockSource.Poll => SponsorBlockRow.SourcePoll,
        SponsorBlockSource.Logout => SponsorBlockRow.SourceLogout,
        SponsorBlockSource.Scim => SponsorBlockRow.SourceScim,
        SponsorBlockSource.Ssf => SponsorBlockRow.SourceSsf,
        _ => throw new ArgumentOutOfRangeException(nameof(source), source, "Unknown sponsor block source."),
    };

    public static string ToColumn(SponsorBlockKind kind) => kind switch
    {
        SponsorBlockKind.Disabled => SponsorBlockRow.KindDisabled,
        SponsorBlockKind.Deleted => SponsorBlockRow.KindDeleted,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown sponsor block kind."),
    };

    private static SponsorBlockSource ToSource(string column) => column switch
    {
        SponsorBlockRow.SourceAdmin => SponsorBlockSource.Admin,
        SponsorBlockRow.SourcePoll => SponsorBlockSource.Poll,
        SponsorBlockRow.SourceLogout => SponsorBlockSource.Logout,
        SponsorBlockRow.SourceScim => SponsorBlockSource.Scim,
        SponsorBlockRow.SourceSsf => SponsorBlockSource.Ssf,
        _ => throw new InvalidOperationException($"Unknown sponsor block source '{column}' in the database."),
    };

    private static SponsorBlockKind ToKind(string column) => column switch
    {
        SponsorBlockRow.KindDisabled => SponsorBlockKind.Disabled,
        SponsorBlockRow.KindDeleted => SponsorBlockKind.Deleted,
        _ => throw new InvalidOperationException($"Unknown sponsor block kind '{column}' in the database."),
    };

    /// <summary>Runs <paramref name="query"/> as one projection of the ledger's columns and maps each row to its record.</summary>
    public static async Task<IReadOnlyList<AuditLedgerRecord>> ToLedgerRecordsAsync(this IQueryable<AuditEventRow> query, CancellationToken cancellationToken)
    {
        var rows = await query
            .Select(e => new { e.Seq, e.Ts, e.Event, e.TaskId, e.AgentId, e.Sponsor, e.Audience, e.Scope, e.Jti, e.DelegationDepth, e.Decision, e.Reason, e.Count, e.Detail })
            .ToListAsync(cancellationToken);

        return rows.Select(r => new AuditLedgerRecord(
                r.Seq,
                new AuditEvent(r.Ts, r.Event, r.TaskId, r.AgentId, r.Sponsor, r.Audience, r.Scope, r.Jti, r.DelegationDepth, AuditDecisionCodes.FromCode(r.Decision), r.Reason, r.Count, r.Detail)))
            .ToList();
    }

    /// <summary>The archived month a row holds.</summary>
    /// <param name="row">The row.</param>
    public static AuditArchive ToDomain(this AuditArchiveRow row)
    {
        ArgumentNullException.ThrowIfNull(row);

        return new AuditArchive(
            row.Month,
            row.Partition,
            row.FirstCheckpointId,
            row.LastCheckpointId,
            row.FirstSeq,
            row.LastSeq,
            row.Records,
            row.Location,
            row.Digest,
            row.ArchivedAt);
    }

    /// <summary>The row for an archived month.</summary>
    /// <param name="archive">The archive.</param>
    public static AuditArchiveRow ToRow(this AuditArchive archive)
    {
        ArgumentNullException.ThrowIfNull(archive);

        return new AuditArchiveRow
        {
            Month = archive.Month.ToUniversalTime(),
            Partition = archive.Partition,
            FirstCheckpointId = archive.FirstCheckpointId,
            LastCheckpointId = archive.LastCheckpointId,
            FirstSeq = archive.FirstSeq,
            LastSeq = archive.LastSeq,
            Records = archive.Records,
            Location = archive.Location,
            Digest = archive.Digest.ToArray(),
            ArchivedAt = archive.ArchivedAt.ToUniversalTime(),
        };
    }

    /// <summary>The row for a checkpoint.</summary>
    /// <param name="checkpoint">The checkpoint.</param>
    public static AuditCheckpointRow ToRow(this AuditCheckpoint checkpoint)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        return new AuditCheckpointRow
        {
            CheckpointId = checkpoint.CheckpointId,
            FirstSeq = checkpoint.FirstSeq,
            LastSeq = checkpoint.LastSeq,
            TreeSize = checkpoint.TreeSize,
            RootHash = checkpoint.RootHash.ToArray(),
            PrevCheckpointHash = checkpoint.PrevCheckpointHash?.ToArray(),
            ClosedAt = checkpoint.ClosedAt.ToUniversalTime(),
            Kid = checkpoint.Kid,
            Signature = checkpoint.Signature.ToArray(),
        };
    }

    /// <summary>Runs <paramref name="query"/> as one projection of the checkpoint columns and maps each row.</summary>
    public static async Task<IReadOnlyList<AuditCheckpoint>> ToCheckpointsAsync(this IQueryable<AuditCheckpointRow> query, CancellationToken cancellationToken)
    {
        var rows = await query
            .Select(c => new { c.CheckpointId, c.FirstSeq, c.LastSeq, c.TreeSize, c.RootHash, c.PrevCheckpointHash, c.ClosedAt, c.Kid, c.Signature })
            .ToListAsync(cancellationToken);

        return rows.Select(c => new AuditCheckpoint(
                c.CheckpointId,
                c.FirstSeq,
                c.LastSeq,
                c.TreeSize,
                c.RootHash,
                // Explicit because the implicit conversion turns null into an empty value. The first
                // checkpoint's prev_checkpoint_hash must stay null (spec section 7).
                c.PrevCheckpointHash is { } previous ? previous : (ReadOnlyMemory<byte>?)null,
                c.ClosedAt,
                c.Kid,
                c.Signature))
            .ToList();
    }

    /// <summary>The SCIM user a row holds.</summary>
    /// <param name="row">The row.</param>
    public static ScimUser ToDomain(this ScimUserRow row) => new(
        row.Id,
        row.UserName,
        row.ExternalId,
        row.SponsorKey,
        row.Active,
        row.CreatedAt,
        row.UpdatedAt);

    /// <summary>The row for a SCIM user.</summary>
    /// <param name="user">The user.</param>
    public static ScimUserRow ToRow(this ScimUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        return new ScimUserRow
        {
            Id = user.Id,
            UserName = user.UserName,
            ExternalId = user.ExternalId,
            SponsorKey = user.SponsorKey,
            Active = user.Active,
            CreatedAt = user.CreatedAt.ToUniversalTime(),
            UpdatedAt = user.UpdatedAt.ToUniversalTime(),
        };
    }
}
