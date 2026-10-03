namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// One month of the ledger that has been exported and removed (spec section 7.5).
/// <para>
/// Records how far back the online ledger goes and which checkpoint a verification walk starts at.
/// Written in the same transaction as the <c>audit.archived</c> record, before the partition is
/// detached.
/// </para>
/// </summary>
public sealed class AuditArchiveRow
{
    /// <summary>First instant of the archived month, UTC.</summary>
    public DateTimeOffset Month { get; set; }

    /// <summary>The partition that was detached and dropped.</summary>
    public required string Partition { get; set; }

    /// <summary>First checkpoint in the export.</summary>
    public long FirstCheckpointId { get; set; }

    /// <summary>Last checkpoint in the export, or one below the first when the export holds none.</summary>
    public long LastCheckpointId { get; set; }

    /// <summary>First sequence number in the export.</summary>
    public long FirstSeq { get; set; }

    /// <summary>Last sequence number in the export, or one below the first when the export holds no records.</summary>
    public long LastSeq { get; set; }

    /// <summary>Records in the export.</summary>
    public long Records { get; set; }

    /// <summary>Where the export was written.</summary>
    public required string Location { get; set; }

    /// <summary>SHA-256 of the export, exactly as it was written.</summary>
    public required byte[] Digest { get; set; }

    /// <summary>When the export was taken.</summary>
    public DateTimeOffset ArchivedAt { get; set; }
}
