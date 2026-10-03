using System.Text.Json.Serialization;
using SubactId.Core.Audit;

namespace SubactId.Server.Contracts;

/// <summary>One page of <c>GET /audit</c>: the matching records oldest first, and where the next page starts.</summary>
/// <param name="Records">The records of this page, each in the shape of spec section 7.</param>
/// <param name="NextCursor">Pass as <c>cursor</c> for the next page. <c>null</c> on the last page.</param>
/// <param name="ArchivedBefore">
/// The earliest instant the online ledger still holds, or <c>null</c> when nothing has been
/// archived. Records older than this have been exported and dropped.
/// </param>
public sealed record AuditQueryResponse(
    [property: JsonPropertyName("records")] IReadOnlyList<AuditRecordPayload> Records,
    [property: JsonPropertyName("next_cursor")] string? NextCursor,
    [property: JsonPropertyName("archived_before")] DateTimeOffset? ArchivedBefore)
{
    /// <summary>
    /// Builds the page from up to one record more than the page size. The extra record only
    /// signals a next page and is not returned.
    /// </summary>
    /// <param name="records">Up to <paramref name="limit"/> + 1 records.</param>
    /// <param name="limit">The page size asked for.</param>
    /// <param name="sealing">The checkpoint sealing each record, by sequence number. Unsealed records are absent.</param>
    /// <param name="archived">The most recently archived month, or <c>null</c> when nothing has been archived.</param>
    public static AuditQueryResponse From(IReadOnlyList<AuditLedgerRecord> records, int limit, IReadOnlyDictionary<long, long> sealing, AuditArchive? archived = null)
    {
        ArgumentNullException.ThrowIfNull(records);
        ArgumentNullException.ThrowIfNull(sealing);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        var page = records.Take(limit).ToList();
        var next = records.Count > limit ? AuditCursorCodec.Encode(page[^1]) : null;
        return new AuditQueryResponse(
            page.Select(record => AuditRecordPayload.From(record, Sealing(sealing, record.Seq))).ToList(),
            next,
            archived?.ArchivedBefore);
    }

    /// <summary>The checkpoint that seals <paramref name="seq"/>, or <c>null</c> when it is not sealed yet.</summary>
    private static long? Sealing(IReadOnlyDictionary<long, long> sealing, long seq) =>
        sealing.TryGetValue(seq, out var checkpoint) ? checkpoint : null;
}
