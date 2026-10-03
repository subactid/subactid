using System.Buffers.Text;
using System.Globalization;
using System.Text;
using SubactId.Core.Audit;

namespace SubactId.Server.Contracts;

/// <summary>
/// The opaque page cursor of <c>GET /audit</c>: a record's time and sequence number, base64url
/// encoded. Not a secret.
/// </summary>
public static class AuditCursorCodec
{
    /// <summary>Longest cursor accepted.</summary>
    public const int MaxLength = 64;

    /// <summary>The cursor for continuing after <paramref name="record"/>.</summary>
    /// <param name="record">The last record of a page.</param>
    public static string Encode(AuditLedgerRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);

        return Base64Url.EncodeToString(Encoding.ASCII.GetBytes(FormattableString.Invariant($"{record.Event.Ts.UtcTicks}:{record.Seq}")));
    }

    /// <summary>The position a cursor names, or <c>null</c> when it is not one this server produced.</summary>
    /// <param name="cursor">The cursor.</param>
    public static AuditCursor? Decode(string cursor)
    {
        ArgumentNullException.ThrowIfNull(cursor);

        if (cursor.Length == 0 || cursor.Length > MaxLength || !Base64Url.IsValid(cursor))
        {
            return null;
        }

        var parts = Encoding.ASCII.GetString(Base64Url.DecodeFromChars(cursor)).Split(':');
        if (parts.Length != 2
            || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var ticks)
            || !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var seq)
            || ticks > DateTimeOffset.MaxValue.UtcTicks
            || seq < 1)
        {
            return null;
        }

        return new AuditCursor(new DateTimeOffset(ticks, TimeSpan.Zero), seq);
    }
}
