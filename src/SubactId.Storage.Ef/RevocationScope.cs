using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SubactId.Storage.Ef;

/// <summary>
/// What a revocation by person, session or agent reaches, as the names its lock is taken under. An
/// exchange takes every scope its new task falls in; a revocation takes the one it revokes.
/// </summary>
public static class RevocationScope
{
    /// <summary>Everything acting for one sponsor key: blocks, kill switches and signals.</summary>
    /// <param name="sponsorKey">The human, as the configured key claim names them.</param>
    public static string Sponsor(string sponsorKey) => "sponsor:" + sponsorKey;

    /// <summary>Everything acting for one upstream <c>sub</c>: a logout that names no session.</summary>
    /// <param name="subject">The human's upstream <c>sub</c>.</param>
    public static string Subject(string subject) => "subject:" + subject;

    /// <summary>Everything issued to one agent: its kill switch.</summary>
    /// <param name="agentId">The agent.</param>
    public static string Agent(string agentId) => "agent:" + agentId;

    /// <summary>Everything started from one identity provider session: a logout that names it.</summary>
    /// <param name="sessionId">The provider's session identifier.</param>
    public static string Session(string sessionId) => "session:" + sessionId;

    /// <summary>
    /// A 64-bit lock key for <paramref name="scope"/>: the first eight bytes of a SHA-256 under a
    /// prefix of its own, so it does not meet the audit seal's keys. Two scopes sharing a key only
    /// wait for each other more often.
    /// </summary>
    /// <param name="scope">A scope from this class.</param>
    public static long LockKey(string scope)
    {
        ArgumentException.ThrowIfNullOrEmpty(scope);

        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.UTF8.GetBytes("subactid.revocation-scope\n" + scope), hash);
        return BinaryPrimitives.ReadInt64BigEndian(hash);
    }
}
