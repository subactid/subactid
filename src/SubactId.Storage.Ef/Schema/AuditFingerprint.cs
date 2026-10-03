using System.Reflection;

namespace SubactId.Storage.Ef.Schema;

/// <summary>
/// A short fingerprint a provider may index the ledger's <c>sponsor</c> and <c>agent_id</c> by,
/// to keep the indexes small. Queries still compare the full string, so collisions cost a row read
/// and never change an answer.
/// <para>
/// Not a security hash. It is a bucket number computed by the database.
/// </para>
/// </summary>
public static class AuditFingerprint
{
    /// <summary>The <see cref="Of"/> method, for a provider that maps it to a function of its own.</summary>
    public static MethodInfo Method { get; } = typeof(AuditFingerprint).GetMethod(nameof(Of))!;

    /// <summary>
    /// The fingerprint of <paramref name="value"/>, as the database computes it. Only translated to
    /// SQL, never run here, so both sides of a comparison use the database's function.
    /// </summary>
    /// <param name="value">The string to fingerprint.</param>
    /// <returns>Never returns.</returns>
    /// <exception cref="NotSupportedException">Always, when called rather than translated.</exception>
    public static int Of(string value) =>
        throw new NotSupportedException("The ledger's fingerprint is the database's own, and this call exists only to be translated into a call to it.");
}
