namespace SubactId.Core.Audit;

/// <summary>The one mapping between <see cref="AuditDecision"/> and the lowercase code stored and hashed.</summary>
public static class AuditDecisionCodes
{
    /// <summary>The stored code for <paramref name="decision"/>; <c>null</c> when there is none.</summary>
    public static string? ToCode(AuditDecision? decision) => decision switch
    {
        AuditDecision.Allow => "allow",
        AuditDecision.Deny => "deny",
        _ => null,
    };

    /// <summary>The decision for a stored <paramref name="code"/>; <c>null</c> for null or anything unknown.</summary>
    public static AuditDecision? FromCode(string? code) => code switch
    {
        "allow" => AuditDecision.Allow,
        "deny" => AuditDecision.Deny,
        _ => null,
    };
}
