namespace SubactId.Core.Delegation;

/// <summary>Lifecycle state of a task.</summary>
public enum DelegationTaskStatus
{
    /// <summary>Live; grants under it may be refreshed.</summary>
    Active,

    /// <summary>Passed its expiry and marked terminal.</summary>
    Expired,

    /// <summary>Revoked explicitly, directly or through a parent.</summary>
    Revoked,
}
