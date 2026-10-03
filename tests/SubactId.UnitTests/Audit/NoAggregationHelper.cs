using SubactId.Server.Audit;

namespace SubactId.UnitTests;

/// <summary>
/// Shared by the service tests that build a <see cref="SubactId.Server.Tokens.TokenAudit"/> directly.
/// </summary>
public static class NoAggregationHelper
{
    /// <summary>
    /// An aggregator that collapses nothing, so service tests see one ledger record per denial.
    /// <c>DenialAggregatorTests</c> covers the aggregator itself.
    /// </summary>
    /// <param name="clock">The test's clock.</param>
    public static DenialAggregator NoAggregation(TimeProvider clock) =>
        new(clock, new DenialAggregationOptions { Enabled = false });
}
