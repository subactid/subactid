using System.Text.RegularExpressions;
using SubactId.Server.Tokens;
using SubactId.Tokens.ClientAuth;
using SubactId.Tokens.Grants;
using SubactId.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Audit;

/// <summary>
/// The reason families built from a rejection's name, held against the catalogue in spec section
/// 7.6. Renaming a rejection renames a published reason, so it fails here until the spec says so.
/// </summary>
public partial class ReasonCatalogueTests
{
    public static TheoryData<string> BuiltReasons()
    {
        var reasons = new TheoryData<string>();
        foreach (var rejection in Enum.GetValues<ClientAssertionRejection>().Where(r => r is not ClientAssertionRejection.None and not ClientAssertionRejection.AgentDisabled))
        {
            reasons.Add(AuditReason.Of("actor", rejection));
        }

        foreach (var rejection in Enum.GetValues<UpstreamRejection>().Where(r => r is not UpstreamRejection.None))
        {
            reasons.Add(AuditReason.Of("subject", rejection));
        }

        // A revoked or expired task is reported as the task's state, not the grant's.
        foreach (var rejection in new[] { TaskGrantRejection.NotFound, TaskGrantRejection.Revoked, TaskGrantRejection.Expired })
        {
            reasons.Add(AuditReason.Of("grant", rejection));
        }

        foreach (var rejection in Enum.GetValues<LogoutRejection>().Where(r => r is not LogoutRejection.None))
        {
            reasons.Add(AuditReason.Of("logout", rejection));
        }

        foreach (var rejection in Enum.GetValues<SecurityEventRejection>().Where(r => r is not SecurityEventRejection.None))
        {
            reasons.Add(AuditReason.Of("ssf", rejection));
        }

        return reasons;
    }

    [Theory]
    [MemberData(nameof(BuiltReasons))]
    public void Every_reason_built_from_a_rejection_is_in_the_spec(string reason)
    {
        Assert.Contains(reason, CataloguedReasons());
    }

    [Theory]
    [InlineData(TokenExchangeService.SubjectLoggedOut)]
    [InlineData(SubactId.Server.Signals.SponsorSignalWriter.SignalOutOfOrder)]
    public void Reasons_that_are_not_built_from_a_rejection_are_in_the_spec_too(string reason)
    {
        Assert.Contains(reason, CataloguedReasons());
    }

    [Fact]
    public void A_reason_names_a_claim_once()
    {
        Assert.DoesNotContain(BuiltReasons().Cast<object[]>().Select(r => (string)r[0]), r => r.StartsWith("subject_subject_", StringComparison.Ordinal));
    }

    private static HashSet<string> CataloguedReasons()
    {
        var spec = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "spec", "v0.1.md"));
        var start = spec.IndexOf("### 7.6 Reasons", StringComparison.Ordinal);
        var end = spec.IndexOf("## 8. Errors", StringComparison.Ordinal);
        Assert.True(start >= 0 && end > start, "Spec section 7.6 was not found.");
        return [.. CatalogueRow().Matches(spec[start..end]).Select(m => m.Groups[1].Value)];
    }

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "docs", "spec", "v0.1.md")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The repository root was not found above the test output.");
    }

    [GeneratedRegex(@"^\| `([a-z_]+)`", RegexOptions.Multiline)]
    private static partial Regex CatalogueRow();
}
