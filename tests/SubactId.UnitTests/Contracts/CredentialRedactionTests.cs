using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

/// <summary>
/// Contracts that carry a credential print without it, so a log line or exception message that
/// includes one never leaks a token, a task grant, a subject token or an assertion.
/// </summary>
public class CredentialRedactionTests
{
    private const string Secret = "SENTINEL-CREDENTIAL";

    public static TheoryData<object, string> Printed() => new()
    {
        { new TokenResponse(Secret + "-access", ExchangeTokenRequest.AccessTokenType, TokenResponse.Bearer, 300, "jira:read", Secret + "-grant", "task_1", DateTimeOffset.UnixEpoch), "task_1" },
        { new ExchangeTokenRequest(ExchangeTokenRequest.TokenExchangeGrantType, Secret + "-subject", ExchangeTokenRequest.AccessTokenType, Secret + "-actor", ExchangeTokenRequest.JwtTokenType, ExchangeTokenRequest.AccessTokenType, "https://jira.internal", "jira:read", "jira-triage"), "https://jira.internal" },
        { new RefreshTokenRequest(RefreshTokenRequest.RefreshTokenGrantType, Secret + "-grant", "https://jira.internal", "jira:read", Secret + "-assertion", RefreshTokenRequest.JwtBearerAssertionType, "jira-triage"), "jira-triage" },
        { new RevokeTokenRequest(Secret + "-token", "refresh_token", Secret + "-assertion", RefreshTokenRequest.JwtBearerAssertionType, "jira-triage"), "refresh_token" },
        { new IntrospectTokenRequest(Secret + "-token", "access_token"), "access_token" },
    };

    [Theory]
    [MemberData(nameof(Printed))]
    public void Printing_a_contract_shows_what_it_is_but_not_its_credentials(object contract, string visible)
    {
        var printed = contract.ToString()!;

        Assert.DoesNotContain(Secret, printed, StringComparison.Ordinal);
        Assert.Contains("<redacted>", printed, StringComparison.Ordinal);
        Assert.Contains(visible, printed, StringComparison.Ordinal);
    }

    [Fact]
    public void An_absent_credential_prints_as_absent()
    {
        Assert.Contains("Token = <none>", new IntrospectTokenRequest(null, null).ToString(), StringComparison.Ordinal);
    }
}
