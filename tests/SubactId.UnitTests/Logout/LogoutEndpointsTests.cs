using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using SubactId.Server.Contracts;
using SubactId.Server.Logout;
using SubactId.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Logout;

/// <summary>
/// How the receiver answers. Accepted is an empty 200, an invalid token is a 400 that does not
/// say why, and unfetchable provider keys are a 503, since that is this server's failure and
/// worth retrying.
/// </summary>
public class LogoutEndpointsTests
{
    [Fact]
    public void An_accepted_logout_is_an_empty_200()
    {
        Assert.IsType<Ok>(LogoutEndpoints.Answer(null));
    }

    [Theory]
    [InlineData(LogoutRejection.Malformed)]
    [InlineData(LogoutRejection.InvalidSignature)]
    [InlineData(LogoutRejection.AudienceMismatch)]
    [InlineData(LogoutRejection.NoncePresent)]
    public void A_token_that_does_not_validate_is_the_same_400_whatever_failed(LogoutRejection rejection)
    {
        var answer = Assert.IsType<BadRequest<OAuthErrorResponse>>(LogoutEndpoints.Answer(rejection));

        Assert.Equal(StatusCodes.Status400BadRequest, answer.StatusCode);
        Assert.Equal(OAuthErrorResponse.InvalidRequest, answer.Value!.Error);
        Assert.DoesNotContain(rejection.ToString(), answer.Value.ErrorDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Keys_that_could_not_be_fetched_are_a_503_so_the_provider_can_retry()
    {
        // A cold instance that cannot reach the JWKS has not judged the token. A 400 would tell the
        // provider its logout was bad, and providers do not retry on that.
        var answer = Assert.IsType<JsonHttpResult<OAuthErrorResponse>>(LogoutEndpoints.Answer(LogoutRejection.KeysUnavailable));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, answer.StatusCode);
        Assert.Equal(OAuthErrorResponse.TemporarilyUnavailable, answer.Value!.Error);
    }
}
