using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Primitives;
using SubactId.Server.Admin;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Signals;
using SubactId.Tokens.Upstream;
using Xunit;

namespace SubactId.UnitTests.Signals;

/// <summary>
/// The push credential and the receiver's answers. RFC 8935 asks for <c>202</c> on delivery and
/// its own error codes on refusal. The codes are only given to callers holding the credential.
/// </summary>
public class SecurityEventEndpointsTests
{
    private const string Current = "0123456789abcdef0123456789abcdef";
    private const string Previous = "fedcba9876543210fedcba9876543210";

    private static SsfOptions Options(string? previous = null) => new()
    {
        MetadataUrl = new Uri("https://transmitter.example.test/.well-known/openid-configuration"),
        Audience = "https://subactid.example.com/events",
        BearerToken = Current,
        PreviousBearerToken = previous,
    };

    [Fact]
    public void The_configured_credential_is_accepted()
    {
        Assert.Null(SecurityEventBearerFilter.Check(new StringValues("Bearer " + Current), Options()));
        Assert.Null(SecurityEventBearerFilter.Check(new StringValues("bearer " + Current), Options()));
        Assert.Equal(AdminApiKeyFilter.InvalidApiKey, SecurityEventBearerFilter.Check(new StringValues("Bearer " + Current.ToUpperInvariant()), Options()));
    }

    [Fact]
    public void Both_credentials_are_accepted_while_a_rotation_is_in_progress()
    {
        var options = Options(Previous);

        Assert.Null(SecurityEventBearerFilter.Check(new StringValues("Bearer " + Current), options));
        Assert.Null(SecurityEventBearerFilter.Check(new StringValues("Bearer " + Previous), options));
        Assert.Equal(AdminApiKeyFilter.InvalidApiKey, SecurityEventBearerFilter.Check(new StringValues("Bearer " + Previous), Options()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("Bearer ")]
    [InlineData("Basic " + Current)]
    [InlineData(Current)]
    public void A_request_with_no_usable_credential_is_refused_as_missing_one(string header)
    {
        Assert.Equal(AdminApiKeyFilter.MissingApiKey, SecurityEventBearerFilter.Check(new StringValues(header), Options()));
    }

    [Fact]
    public void Two_authorization_headers_are_not_one_credential()
    {
        Assert.Equal(AdminApiKeyFilter.MissingApiKey, SecurityEventBearerFilter.Check(new StringValues(["Bearer " + Current, "Bearer " + Current]), Options()));
    }

    [Fact]
    public void A_delivered_event_is_an_empty_202()
    {
        // What a transmitter reads to stop retrying.
        var answer = Assert.IsType<StatusCodeHttpResult>(SecurityEventEndpoints.Answer(null));

        Assert.Equal(StatusCodes.Status202Accepted, answer.StatusCode);
    }

    [Theory]
    [InlineData(SecurityEventRejection.InvalidSignature, "invalid_key")]
    [InlineData(SecurityEventRejection.UnknownKey, "invalid_key")]
    [InlineData(SecurityEventRejection.UnsupportedAlgorithm, "invalid_key")]
    [InlineData(SecurityEventRejection.UntrustedIssuer, "invalid_issuer")]
    [InlineData(SecurityEventRejection.AudienceMismatch, "invalid_audience")]
    [InlineData(SecurityEventRejection.Malformed, "invalid_request")]
    [InlineData(SecurityEventRejection.UnsupportedSubjectFormat, "invalid_request")]
    [InlineData(SecurityEventRejection.AmbiguousSubject, "invalid_request")]
    [InlineData(SecurityEventRejection.TooOld, "invalid_request")]
    public void A_refused_event_names_the_check_that_failed_so_the_transmitter_can_fix_it(SecurityEventRejection rejection, string expected)
    {
        var answer = Assert.IsType<JsonHttpResult<SecurityEventErrorResponse>>(SecurityEventEndpoints.Answer(rejection));

        Assert.Equal(StatusCodes.Status400BadRequest, answer.StatusCode);
        Assert.Equal(expected, answer.Value!.Err);
    }

    [Fact]
    public void An_event_refused_for_its_age_is_told_so_rather_than_called_invalid()
    {
        // A transmitter draining its queue after an outage sees what happened to each event, rather
        // than a generic "not a valid security event token".
        var answer = Assert.IsType<JsonHttpResult<SecurityEventErrorResponse>>(SecurityEventEndpoints.Answer(SecurityEventRejection.TooOld));

        Assert.Contains("iat", answer.Value!.Description, StringComparison.Ordinal);
        Assert.Contains("older", answer.Value.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void Keys_that_could_not_be_fetched_are_a_503_so_the_transmitter_retries()
    {
        // Failing to reach the transmitter's keys is this server's failure, not a bad event.
        var answer = Assert.IsType<JsonHttpResult<SecurityEventErrorResponse>>(SecurityEventEndpoints.Answer(SecurityEventRejection.KeysUnavailable));

        Assert.Equal(StatusCodes.Status503ServiceUnavailable, answer.StatusCode);
    }

    [Theory]
    [InlineData("application/secevent+jwt", true)]
    [InlineData("application/secevent+jwt; charset=utf-8", true)]
    [InlineData("application/json", false)]
    [InlineData("application/jwt", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Only_a_security_event_token_is_read(string? contentType, bool accepted)
    {
        // A JWS is not JSON, so nothing else is parsed.
        Assert.Equal(accepted, SecurityEventEndpoints.IsAcceptedMediaType(contentType));
    }
}
