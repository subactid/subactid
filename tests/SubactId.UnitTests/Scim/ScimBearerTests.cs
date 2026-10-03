using Microsoft.Extensions.Primitives;
using SubactId.Core.Scim;
using SubactId.Server.Admin;
using SubactId.Server.Configuration;
using SubactId.Server.Contracts;
using SubactId.Server.Scim;
using Xunit;

namespace SubactId.UnitTests.Scim;

/// <summary>
/// The provisioning credential, and the lookup query. Both face strangers first, so both refuse
/// anything they do not understand.
/// </summary>
public class ScimBearerTests
{
    private const string Current = "0123456789abcdef0123456789abcdef";
    private const string Previous = "fedcba9876543210fedcba9876543210";

    private static ScimOptions Options(string? previous = null) => new()
    {
        BearerToken = Current,
        PreviousBearerToken = previous,
        SponsorKeyAttribute = ScimSponsorKeyAttribute.ExternalId,
        MaxUsers = ScimOptions.DefaultMaxUsers,
    };

    [Fact]
    public void The_configured_credential_is_accepted()
    {
        Assert.Null(ScimBearerFilter.Check(new StringValues("Bearer " + Current), Options()));

        // The scheme is case-insensitive; the credential is not.
        Assert.Null(ScimBearerFilter.Check(new StringValues("bearer " + Current), Options()));
        Assert.Equal(AdminApiKeyFilter.InvalidApiKey, ScimBearerFilter.Check(new StringValues("Bearer " + Current.ToUpperInvariant()), Options()));
    }

    [Fact]
    public void Both_credentials_are_accepted_while_a_rotation_is_in_progress()
    {
        // Okta and Entra rotate a provisioning secret in two steps, so two values are accepted at once.
        var options = Options(Previous);

        Assert.Null(ScimBearerFilter.Check(new StringValues("Bearer " + Current), options));
        Assert.Null(ScimBearerFilter.Check(new StringValues("Bearer " + Previous), options));

        // And the old one stops working the moment it is removed from the configuration.
        Assert.Equal(AdminApiKeyFilter.InvalidApiKey, ScimBearerFilter.Check(new StringValues("Bearer " + Previous), Options()));
    }

    [Theory]
    [InlineData("")]
    [InlineData("Bearer ")]
    [InlineData("Basic " + Current)]
    [InlineData(Current)]
    public void A_request_with_no_usable_credential_is_refused_as_missing_one(string header)
    {
        Assert.Equal(AdminApiKeyFilter.MissingApiKey, ScimBearerFilter.Check(new StringValues(header), Options()));
    }

    [Fact]
    public void Two_authorization_headers_are_not_one_credential()
    {
        Assert.Equal(AdminApiKeyFilter.MissingApiKey, ScimBearerFilter.Check(new StringValues(["Bearer " + Current, "Bearer " + Current]), Options()));
    }

    [Fact]
    public void A_wrong_credential_is_refused()
    {
        Assert.Equal(AdminApiKeyFilter.InvalidApiKey, ScimBearerFilter.Check(new StringValues("Bearer " + new string('z', 32)), Options(Previous)));
    }

    [Theory]
    [InlineData("userName eq \"ada@example.com\"", "ada@example.com", null)]
    [InlineData("username EQ \"ada@example.com\"", "ada@example.com", null)]
    [InlineData("externalId eq \"oid-42\"", null, "oid-42")]
    public void A_filter_this_receiver_serves_is_read(string expression, string? userName, string? externalId)
    {
        var request = new ListScimUsersRequest { Filter = expression };

        Assert.True(request.TryToFilter(out var filter));
        Assert.Equal((userName, externalId), (filter!.UserName, filter.ExternalId));
        Assert.Equal((1, ListScimUsersRequest.DefaultCount), (filter.StartIndex, filter.Count));
    }

    [Fact]
    public void A_quoted_value_is_read_as_the_string_it_is()
    {
        // A user name may contain a quote, so the string is parsed rather than trimmed of quotes.
        var request = new ListScimUsersRequest { Filter = "userName eq \"a\\\"b\"" };

        Assert.True(request.TryToFilter(out var filter));
        Assert.Equal("a\"b", filter!.UserName);
    }

    [Theory]
    [InlineData("displayName eq \"Ada\"")]
    [InlineData("userName co \"ada\"")]
    [InlineData("userName eq ada@example.com")]
    [InlineData("userName eq")]
    [InlineData("userName")]
    public void A_filter_this_receiver_does_not_serve_is_refused_rather_than_ignored(string expression)
    {
        // Ignoring the filter would return everybody, which a provisioning client would not notice.
        Assert.False(new ListScimUsersRequest { Filter = expression }.TryToFilter(out _));
    }

    [Fact]
    public void Paging_is_read_and_bounded()
    {
        var request = new ListScimUsersRequest { StartIndex = "3", Count = "1000" };

        Assert.True(request.TryToFilter(out var filter));
        Assert.Equal((3, ListScimUsersRequest.MaxCount), (filter!.StartIndex, filter.Count));

        // A count of zero is a count of the matches with none of them, which SCIM allows.
        Assert.True(new ListScimUsersRequest { Count = "0" }.TryToFilter(out var none));
        Assert.Equal(0, none!.Count);
    }

    [Theory]
    [InlineData("0", null)]
    [InlineData("-1", null)]
    [InlineData("many", null)]
    [InlineData(null, "-1")]
    [InlineData(null, "lots")]
    public void Paging_that_is_not_a_position_is_refused(string? startIndex, string? count)
    {
        Assert.False(new ListScimUsersRequest { StartIndex = startIndex, Count = count }.TryToFilter(out _));
    }

    [Theory]
    [InlineData("application/scim+json", true)]
    [InlineData("application/scim+json; charset=utf-8", true)]
    [InlineData("APPLICATION/SCIM+JSON", true)]
    [InlineData("application/json", true)]
    [InlineData("application/json; charset=utf-8", true)]
    [InlineData("application/scim+json; charset=UTF-8", true)]
    [InlineData("application/scim+json; charset=\"utf-8\"", true)]
    [InlineData("application/scim+json; charset=iso-8859-1", false)]
    [InlineData("application/json; charset=utf-16", false)]
    [InlineData("text/plain", false)]
    [InlineData("application/xml", false)]
    [InlineData("application/jsonx", false)]
    [InlineData("text/json", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Only_a_SCIM_or_JSON_body_in_UTF_8_is_read(string? contentType, bool accepted)
    {
        Assert.Equal(accepted, ScimBody.IsAcceptedMediaType(contentType));
    }
}
