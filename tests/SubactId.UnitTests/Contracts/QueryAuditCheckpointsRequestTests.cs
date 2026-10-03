using SubactId.Server.Contracts;
using Xunit;

namespace SubactId.UnitTests.Contracts;

public class QueryAuditCheckpointsRequestTests
{
    [Fact]
    public void An_empty_request_is_the_first_page_of_one_hundred()
    {
        var errors = new QueryAuditCheckpointsRequest().TryToQuery(out var after, out var limit);

        Assert.Empty(errors);
        Assert.Equal((0L, QueryAuditCheckpointsRequest.DefaultLimit), (after, limit));
    }

    [Fact]
    public void After_and_limit_are_read_as_given()
    {
        var errors = new QueryAuditCheckpointsRequest { After = "271", Limit = "1000" }.TryToQuery(out var after, out var limit);

        Assert.Empty(errors);
        Assert.Equal((271L, 1000), (after, limit));
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("+1")]
    [InlineData("1.5")]
    [InlineData("271 ")]
    [InlineData("last")]
    [InlineData("")]
    public void A_cursor_that_is_not_a_whole_number_is_refused_by_name(string after)
    {
        var errors = new QueryAuditCheckpointsRequest { After = after }.TryToQuery(out _, out _);

        var error = Assert.Single(errors);
        Assert.Equal("after", error.Field);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("1001")]
    [InlineData("-5")]
    [InlineData("many")]
    [InlineData("")]
    public void A_limit_outside_one_to_a_thousand_is_refused_by_name(string limit)
    {
        var errors = new QueryAuditCheckpointsRequest { Limit = limit }.TryToQuery(out _, out _);

        var error = Assert.Single(errors);
        Assert.Equal("limit", error.Field);
    }

    /// <summary>
    /// On error both outputs go back to their defaults, so a caller that ignores the errors cannot
    /// page from a half-parsed number.
    /// </summary>
    [Fact]
    public void Every_error_is_reported_at_once_and_the_outputs_are_left_at_their_defaults()
    {
        var errors = new QueryAuditCheckpointsRequest { After = "-1", Limit = "5000" }.TryToQuery(out var after, out var limit);

        Assert.Equal(["after", "limit"], errors.Select(e => e.Field));
        Assert.Equal((0L, QueryAuditCheckpointsRequest.DefaultLimit), (after, limit));
    }
}
