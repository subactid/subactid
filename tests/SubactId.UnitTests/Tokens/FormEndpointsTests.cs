using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using SubactId.Server.Tokens;
using SubactId.Tokens.Signing;
using Xunit;

namespace SubactId.UnitTests.Tokens;

/// <summary>
/// The 64 KiB limit on the form endpoints' bodies: set on the host before anything is read, a body
/// declared over it is not read at all, a body the host cuts off is refused rather than thrown,
/// and the largest legitimate exchange fits well inside it.
/// </summary>
public class FormEndpointsTests
{
    [Fact]
    public void The_limit_is_handed_to_the_host_before_the_body_is_read()
    {
        var limit = new BodySizeFeature();
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(limit);

        Assert.True(FormEndpoints.LimitBody(context));
        Assert.Equal(64 * 1024, limit.MaxRequestBodySize);
    }

    [Fact]
    public void A_limit_the_host_no_longer_takes_is_left_alone()
    {
        var limit = new BodySizeFeature { IsReadOnly = true };
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpMaxRequestBodySizeFeature>(limit);

        Assert.True(FormEndpoints.LimitBody(context));
        Assert.Null(limit.MaxRequestBodySize);
    }

    [Fact]
    public async Task A_body_declared_over_the_limit_is_refused_without_being_read()
    {
        var body = new UnreadableStream();
        var context = Form(body);
        context.Request.ContentLength = FormEndpoints.MaxBodyBytes + 1;

        Assert.False(FormEndpoints.LimitBody(context));
        Assert.Null(await FormEndpoints.TryReadAsync(context.Request, CancellationToken.None));
        Assert.False(body.Touched);
    }

    [Fact]
    public async Task A_body_at_the_limit_is_read()
    {
        var fields = "grant_type=refresh_token&pad=";
        var form = fields + new string('a', (int)FormEndpoints.MaxBodyBytes - fields.Length);
        var context = Form(new MemoryStream(Encoding.ASCII.GetBytes(form)));
        context.Request.ContentLength = form.Length;

        var read = await FormEndpoints.TryReadAsync(context.Request, CancellationToken.None);

        Assert.Equal("refresh_token", read!["grant_type"].ToString());
    }

    [Fact]
    public async Task A_body_the_host_cuts_off_as_too_large_is_refused_rather_than_thrown()
    {
        // Chunked, so no length was declared: the host stops it as it arrives, with a 413.
        var context = Form(new MemoryStream());
        context.Features.Set<IFormFeature>(new ThrowingFormFeature(new BadHttpRequestException("Request body too large.", StatusCodes.Status413PayloadTooLarge)));

        Assert.Null(await FormEndpoints.TryReadAsync(context.Request, CancellationToken.None));
    }

    [Fact]
    public async Task A_form_over_the_readers_own_limits_is_refused_rather_than_thrown()
    {
        var context = Form(new MemoryStream());
        context.Features.Set<IFormFeature>(new ThrowingFormFeature(new InvalidDataException("Form value count limit exceeded.")));

        Assert.Null(await FormEndpoints.TryReadAsync(context.Request, CancellationToken.None));
    }

    [Fact]
    public async Task The_largest_legitimate_exchange_fits_well_inside_the_limit()
    {
        // Every value at the most the exchange accepts, encoded as a client would send it. Values
        // that need escaping are the worst case: each such character takes three bytes.
        var longest = new string(':', 2048);
        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange",
            ["subject_token"] = new string('s', Jws.MaxUpstreamTokenLength),
            ["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["actor_token"] = new string('a', Jws.MaxTokenLength),
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:jwt",
            ["requested_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
            ["resource"] = longest,
            ["scope"] = longest,
            ["client_id"] = longest,
        });

        var length = (await content.ReadAsByteArrayAsync()).Length;

        Assert.True(length < FormEndpoints.MaxBodyBytes * 3 / 4, $"{length} bytes");
    }

    private static DefaultHttpContext Form(Stream body)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = HttpMethods.Post;
        context.Request.ContentType = FormEndpoints.FormMediaType;
        context.Request.Body = body;
        return context;
    }

    private sealed class BodySizeFeature : IHttpMaxRequestBodySizeFeature
    {
        public bool IsReadOnly { get; init; }

        public long? MaxRequestBodySize { get; set; }
    }

    private sealed class ThrowingFormFeature(Exception exception) : IFormFeature
    {
        public bool HasFormContentType => true;

        public IFormCollection? Form { get; set; }

        public IFormCollection ReadForm() => throw exception;

        public Task<IFormCollection> ReadFormAsync(CancellationToken cancellationToken) => Task.FromException<IFormCollection>(exception);
    }

    /// <summary>A body that records whether anything tried to read it.</summary>
    private sealed class UnreadableStream : MemoryStream
    {
        public bool Touched { get; private set; }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Touched = true;
            return 0;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Touched = true;
            return ValueTask.FromResult(0);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Touched = true;
            return Task.FromResult(0);
        }
    }
}
