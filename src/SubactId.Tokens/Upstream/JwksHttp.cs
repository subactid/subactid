using System.Net.Http;

namespace SubactId.Tokens.Upstream;

/// <summary>Bounded reads of small JSON documents (discovery, JWKS) from other parties.</summary>
internal static class JwksHttp
{
    /// <summary>Largest document accepted.</summary>
    public const int MaxDocumentBytes = 1024 * 1024;

    /// <summary>Reads the body at <paramref name="url"/> as UTF-8, refusing anything over <see cref="MaxDocumentBytes"/>.</summary>
    public static async Task<string> ReadAsync(HttpClient client, Uri url, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength > MaxDocumentBytes)
        {
            throw new UpstreamDiscoveryException($"The document at {url} exceeds {MaxDocumentBytes} bytes.", fault: UpstreamDiscoveryFault.TooLarge);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read > MaxDocumentBytes)
            {
                throw new UpstreamDiscoveryException($"The document at {url} exceeds {MaxDocumentBytes} bytes.", fault: UpstreamDiscoveryFault.TooLarge);
            }

            buffer.Write(chunk, 0, read);
        }

        return System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }
}
