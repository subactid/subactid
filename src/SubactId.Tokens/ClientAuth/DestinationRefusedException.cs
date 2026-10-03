namespace SubactId.Tokens.ClientAuth;

/// <summary>
/// A fetch this control plane refused to make, because every address its destination resolves to
/// is one it is configured not to reach, such as a private or loopback address. Thrown while the
/// connection is being made, so it arrives wrapped in the
/// <see cref="System.Net.Http.HttpRequestException"/> the fetch fails with. It is a standing
/// refusal, not an outage: the same destination is refused every time.
/// </summary>
/// <param name="message">Which destination was refused, in words. Never key or token material.</param>
public sealed class DestinationRefusedException(string message) : Exception(message)
{
    /// <summary>Whether <paramref name="exception"/>, or any exception it wraps, is a refusal.</summary>
    /// <param name="exception">The failure a fetch ended with.</param>
    public static bool IsIn(Exception? exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current is DestinationRefusedException)
            {
                return true;
            }
        }

        return false;
    }
}
