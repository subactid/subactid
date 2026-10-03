using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SubactId.UnitTests.Http;

/// <summary>A one-response HTTP server on a loopback port that counts the connections it takes.</summary>
internal sealed class LoopbackServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stopping = new();
    private readonly Task serving;
    private int connections;

    public LoopbackServer(string response)
    {
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        serving = ServeAsync(Encoding.ASCII.GetBytes(response));
    }

    public int Port { get; }

    public int Connections => Volatile.Read(ref connections);

    public async ValueTask DisposeAsync()
    {
        await stopping.CancelAsync();
        listener.Stop();
        await serving;
        stopping.Dispose();
    }

    private async Task ServeAsync(byte[] response)
    {
        try
        {
            while (true)
            {
                using var accepted = await listener.AcceptTcpClientAsync(stopping.Token);
                Interlocked.Increment(ref connections);
                var stream = accepted.GetStream();

                // Read the request head, then answer and close.
                var head = new StringBuilder();
                var buffer = new byte[1024];
                while (!head.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                {
                    var read = await stream.ReadAsync(buffer, stopping.Token);
                    if (read == 0)
                    {
                        break;
                    }

                    head.Append(Encoding.ASCII.GetString(buffer, 0, read));
                }

                await stream.WriteAsync(response, stopping.Token);
            }
        }
        catch (Exception exception) when (exception is OperationCanceledException or SocketException or IOException or ObjectDisposedException)
        {
            // Stopped.
        }
    }
}
