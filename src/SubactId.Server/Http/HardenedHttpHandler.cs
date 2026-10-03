using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using SubactId.Tokens.ClientAuth;

namespace SubactId.Server.Http;

/// <summary>
/// The primary handler for the control plane's outbound fetches from other parties: agents' key
/// sets, and the discovery documents, key sets and admin API of the identity provider and of a
/// Shared Signals transmitter. It never follows a redirect, so a configured or registered URL
/// cannot bounce the fetch to another host. When asked to, it also refuses to connect
/// to any address that is not public, closing off a registered <c>jwks_uri</c> that points at
/// internal infrastructure (SSRF).
/// </summary>
public static class HardenedHttpHandler
{
    // Addresses that are not a public unicast destination: not globally reachable in the IANA
    // special-purpose registries, or not unicast at all.
    private static readonly IPNetwork[] NonPublicIPv4 =
    [
        IPNetwork.Parse("0.0.0.0/8"),       // "this network"
        IPNetwork.Parse("10.0.0.0/8"),      // private
        IPNetwork.Parse("100.64.0.0/10"),   // shared address space (carrier-grade NAT)
        IPNetwork.Parse("127.0.0.0/8"),     // loopback
        IPNetwork.Parse("169.254.0.0/16"),  // link-local, where cloud metadata services answer
        IPNetwork.Parse("172.16.0.0/12"),   // private
        IPNetwork.Parse("192.0.0.0/24"),    // IETF protocol assignments
        IPNetwork.Parse("192.0.2.0/24"),    // documentation
        IPNetwork.Parse("192.88.99.0/24"),  // 6to4 relay anycast, deprecated
        IPNetwork.Parse("192.168.0.0/16"),  // private
        IPNetwork.Parse("198.18.0.0/15"),   // benchmarking
        IPNetwork.Parse("198.51.100.0/24"), // documentation
        IPNetwork.Parse("203.0.113.0/24"),  // documentation
        IPNetwork.Parse("224.0.0.0/4"),     // multicast
        IPNetwork.Parse("240.0.0.0/4"),     // reserved, and the limited broadcast address
    ];

    private static readonly IPNetwork[] NonPublicIPv6 =
    [
        IPNetwork.Parse("64:ff9b:1::/48"),  // local-use IPv4/IPv6 translation
        IPNetwork.Parse("100::/64"),        // discard-only
        IPNetwork.Parse("2001:db8::/32"),   // documentation
        IPNetwork.Parse("3fff::/20"),       // documentation
        IPNetwork.Parse("fc00::/7"),        // unique local
        IPNetwork.Parse("fe80::/10"),       // link-local
        IPNetwork.Parse("fec0::/10"),       // site-local, deprecated
        IPNetwork.Parse("ff00::/8"),        // multicast
    ];

    // IPv6 ranges that carry an IPv4 address in their last 32 bits and reach it: IPv4-compatible
    // (deprecated; also covers :: and ::1), IPv4-translated, and the NAT64 well-known prefix,
    // through which an IPv6-only host reaches IPv4 ones. IPv4-mapped addresses are unwrapped
    // first, since IPNetwork.Contains never matches one against an IPv6 range.
    private static readonly IPNetwork[] CarryIPv4InLast32Bits =
    [
        IPNetwork.Parse("::/96"),
        IPNetwork.Parse("::ffff:0:0:0/96"),
        IPNetwork.Parse("64:ff9b::/96"),
    ];

    // 6to4, which carries the IPv4 address right after its 16-bit prefix.
    private static readonly IPNetwork SixToFour = IPNetwork.Parse("2002::/16");

    /// <summary>
    /// A <see cref="SocketsHttpHandler"/> with redirects disabled and, when
    /// <paramref name="blockPrivateNetworks"/> is set, a connect callback that refuses every
    /// address that is not public. The addresses it resolves are the addresses it connects to, so
    /// the check and the connection cannot disagree. A guarded handler connects directly and never
    /// through a proxy: behind a proxy, the connection is made to the proxy and the proxy picks the
    /// destination's address, so there would be nothing left to check.
    /// </summary>
    /// <param name="blockPrivateNetworks">Whether to refuse addresses that are not public.</param>
    public static SocketsHttpHandler Create(bool blockPrivateNetworks)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };

        if (blockPrivateNetworks)
        {
            handler.UseProxy = false;
            handler.ConnectCallback = ConnectToPublicOnlyAsync;
        }

        return handler;
    }

    private static async ValueTask<Stream> ConnectToPublicOnlyAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var host = context.DnsEndPoint.Host;
        var port = context.DnsEndPoint.Port;

        // An IPv6 literal may still carry the brackets of its URL.
        var literalHost = host.Length > 2 && host[0] == '[' && host[^1] == ']' ? host[1..^1] : host;
        var addresses = IPAddress.TryParse(literalHost, out var literal)
            ? [literal]
            : await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);

        var allowed = Array.FindAll(addresses, static address => !IsPrivate(address));
        if (allowed.Length == 0)
        {
            // Nothing left to connect to that is public. The caller reports a refused registration,
            // never what was reached or would have been.
            throw new DestinationRefusedException($"'{host}' resolves only to addresses that are not public, and agent keys are not fetched from those.");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(allowed, port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Whether <paramref name="address"/> is not a public unicast destination: loopback, private,
    /// link-local, shared, documentation, benchmarking, reserved or multicast, or an IPv6 address
    /// that carries such an IPv4 address (IPv4-mapped, -translated or -compatible, NAT64 or 6to4).
    /// </summary>
    /// <param name="address">The address to classify.</param>
    public static bool IsPrivate(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (SixToFour.Contains(address))
            {
                address = new IPAddress(address.GetAddressBytes().AsSpan(2, 4));
            }
            else if (Array.Exists(CarryIPv4InLast32Bits, range => range.Contains(address)))
            {
                address = new IPAddress(address.GetAddressBytes().AsSpan(12, 4));
            }
        }

        var ranges = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => NonPublicIPv4,
            AddressFamily.InterNetworkV6 => NonPublicIPv6,
            _ => null,
        };

        // An address of any other family is not one this check can vouch for.
        return ranges is null || Array.Exists(ranges, range => range.Contains(address));
    }
}
