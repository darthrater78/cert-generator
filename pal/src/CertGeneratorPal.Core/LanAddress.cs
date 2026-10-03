using System.Net;
using System.Net.Sockets;

namespace CertGeneratorPal.Core;

/// <summary>Cert Generator Pal is LAN only: it talks to private addresses and nothing else.</summary>
public static class LanAddress
{
    /// <summary>Loopback, RFC 1918, CGNAT 100.64.0.0/10 (SSE / ZTNA overlays), link-local, IPv6 ULA
    /// (and IPv4-mapped forms of them). Mirrors app/pal.py.</summary>
    public static bool IsPrivate(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }
        if (IPAddress.IsLoopback(address))
        {
            return true;
        }
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] b = address.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
                || (b[0] == 169 && b[1] == 254);
        }
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte first = address.GetAddressBytes()[0];
            return address.IsIPv6LinkLocal || (first & 0xFE) == 0xFC;
        }
        return false;
    }
}
