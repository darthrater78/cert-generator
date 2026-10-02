using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace CertGeneratorPal;

/// <summary>Names filled in the way a Windows CA builds them, so a request rarely needs typing.</summary>
internal static class LocalIdentity
{
    public static string Hostname => Environment.MachineName.ToLowerInvariant();

    public static string OsDescription => RuntimeInformation.OSDescription;

    /// <summary>The PC's DNS name: its primary DNS suffix, else what the LAN's DNS calls it, else the bare host name.</summary>
    public static string Fqdn(Uri? server = null)
    {
        var props = IPGlobalProperties.GetIPGlobalProperties();
        if (!string.IsNullOrWhiteSpace(props.DomainName))
        {
            return (props.HostName + "." + props.DomainName).ToLowerInvariant();
        }
        foreach (var candidate in ReverseNames(server))
        {
            if (candidate.Contains('.', StringComparison.Ordinal)
                && candidate.StartsWith(Environment.MachineName + ".", StringComparison.OrdinalIgnoreCase))
            {
                return candidate.TrimEnd('.').ToLowerInvariant();
            }
        }
        return Hostname;
    }

    private static List<string> ReverseNames(Uri? server)
    {
        var names = new List<string>();
        try
        {
            if (server is not null && LocalAddressFor(server) is { } local)
            {
                names.Add(Dns.GetHostEntry(local).HostName);
            }
            names.Add(Dns.GetHostEntry(Dns.GetHostName()).HostName);
        }
        catch (SocketException)
        {
            // no reverse DNS on this LAN
        }
        return names;
    }

    /// <summary>The local address this PC uses to reach the server.</summary>
    public static IPAddress? LocalAddressFor(Uri server)
    {
        try
        {
            IPAddress target = IPAddress.TryParse(server.Host, out var ip) ? ip : Dns.GetHostAddresses(server.Host).First();
            using var socket = new Socket(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect(target, server.Port);  // UDP: no packet is sent
            return (socket.LocalEndPoint as IPEndPoint)?.Address;
        }
        catch (Exception e) when (e is SocketException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The signed-in user's UPN (domain accounts), else user@domain from the admin's pattern.</summary>
    public static string SuggestedUpn(IReadOnlyList<string> userPatterns)
    {
        string? upn = UserNameEx(NativeMethods.NameUserPrincipal);
        if (!string.IsNullOrEmpty(upn))
        {
            return upn.ToLowerInvariant();
        }
        string user = Environment.UserName.ToLowerInvariant().Replace(' ', '.');
        string? pattern = userPatterns.Count > 0 ? userPatterns[0] : null;
        if (pattern is null)
        {
            return user;
        }
        return pattern.StartsWith("*@", StringComparison.Ordinal) ? user + pattern[1..] : pattern;
    }

    public static string DisplayName => UserNameEx(NativeMethods.NameDisplay) is { Length: > 0 } name ? name : Environment.UserName;

    private static string? UserNameEx(int format)
    {
        uint size = 256;
        char[] buffer = new char[size];
        return NativeMethods.GetUserNameEx(format, buffer, ref size) ? new string(buffer, 0, (int)size) : null;
    }
}
