using System.Diagnostics;
using System.Globalization;
using System.Net;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>Does a revocation (CRL) address answer, and with what? For the status rows and their Test links.</summary>
internal static class CrlCheck
{
    /// <param name="Crl">The CRL the address answered with, when it did.</param>
    public sealed record Result(bool Ok, string Summary, string Detail, CrlList? Crl = null);

    /// <param name="onThisPc">The endpoint-hosted address: it must be answered by this PC's own listener, not the network.</param>
    public static async Task<Result> TestAsync(string url, bool onThisPc)
    {
        var result = await TestCoreAsync(url, onThisPc).ConfigureAwait(false);
        AppLog.Debug($"CRL check {url}{(onThisPc ? " (this PC)" : "")}: {(result.Ok ? "ok" : "FAILED")}: {result.Detail.ReplaceLineEndings(" | ")}");
        return result;
    }

    private static async Task<Result> TestCoreAsync(string url, bool onThisPc)
    {
        var watch = Stopwatch.StartNew();
        try
        {
            using var http = new HttpClient(new HttpClientHandler { UseProxy = !onThisPc }) { Timeout = TimeSpan.FromSeconds(5) };
            using var response = await http.GetAsync(url).ConfigureAwait(false);
            byte[] body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            watch.Stop();
            string timing = $"{watch.ElapsedMilliseconds.ToString(CultureInfo.CurrentCulture)} ms";
            if (onThisPc)
            {
                var resolved = await Dns.GetHostAddressesAsync(new Uri(url).Host).ConfigureAwait(false);
                if (!resolved.Any(IPAddress.IsLoopback))
                {
                    return new(false, "Not installed on this PC", $"{url}\n\nAnswered by another machine ({string.Join(", ", resolved.Select(a => a.ToString()))}), " +
                        "not this PC's own CRL listener. Install the endpoint-hosted CRL.");
                }
            }
            if (!response.IsSuccessStatusCode)
            {
                int code = (int)response.StatusCode;
                string summary = code == 404 ? "Not published yet (HTTP 404)" : $"HTTP {code}";
                string why = code == 404
                    ? "The address answers, but has no CRL there yet. This server publishes it once a certificate uses it."
                    : $"The address answered {code} {response.ReasonPhrase}.";
                return new(false, summary, $"{url}\n\n{why}\nTime: {timing}");
            }
            var crl = CrlList.Parse(body);
            string? about = crl is null ? null : Describe(crl);
            return new(about is not null, about is not null ? $"Reachable · {timing}" : "Answers, but not with a CRL",
                $"{url}\n\nHTTP {(int)response.StatusCode} · {body.Length.ToString("N0", CultureInfo.CurrentCulture)} bytes · {timing}\n" +
                (about ?? "The reply isn't a CRL Windows can read."), crl);
        }
        catch (TaskCanceledException)
        {
            return new(false, "Timed out", $"{url}\n\nNo answer within 5 seconds.");
        }
        catch (Exception e) when (e is HttpRequestException or System.Net.Sockets.SocketException or UriFormatException)
        {
            return new(false, onThisPc ? "Not installed on this PC" : "Can't connect", $"{url}\n\n{e.Message}");
        }
    }

    /// <summary>The CRL at an address, for the viewer. Throws what HttpClient throws when it can't be had.</summary>
    public static async Task<byte[]> DownloadAsync(string url, bool onThisPc)
    {
        using var http = new HttpClient(new HttpClientHandler { UseProxy = !onThisPc })
        {
            Timeout = TimeSpan.FromSeconds(10),
            MaxResponseContentBufferSize = 16 * 1024 * 1024,  // a CRL is kilobytes; whatever answers can't fill memory
        };
        using var response = await http.GetAsync(url).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }

    public static string Date(DateTimeOffset t) => t.ToLocalTime().ToString("d MMM yyyy HH:mm", CultureInfo.CurrentCulture);

    /// <summary>This update, next update and the number of revoked serials.</summary>
    private static string Describe(CrlList crl)
    {
        string next = crl.NextUpdate is { } n ? $"Next update: {Date(n)}{(crl.Stale ? "  (STALE: Windows rejects it)" : "")}" : "Next update: none";
        return $"Valid CRL. Issued {Date(crl.ThisUpdate)}\n{next}\nRevoked certificates: {crl.Revoked.Count.ToString(CultureInfo.CurrentCulture)}";
    }
}
