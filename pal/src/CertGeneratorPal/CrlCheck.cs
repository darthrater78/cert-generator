using System.Diagnostics;
using System.Formats.Asn1;
using System.Globalization;
using System.Net;

namespace CertGeneratorPal;

/// <summary>Does a revocation (CRL) address answer, and with what? For the status rows and their Test links.</summary>
internal static class CrlCheck
{
    public sealed record Result(bool Ok, string Summary, string Detail);

    /// <param name="onThisPc">The self-hosted address: it must be answered by this PC's own listener, not the network.</param>
    public static async Task<Result> TestAsync(string url, bool onThisPc)
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
                        "not this PC's own CRL listener. Install the self-hosted CRL.");
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
            string? about = Describe(body);
            return new(about is not null, about is not null ? $"Reachable · {timing}" : "Answers, but not with a CRL",
                $"{url}\n\nHTTP {(int)response.StatusCode} · {body.Length.ToString("N0", CultureInfo.CurrentCulture)} bytes · {timing}\n" +
                (about ?? "The reply isn't a CRL Windows can read."));
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

    /// <summary>This update, next update and the number of revoked serials, read from a DER CRL.</summary>
    private static string? Describe(byte[] der)
    {
        try
        {
            var crl = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
            var tbs = crl.ReadSequence();
            if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                tbs.ReadInteger();  // version
            }
            tbs.ReadSequence();  // signature algorithm
            tbs.ReadEncodedValue();  // issuer
            DateTimeOffset thisUpdate = ReadTime(tbs);
            DateTimeOffset? nextUpdate = tbs.HasData && IsTime(tbs.PeekTag()) ? ReadTime(tbs) : null;
            int revoked = 0;
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var list = tbs.ReadSequence();
                while (list.HasData)
                {
                    list.ReadEncodedValue();
                    revoked++;
                }
            }
            string Date(DateTimeOffset t) => t.ToLocalTime().ToString("d MMM yyyy HH:mm", CultureInfo.CurrentCulture);
            string next = nextUpdate is { } n
                ? $"Next update: {Date(n)}{(n < DateTimeOffset.UtcNow ? "  (STALE: Windows rejects it)" : "")}"
                : "Next update: none";
            return $"Valid CRL. Issued {Date(thisUpdate)}\n{next}\nRevoked certificates: {revoked.ToString(CultureInfo.CurrentCulture)}";
        }
        catch (AsnContentException)
        {
            return null;
        }
    }

    private static bool IsTime(Asn1Tag tag) => tag.HasSameClassAndValue(Asn1Tag.UtcTime) || tag.HasSameClassAndValue(Asn1Tag.GeneralizedTime);

    private static DateTimeOffset ReadTime(AsnReader reader) =>
        reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? reader.ReadUtcTime() : reader.ReadGeneralizedTime();
}
