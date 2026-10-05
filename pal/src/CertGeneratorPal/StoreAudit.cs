using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>One certificate found in this PC's stores that chains to the paired root.</summary>
internal sealed class AuditItem
{
    public required X509Certificate2 Cert { get; init; }
    public required StoreLocation Location { get; init; }
    public required string StoreName { get; init; }
    public required bool IsCa { get; init; }
    public required bool IsRoot { get; init; }
    public string Serial => Cert.SerialNumber;
    public string Names { get; init; } = "";
    public DeviceCert? FromPal { get; set; }
    public string ServerStatus { get; set; } = "unknown";
    public List<string> Flags { get; } = [];

    /// <summary>Where the private key lives: "tpm" or "software" (read here, or as this PC reported it when it
    /// asked: a machine key can't be read without administrator rights); "" when unknown or there is no key.</summary>
    public string KeyStorage { get; set; } = "";

    /// <summary>What uses this certificate: "Remote Desktop", "HTTPS 0.0.0.0:443" (the computer's Personal store only).</summary>
    public List<string> UsedBy { get; } = [];

    /// <summary>A server certificate in the computer's Personal store, with its key: it can serve IIS or Remote Desktop.</summary>
    public bool CanBind => !IsCa && Location == StoreLocation.LocalMachine && StoreName == "My" && Cert.HasPrivateKey
        && (Cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault() is not { } eku
            || eku.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().Any(o => o.Value == "1.3.6.1.5.5.7.3.1"));

    public string StoreLabel => $"{(Location == StoreLocation.LocalMachine ? "Computer" : "User")} \\ {StoreName}";

    public string UseLabel => FromPal is { } pal && UseCases.FromTemplate(pal.Template) is { } useCase
        ? UseCases.Label(useCase)
        : IsRoot ? "Root CA" : IsCa ? "Intermediate CA" : PurposeOf(Cert);

    private static string PurposeOf(X509Certificate2 cert)
    {
        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is null)
        {
            return "Certificate";
        }
        var oids = eku.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().Select(o => o.Value).ToHashSet();
        return oids.Contains("1.3.6.1.5.5.7.3.3") ? "Code signing"
            : oids.Contains("1.3.6.1.5.5.7.3.1") && oids.Contains("1.3.6.1.5.5.7.3.2") ? "Computer"
            : oids.Contains("1.3.6.1.5.5.7.3.1") ? "Web server"
            : oids.Contains("1.3.6.1.5.5.7.3.2") ? "Client"
            : "Certificate";
    }
}

/// <summary>
/// Audits the user and machine stores, showing only certificates that chain to the paired
/// root (exact thumbprint), whoever installed them. Nothing else on the PC is listed or sent.
/// </summary>
internal static class StoreAudit
{
    private static readonly string[] StoreNames = ["My", "Root", "CA", "WebHosting", "Remote Desktop", "TrustedPeople"];

    public static List<AuditItem> Run(DeviceState state)
    {
        using var root = X509Certificate2.CreateFromPem(state.Chain[0]);
        var intermediates = new X509Certificate2Collection();
        foreach (string pem in state.Chain.Skip(1))
        {
            intermediates.Add(X509Certificate2.CreateFromPem(pem));
        }
        var items = new List<AuditItem>();
        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            foreach (string name in StoreNames)
            {
                X509Certificate2Collection found;
                try
                {
                    using var store = new X509Store(name, location);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    found = store.Certificates;
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    continue;  // this store doesn't exist here
                }
                foreach (var cert in found)
                {
                    // The user's Root and CA stores also show the computer's: list each certificate
                    // once, under the store it really lives in.
                    if (location == StoreLocation.CurrentUser && items.Any(i => i.Location == StoreLocation.LocalMachine
                            && i.StoreName == name && i.Cert.Thumbprint == cert.Thumbprint))
                    {
                        cert.Dispose();
                        continue;
                    }
                    if (TiesToRoot(cert, root, intermediates))
                    {
                        items.Add(Describe(cert, location, name, root));
                    }
                    else
                    {
                        cert.Dispose();
                    }
                }
            }
        }
        foreach (var cert in intermediates)
        {
            cert.Dispose();
        }
        Flag(items);
        var uses = Binder.Uses();
        foreach (var item in items.Where(i => i.Location == StoreLocation.LocalMachine && i.StoreName == "My"))
        {
            item.UsedBy.AddRange(uses.GetValueOrDefault(item.Cert.Thumbprint) ?? []);
        }
        return items;
    }

    private static bool TiesToRoot(X509Certificate2 cert, X509Certificate2 root, X509Certificate2Collection intermediates)
    {
        if (cert.Thumbprint == root.Thumbprint)
        {
            return true;
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.ExtraStore.AddRange(intermediates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreCtlNotTimeValid;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        bool built = chain.Build(cert);
        return built && chain.ChainElements[^1].Certificate.Thumbprint == root.Thumbprint;
    }

    private static AuditItem Describe(X509Certificate2 cert, StoreLocation location, string storeName, X509Certificate2 root)
    {
        bool isCa = cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(b => b.CertificateAuthority);
        var names = new List<string>();
        foreach (var san in cert.Extensions.OfType<X509SubjectAlternativeNameExtension>())
        {
            names.AddRange(san.EnumerateDnsNames());
            names.AddRange(san.EnumerateIPAddresses().Select(ip => ip.ToString()));
        }
        string simple = cert.GetNameInfo(X509NameType.SimpleName, false);
        return new AuditItem
        {
            Cert = cert,
            Location = location,
            StoreName = storeName,
            IsCa = isCa,
            IsRoot = cert.Thumbprint == root.Thumbprint,
            Names = names.Count > 0 && !isCa ? string.Join(", ", names) : simple,
        };
    }

    /// <summary>Problems worth a look: expiry, missing keys, stale copies, CA certificates in the wrong store.</summary>
    /// <summary>What a certificate may be used for (its extended key usages), as one comparable string.</summary>
    private static string Purposes(X509Certificate2 cert) => string.Join(",",
        cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().SelectMany(e => e.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>())
            .Select(o => o.Value).Order(StringComparer.Ordinal));

    private static void Flag(List<AuditItem> items)
    {
        var now = DateTime.Now;
        foreach (var item in items)
        {
            if (item.Cert.NotAfter < now)
            {
                item.Flags.Add("Expired");
            }
            else if (item.Cert.NotAfter < now.AddDays(30))
            {
                item.Flags.Add(string.Create(CultureInfo.InvariantCulture, $"Expires in {(item.Cert.NotAfter - now).Days} days"));
            }
            if (item.IsRoot && item.StoreName != "Root")
            {
                item.Flags.Add("Root CA outside Trusted Root store");
            }
            if (item.IsCa && !item.IsRoot && item.StoreName == "Root")
            {
                item.Flags.Add("Intermediate CA in Trusted Root store (belongs in Intermediate CAs)");
            }
            if (!item.IsCa && item.StoreName == "My" && !item.Cert.HasPrivateKey)
            {
                item.Flags.Add("No private key");
            }
        }
        // the same names and the same purposes held more than once in one store: a copy left behind after a
        // renewal. A web server and a This computer certificate share the PC's name and are not copies.
        foreach (var group in items.Where(i => !i.IsCa).GroupBy(i => (i.Location, i.StoreName, i.Names, Purposes(i.Cert))).Where(g => g.Count() > 1))
        {
            foreach (var older in group.OrderByDescending(i => i.Cert.NotAfter).Skip(1))
            {
                older.Flags.Add("Older copy: a newer certificate has the same names");
            }
        }
        if (!items.Any(i => i.IsRoot && i.StoreName == "Root"))
        {
            items.FirstOrDefault(i => i.IsRoot)?.Flags.Add("The root isn't trusted here yet");
        }
    }

    /// <summary>Add the server's view (valid / revoked / expired / unknown) and which certificates the Pal issued.</summary>
    public static void ApplyServer(List<AuditItem> items, Dictionary<string, string> status, DeviceInfo? device)
    {
        var palBySerial = (device?.Certs ?? []).ToDictionary(c => NormalizeSerial(c.Serial), c => c);
        foreach (var item in items)
        {
            if (status.TryGetValue(item.Serial, out var s))
            {
                item.ServerStatus = s;
                if (s == "revoked")
                {
                    item.Flags.Insert(0, "REVOKED: remove it");
                }
            }
            item.FromPal = palBySerial.GetValueOrDefault(NormalizeSerial(item.Serial));
        }
    }

    /// <summary>The CRL distribution point addresses a certificate names.</summary>
    public static IEnumerable<string> CrlUrls(X509Certificate2 cert)
    {
        var ext = cert.Extensions["2.5.29.31"];
        return ext is null ? [] : System.Text.RegularExpressions.Regex.Matches(ext.Format(true), @"https?://[^\s,;]+")
            .Select(m => m.Value).Distinct();
    }

    /// <summary>Does this address answer? (What Windows needs to check revocation.)</summary>
    public static async Task<bool> ReachableAsync(string url)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            using var response = await http.SendAsync(new HttpRequestMessage(HttpMethod.Head, url)).ConfigureAwait(false);
            return response.IsSuccessStatusCode;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            return false;
        }
    }

    public static string NormalizeSerial(string serial)
    {
        string hex = serial.Replace(":", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).ToLowerInvariant();
        if (hex.StartsWith("0x", StringComparison.Ordinal))
        {
            hex = hex[2..];
        }
        return hex.TrimStart('0');
    }
}
