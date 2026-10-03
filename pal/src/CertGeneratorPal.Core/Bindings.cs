using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace CertGeneratorPal.Core;

/// <summary>Where a web server certificate should be used: Remote Desktop and/or one IIS site's https binding.</summary>
public sealed class BindRequest
{
    public bool Rdp { get; set; }

    /// <summary>The IIS site, as IIS Manager names it; null for none.</summary>
    public string? IisSite { get; set; }

    public int Port { get; set; } = 443;

    /// <summary>A host name for an SNI binding (one of the certificate's names); empty binds every name on the port.</summary>
    public string Host { get; set; } = "";

    public bool IsEmpty => !Rdp && IisSite is null;
}

/// <summary>An IIS site and its bindings, as appcmd lists them.</summary>
public sealed record IisSite(string Name, IReadOnlyList<IisBinding> Bindings);

/// <summary>One site binding. <see cref="CertificateHash"/> is IIS's own record of the certificate (https only, may be absent).</summary>
public sealed record IisBinding(string Protocol, string Information, string? CertificateHash = null)
{
    /// <summary>The port of "*:443:host"; 0 when it can't be read.</summary>
    public int Port => Information.Split(':') is [_, var port, ..] && int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out int p) ? p : 0;

    /// <summary>The host name of "*:443:host"; empty for every name.</summary>
    public string Host => Information.Split(':') is [_, _, var host] ? host : "";
}

/// <summary>
/// The rules for binding a certificate, kept free of Windows APIs: what the elevated helper
/// accepts, and how appcmd's output is read. appcmd gets each value as its own argument and
/// never through a shell, but a site name still can't carry characters its syntax treats specially.
/// </summary>
public static partial class BindingRules
{
    /// <summary>The address IIS gives "*" bindings: http.sys's IPv4 wildcard, which serves IPv6 too.</summary>
    public const string AnyAddress = "0.0.0.0";

    public static string? ValidThumbprint(string? thumbprint) =>
        thumbprint is { Length: 40 } t && t.All(Uri.IsHexDigit) ? t.ToUpperInvariant() : null;

    /// <summary>
    /// What a newly requested certificate may be bound to: a web server certificate to anything,
    /// a This computer certificate to Remote Desktop only (it has just the PC's own name). Null for nothing.
    /// </summary>
    public static BindRequest? ForUseCase(string useCase, BindRequest? request) => request is not { IsEmpty: false } ? null : useCase switch
    {
        UseCases.WebServer => request,
        UseCases.Computer when request.Rdp => new BindRequest { Rdp = true },
        _ => null,
    };

    /// <summary>Checks a request from the unelevated app before the helper acts on it. Throws with a short headline.</summary>
    public static void Validate(BindRequest request, IEnumerable<string> certificateNames)
    {
        if (request.IisSite is null)
        {
            return;
        }
        if (!IsValidSiteName(request.IisSite))
        {
            throw new PalException("Site name not allowed. Use the name IIS Manager shows, without quotes, brackets or slashes.");
        }
        if (request.Port is < 1 or > 65535)
        {
            throw new PalException("Port not allowed. Use 1 to 65535 (https is usually 443).");
        }
        if (request.Host.Length > 0)
        {
            if (!IsValidHost(request.Host))
            {
                throw new PalException("Host name not allowed. Use one of the certificate's names, or leave it empty for every name.");
            }
            if (!certificateNames.Any(n => string.Equals(n, request.Host, StringComparison.OrdinalIgnoreCase)))
            {
                throw new PalException($"Not in the certificate. {request.Host} isn't one of its names, so browsers would refuse it.");
            }
        }
    }

    public static bool IsValidSiteName(string name) =>
        name.Length is > 0 and <= 256 && name.Trim() == name && !name.Any(c => char.IsControl(c) || "'\"[]/\\%".Contains(c));

    /// <summary>A plain DNS name (no wildcard: the Pal never gets wildcard certificates).</summary>
    public static bool IsValidHost(string host) => host.Length <= 253 && HostPattern().IsMatch(host);

    [GeneratedRegex(@"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")]
    private static partial Regex HostPattern();

    /// <summary>IIS's bindingInformation for an https binding on every address: "*:443:" or "*:443:host".</summary>
    public static string BindingInformation(int port, string host) => string.Create(CultureInfo.InvariantCulture, $"*:{port}:{host}");

    /// <summary>Sites from "appcmd list site /config /xml": names, bindings and any certificate hash IIS recorded.</summary>
    public static List<IisSite> ParseSites(string appcmdXml)
    {
        XDocument doc;
        try
        {
            doc = XDocument.Parse(appcmdXml, LoadOptions.None);
        }
        catch (XmlException e)
        {
            throw new PalException("IIS's site list couldn't be read: " + e.Message);
        }
        var sites = new List<IisSite>();
        foreach (var listed in doc.Root?.Elements("SITE") ?? [])
        {
            string? name = (string?)listed.Attribute("SITE.NAME");
            if (name is null)
            {
                continue;
            }
            var config = listed.Element("site")?.Element("bindings");
            List<IisBinding> bindings;
            if (config is not null)
            {
                bindings = config.Elements("binding")
                    .Select(b => new IisBinding((string?)b.Attribute("protocol") ?? "", (string?)b.Attribute("bindingInformation") ?? "",
                        ValidThumbprint((string?)b.Attribute("certificateHash"))))
                    .ToList();
            }
            else
            {
                // without /config: bindings="http/*:80:,https/*:443:"
                bindings = ((string?)listed.Attribute("bindings") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(b => b.Split('/', 2))
                    .Where(p => p.Length == 2)
                    .Select(p => new IisBinding(p[0], p[1]))
                    .ToList();
            }
            sites.Add(new IisSite(name, bindings));
        }
        return sites;
    }
}
