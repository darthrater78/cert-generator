using System.Text.Json;
using System.Text.Json.Serialization;

namespace CertGeneratorPal.Core;

public static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };
}

/// <summary>The four kinds of certificate a PC can request (server: app/pal.py USE_CASES).</summary>
public static class UseCases
{
    public const string WebServer = "web-server";
    public const string Computer = "computer";
    public const string User = "user";
    public const string CodeSigning = "code-signing";

    public static readonly IReadOnlyList<string> All = [Computer, WebServer, User, CodeSigning];

    /// <summary>Machine certificates go in LocalMachine\My and need administrator rights.</summary>
    public static bool IsMachine(string useCase) => useCase is WebServer or Computer;

    public static string Label(string useCase) => useCase switch
    {
        WebServer => "Web server / RDP",
        Computer => "This computer",
        User => "Me",
        CodeSigning => "Code signing",
        _ => useCase,
    };

    /// <summary>The use case a certificate was issued for, from its server-side template.</summary>
    public static string? FromTemplate(string? template) => template switch
    {
        "web-server" => WebServer,
        "computer" => Computer,
        "user" => User,
        "code-signing" => CodeSigning,
        _ => null,
    };
}

/// <summary>Revocation (CRL) types, as the server names them; each allowed one is a profile in the Pal.</summary>
public static class CrlTypes
{
    public static string Label(string crlDp) => crlDp switch
    {
        "server" => "Cert Generator (LAN)",
        "cloudflare" => "Cloudflare Worker",
        "placeholder" => "Self-hosted on this PC",
        "none" => "No revocation checks",
        _ => crlDp,
    };
}

public sealed class Policy
{
    public Dictionary<string, string> UseCases { get; set; } = [];
    public List<string> Dns { get; set; } = [];
    public List<string> Users { get; set; } = [];
    public int MaxDays { get; set; }
    public List<string> CrlDps { get; set; } = [];

    public string Mode(string useCase) => UseCases.GetValueOrDefault(useCase, "off");
}

public sealed class CrlEntry
{
    public string CaName { get; set; } = "";
    public string Crl { get; set; } = "";
}

public sealed class RequestNames
{
    public string? CommonName { get; set; }
    public List<string> San { get; set; } = [];
    public string? Upn { get; set; }
    public string? Email { get; set; }

    public string Display => Upn ?? (San.Count > 0 ? string.Join(", ", San) : CommonName ?? "");
}

public sealed class RequestView
{
    public int Id { get; set; }
    public string UseCase { get; set; } = "";
    public string Status { get; set; } = "";
    public string Reason { get; set; } = "";
    public string? CreatedAt { get; set; }
    public RequestNames Names { get; set; } = new();
    public int? CertId { get; set; }
    public int? RenewOf { get; set; }
    public string? Cert { get; set; }
    public string? Serial { get; set; }
    public string? NotAfter { get; set; }
    public List<string>? Chain { get; set; }
}

public sealed class DeviceCert
{
    public int Id { get; set; }
    public string CommonName { get; set; } = "";
    public string SanDomains { get; set; } = "";
    public string Template { get; set; } = "";
    public string Serial { get; set; } = "";
    public string NotAfter { get; set; } = "";
    public int Revoked { get; set; }

    /// <summary>When renewal opens (the server refuses earlier renewals).</summary>
    public string? RenewFrom { get; set; }

    public DateTimeOffset? RenewFromTime =>
        DateTimeOffset.TryParse(RenewFrom, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? t : null;
}

/// <summary>Where this PC's local CRL server answers for one CA, and (from /crls) its current CRL.</summary>
public sealed class SelfHostedCrl
{
    public string CaName { get; set; } = "";
    public string Url { get; set; } = "";
    public string Host { get; set; } = "";
    public string File { get; set; } = "";
    public string? Crl { get; set; }
    public string? NextUpdate { get; set; }
}

internal sealed class SelfHostedCrlsReply
{
    public List<SelfHostedCrl> Crls { get; set; } = [];
}

public sealed class DeviceInfo
{
    /// <summary>The server's release; the Pal that shipped with it has the same version.</summary>
    public string ServerVersion { get; set; } = "";

    public string CrlDp { get; set; } = "none";
    public List<string> CrlDps { get; set; } = [];
    public List<SelfHostedCrl> SelfHosted { get; set; } = [];

    /// <summary>For each revocation type the PC may use, the CRL address its certificates name.</summary>
    public Dictionary<string, string> CrlUrls { get; set; } = [];
    public string DeviceId { get; set; } = "";
    public string Label { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public string CaName { get; set; } = "";
    public Policy Policy { get; set; } = new();
    public List<string> Chain { get; set; } = [];
    public List<CrlEntry> Crls { get; set; } = [];
    public List<RequestView> Requests { get; set; } = [];
    public List<DeviceCert> Certs { get; set; } = [];
}

internal sealed class EnrollBody
{
    public string CodeId { get; set; } = "";
    public string DeviceKey { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public string Os { get; set; } = "";
    public long Ts { get; set; }
    public string Nonce { get; set; } = "";
}

internal sealed class CreateRequestBody
{
    public string UseCase { get; set; } = "";
    public Dictionary<string, object> Names { get; set; } = [];
    public string Csr { get; set; } = "";
    public int? LifetimeDays { get; set; }
    public int? RenewOf { get; set; }
    public string? CrlDp { get; set; }
}

internal sealed class StatusBody
{
    public List<string> Serials { get; set; } = [];
}

internal sealed class StatusReply
{
    public Dictionary<string, string> Status { get; set; } = [];
}

internal sealed class ErrorReply
{
    public string? Error { get; set; }
}
