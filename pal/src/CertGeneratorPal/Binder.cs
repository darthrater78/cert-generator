using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using CertGeneratorPal.Core;
using Microsoft.Win32;

namespace CertGeneratorPal;

/// <summary>
/// Puts a machine certificate to work: Remote Desktop and WinRM (a This computer certificate),
/// IIS sites (http.sys SSL bindings plus the site's https binding), RD Gateway and the RD
/// Connection Broker's roles (a web server certificate). A renewal repoints everything that
/// used the old certificate, whoever set it up, before the old one is removed.
/// </summary>
internal static class Binder
{
    /// <summary>Where each certificate is in use, by thumbprint, for the list and for warnings: "Remote Desktop", "HTTPS 0.0.0.0:443".</summary>
    public static Dictionary<string, List<string>> Uses()
    {
        var uses = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        void Add(string thumbprint, string use)
        {
            if (!uses.TryGetValue(thumbprint, out var list))
            {
                uses[thumbprint] = list = [];
            }
            list.Add(use);
        }
        try
        {
            if (Rdp.CurrentHash() is { } rdp)
            {
                Add(rdp, UseRdp);
            }
        }
        catch (Exception e) when (e is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            AppLog.Debug("Couldn't read the Remote Desktop certificate: " + e.Message);
        }
        foreach (string thumbprint in WinRm.ListedHashes())
        {
            Add(thumbprint, UseWinRm);
        }
        try
        {
            foreach (var binding in HttpSys.List())
            {
                Add(binding.Thumbprint, "HTTPS " + binding.Display);
            }
        }
        catch (PalException e)
        {
            AppLog.Debug("Couldn't read the HTTPS bindings: " + e.Message);
        }
        // RD Gateway and the broker's roles: Windows tells only an administrator, so these come from the Pal's own record.
        foreach (var (role, thumbprint) in BindLog.Read())
        {
            Add(thumbprint, role);
        }
        return uses;
    }

    public const string UseRdp = "Remote Desktop";
    public const string UseWinRm = "WinRM";
    public const string UseGateway = "RD Gateway";
    public const string UsePublishing = "RD Connection Broker (signs RDP files)";
    public const string UseRedirector = "RD Connection Broker (single sign-on)";

    /// <summary>The bind role behind one of <see cref="Uses"/>' labels; null for something else.</summary>
    public static string? TargetOf(string use) => use switch
    {
        UseRdp => BindKeys.Rdp,
        UseWinRm => BindKeys.WinRm,
        UseGateway => BindKeys.RdGateway,
        UsePublishing or UseRedirector => BindKeys.RdBroker,
        _ when use.StartsWith("HTTPS ", StringComparison.Ordinal) => BindKeys.Iis,
        _ => null,
    };

    /// <summary>
    /// Stop <paramref name="target"/> using the certificate. Remote Desktop goes back to Windows'
    /// own self-signed certificate; WinRM loses its HTTPS listener; IIS loses the https bindings
    /// that served it. RD Gateway and the broker can't run without a certificate: bind another instead.
    /// </summary>
    public static List<string> Remove(string thumbprint, string target) => target switch
    {
        BindKeys.Rdp => [Rdp.Remove(thumbprint)],
        BindKeys.WinRm => [WinRm.Remove(thumbprint)],
        BindKeys.Iis => Iis.Remove(thumbprint),
        _ => throw new PalException("Can't be removed. That role needs a certificate to run: bind another certificate to it instead."),
    };

    /// <summary>Use <paramref name="cert"/> (in LocalMachine\My, with its key) as <paramref name="request"/> says. Returns what changed.</summary>
    public static List<string> Apply(X509Certificate2 cert, BindRequest request)
    {
        BindingRules.Validate(request, DnsNames(cert));
        var notes = new List<string>();
        if (request.IisSite is { } site)
        {
            notes.Add(Iis.Bind(site, request.Port, request.Host, cert.Thumbprint));
        }
        if (request.Rdp)
        {
            notes.Add(Rdp.Use(cert));
        }
        if (request.WinRm)
        {
            notes.Add(WinRm.Use(cert));
        }
        if (request.RdGateway)
        {
            notes.Add(RdGateway.Use(cert));
        }
        if (request.RdPublishing)
        {
            notes.Add(RdBroker.Use(cert, RdBroker.Publishing));
        }
        if (request.RdRedirector)
        {
            notes.Add(RdBroker.Use(cert, RdBroker.Redirector));
        }
        return notes;
    }

    /// <summary>Everything that used <paramref name="oldThumbprint"/> now uses <paramref name="replacement"/>. Returns what moved.</summary>
    public static List<string> Repoint(string oldThumbprint, X509Certificate2 replacement)
    {
        var notes = new List<string>();
        foreach (var binding in HttpSys.List().Where(b => string.Equals(b.Thumbprint, oldThumbprint, StringComparison.OrdinalIgnoreCase)))
        {
            HttpSys.Replace(binding, replacement.Thumbprint);
            notes.Add($"HTTPS {binding.Display} now uses the new certificate.");
        }
        Iis.RepointConfig(oldThumbprint, replacement.Thumbprint);
        if (string.Equals(Rdp.CurrentHash(), oldThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            notes.Add(Rdp.Use(replacement));
        }
        if (WinRm.CurrentHashes().Contains(oldThumbprint, StringComparer.OrdinalIgnoreCase))
        {
            notes.Add(WinRm.Use(replacement));
        }
        if (string.Equals(RdGateway.CurrentHash(), oldThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            notes.Add(RdGateway.Use(replacement));
        }
        foreach (string role in RdBroker.RolesUsing(oldThumbprint))
        {
            notes.Add(RdBroker.Use(replacement, role));
        }
        return notes;
    }

    public static List<string> DnsNames(X509Certificate2 cert)
    {
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        return san is null ? [] : san.EnumerateDnsNames().ToList();
    }

    /// <summary>
    /// Lets NETWORK SERVICE read the certificate's private key: Remote Desktop and RD Gateway run
    /// as it. IIS and WinRM don't need this (http.sys does TLS in LSASS, as SYSTEM).
    /// </summary>
    internal static bool GrantNetworkService(X509Certificate2 cert)
    {
        using var ecdsa = cert.GetECDsaPrivateKey();
        using var rsa = ecdsa is null ? cert.GetRSAPrivateKey() : null;
        var key = (ecdsa as ECDsaCng)?.Key ?? (rsa as RSACng)?.Key
            ?? throw new PalException("Not a CNG key. Remote Desktop can't be given access to this certificate's key.");
        const string property = "Security Descr";
        const CngPropertyOptions dacl = (CngPropertyOptions)4;  // DACL_SECURITY_INFORMATION
        var sd = new RawSecurityDescriptor(key.GetProperty(property, dacl).GetValue()!, 0);
        var networkService = new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null);
        const int genericRead = unchecked((int)0x80000000);
        sd.DiscretionaryAcl ??= new RawAcl(GenericAcl.AclRevision, 1);
        if (sd.DiscretionaryAcl.Cast<GenericAce>().OfType<CommonAce>()
                .Any(a => a.SecurityIdentifier == networkService && a.AceQualifier == AceQualifier.AccessAllowed && (a.AccessMask & genericRead) != 0))
        {
            return false;
        }
        sd.DiscretionaryAcl.InsertAce(sd.DiscretionaryAcl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, genericRead, networkService, false, null));
        byte[] bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);
        key.SetProperty(new CngProperty(property, bytes, dacl));
        AppLog.Info($"Gave NETWORK SERVICE read access to the key of {cert.Thumbprint}");
        return true;
    }

    // ── Remote Desktop ──────────────────────────────────────────────

    internal static class Rdp
    {
        // What Win32_TSGeneralSetting.SSLCertificateSHA1Hash sets; read for every new connection.
        private const string KeyPath = @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
        private const string ValueName = "SSLCertificateSHA1Hash";

        public static string? CurrentHash()
        {
            using var key = Registry.LocalMachine.OpenSubKey(KeyPath);
            return key?.GetValue(ValueName) is byte[] { Length: 20 } hash ? Convert.ToHexString(hash) : null;
        }

        public static string Use(X509Certificate2 cert)
        {
            if (!cert.HasPrivateKey)
            {
                throw new PalException("No private key. Remote Desktop needs the certificate's key on this PC.");
            }
            string access = "";
            try
            {
                GrantNetworkService(cert);
            }
            catch (CryptographicException e)
            {
                // A TPM key may refuse a new ACL: say so rather than leave RDP silently on its old certificate.
                AppLog.Error("Couldn't give NETWORK SERVICE access to the key", e);
                access = " Windows refused to let Remote Desktop's service read the key, so it may keep its own certificate; see pal.log.";
            }
            using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: true)
                ?? throw new PalException("Remote Desktop isn't set up. Turn on Remote Desktop in Settings first.");
            key.SetValue(ValueName, Convert.FromHexString(cert.Thumbprint), RegistryValueKind.Binary);
            AppLog.Info($"Remote Desktop uses {cert.Thumbprint}");
            return "Remote Desktop uses it for new connections." + access;
        }

        public static string Remove(string thumbprint)
        {
            if (!string.Equals(CurrentHash(), thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                return "Remote Desktop wasn't using it.";
            }
            using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: true)
                ?? throw new PalException("Remote Desktop isn't set up. There is nothing to remove.");
            key.DeleteValue(ValueName, throwOnMissingValue: false);
            AppLog.Info($"Remote Desktop no longer uses {thumbprint}");
            return "Remote Desktop goes back to Windows' own self-signed certificate for new connections.";
        }
    }

    // ── WinRM, RD Gateway, RD Connection Broker (their PowerShell interfaces) ──

    /// <summary>A Windows service is installed (running or not).</summary>
    private static bool ServiceInstalled(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + name);
            return key is not null;
        }
        catch (Exception e) when (e is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return false;
        }
    }

    private static string NormalizeHash(string? text) =>
        BindingRules.ValidThumbprint(new string((text ?? "").Where(Uri.IsHexDigit).ToArray())) ?? "";

    /// <summary>
    /// Windows PowerShell, for the roles whose supported interface is a PowerShell module. The
    /// script is fixed text; values reach it as environment variables, never as part of the command.
    /// </summary>
    private static class PowerShell
    {
        private static string Exe => Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

        /// <summary>Runs <paramref name="script"/> and returns its output lines. Throws "<paramref name="what"/> refused. …" when it fails.</summary>
        public static List<string> Run(string what, string script, params (string Name, string Value)[] values)
        {
            // A failure leaves as one plain line on stderr, not PowerShell's CLIXML error record.
            string wrapped = "$ErrorActionPreference = 'Stop'\ntry {\n" + script +
                "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
            var start = new ProcessStartInfo(Exe)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            // RemoteSigned, for this one process: the role modules are script modules, which the default policy on a client PC blocks.
            foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-EncodedCommand",
                         Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(wrapped)) })
            {
                start.ArgumentList.Add(arg);
            }
            // This runs elevated: load modules from Windows' own folder only, never from a user's profile.
            start.Environment["PSModulePath"] = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "Modules");
            foreach (var (name, value) in values)
            {
                start.Environment["PAL_" + name] = value;
            }
            Process? started;
            try
            {
                started = Process.Start(start);
            }
            catch (System.ComponentModel.Win32Exception e)
            {
                throw new PalException("Windows PowerShell didn't start: " + e.Message);
            }
            using var process = started ?? throw new PalException("Windows PowerShell didn't start.");
            var stderr = process.StandardError.ReadToEndAsync();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                string why = stderr.GetAwaiter().GetResult().Trim();
                throw new PalException(what + " refused. " + (why.Length > 300 ? why[..300] : why));
            }
            return [.. output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];
        }

        /// <summary>The same for a question: no answer (and a debug line) when it can't be asked.</summary>
        public static List<string> TryRun(string what, string script, params (string Name, string Value)[] values)
        {
            try
            {
                return Run(what, script, values);
            }
            catch (Exception e) when (e is PalException or IOException)
            {
                AppLog.Debug(e.Message);
                return [];
            }
        }
    }

    /// <summary>The WinRM HTTPS listener (PowerShell remoting over TLS, port 5986).</summary>
    internal static class WinRm
    {
        private const string ListenerKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener";

        /// <summary>The HTTPS listeners' certificates as WinRM's configuration in the registry lists them: for display, readable unelevated.</summary>
        public static List<string> ListedHashes()
        {
            var hashes = new List<string>();
            try
            {
                using var listeners = Registry.LocalMachine.OpenSubKey(ListenerKey);
                foreach (string name in listeners?.GetSubKeyNames() ?? [])
                {
                    if (!name.EndsWith("+HTTPS", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    using var listener = listeners!.OpenSubKey(name);
                    if (NormalizeHash(listener?.GetValue("certThumbprint") as string) is { Length: > 0 } hash)
                    {
                        hashes.Add(hash);
                    }
                }
            }
            catch (Exception e) when (e is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
                AppLog.Debug("Couldn't read the WinRM listeners: " + e.Message);
            }
            return hashes;
        }

        /// <summary>The same, asked of WinRM itself (it must be running): what a renewal goes by.</summary>
        public static List<string> CurrentHashes() => PowerShell.TryRun("WinRM",
                "Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate | Where-Object { $_.Transport -eq 'HTTPS' } | ForEach-Object { $_.CertificateThumbprint }")
            .Select(NormalizeHash).Where(h => h.Length > 0).ToList();

        public static string Use(X509Certificate2 cert)
        {
            // WinRM matches the listener's host name against the certificate's subject, not its other names.
            string host = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            if (!BindingRules.IsValidHost(host))
            {
                throw new PalException("Name not usable. WinRM needs a certificate issued to a DNS name; this one is issued to " + host + ".");
            }
            var result = PowerShell.Run("WinRM",
                """
                $listeners = @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate | Where-Object { $_.Transport -eq 'HTTPS' })
                if ($listeners.Count -gt 0) {
                    foreach ($l in $listeners) {
                        Set-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{ Address = $l.Address; Transport = 'HTTPS' } -ValueSet @{ CertificateThumbprint = $env:PAL_THUMBPRINT } | Out-Null
                    }
                    'updated'
                } else {
                    New-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{ Address = '*'; Transport = 'HTTPS' } -ValueSet @{ Hostname = $env:PAL_HOST; CertificateThumbprint = $env:PAL_THUMBPRINT } | Out-Null
                    'created'
                }
                """, ("THUMBPRINT", cert.Thumbprint), ("HOST", host));
            bool created = result.Contains("created");
            AppLog.Info($"WinRM HTTPS listener {(created ? "created with" : "now uses")} {cert.Thumbprint}");
            return created
                ? $"WinRM now listens for HTTPS on port 5986 as {host}. Windows Firewall wasn't changed: open that port if other PCs should reach it."
                : "WinRM's HTTPS listener uses it.";
        }

        /// <summary>Remove the HTTPS listeners that use this certificate (a listener can't exist without one).</summary>
        public static string Remove(string thumbprint)
        {
            var result = PowerShell.Run("WinRM",
                """
                $removed = 0
                foreach ($l in @(Get-WSManInstance -ResourceURI winrm/config/Listener -Enumerate | Where-Object { $_.Transport -eq 'HTTPS' })) {
                    if (($l.CertificateThumbprint -replace '[^0-9A-Fa-f]', '') -eq $env:PAL_THUMBPRINT) {
                        Remove-WSManInstance -ResourceURI winrm/config/Listener -SelectorSet @{ Address = $l.Address; Transport = 'HTTPS' }
                        $removed++
                    }
                }
                "removed $removed"
                """, ("THUMBPRINT", thumbprint));
            bool any = !result.Contains("removed 0");
            AppLog.Info($"WinRM HTTPS listener for {thumbprint}: {string.Join(" ", result)}");
            return any ? "WinRM's HTTPS listener was removed. WinRM over HTTP, if it is on, is unchanged." : "WinRM wasn't using it.";
        }
    }

    /// <summary>The RD Gateway role service on this PC.</summary>
    internal static class RdGateway
    {
        public static bool IsInstalled => ServiceInstalled("TSGateway");

        public static string? CurrentHash() => !IsInstalled ? null
            : PowerShell.TryRun("RD Gateway",
                    "Import-Module RemoteDesktopServices\n(Get-Item -Path 'RDS:\\GatewayServer\\SSLCertificate\\Thumbprint').CurrentValue")
                .Select(NormalizeHash).FirstOrDefault(h => h.Length > 0);

        public static string Use(X509Certificate2 cert)
        {
            if (!IsInstalled)
            {
                throw new PalException("RD Gateway isn't installed. Add the Remote Desktop Gateway role service first.");
            }
            string access = "";
            try
            {
                GrantNetworkService(cert);  // the gateway's own service handles its UDP transport
            }
            catch (CryptographicException e)
            {
                AppLog.Error("Couldn't give NETWORK SERVICE access to the key", e);
                access = " Windows refused to let the gateway's service read the key, so its UDP transport may not use it; see pal.log.";
            }
            PowerShell.Run("RD Gateway",
                """
                Import-Module RemoteDesktopServices
                Set-Item -Path 'RDS:\GatewayServer\SSLCertificate\Thumbprint' -Value $env:PAL_THUMBPRINT
                Restart-Service -Name TSGateway -Force
                """, ("THUMBPRINT", cert.Thumbprint));
            BindLog.Set(UseGateway, cert.Thumbprint);
            AppLog.Info($"RD Gateway uses {cert.Thumbprint}");
            return "RD Gateway uses it; its service was restarted." + access;
        }
    }

    /// <summary>
    /// The RD Connection Broker's own certificates, when this PC is the broker. Each role is set on
    /// the PC that runs it, from its own store: the key never leaves, so the broker can't hand it to
    /// other servers. RD Web Access is an IIS site and RD Gateway has its own entry.
    /// </summary>
    internal static class RdBroker
    {
        public const string Publishing = "RDPublishing";
        public const string Redirector = "RDRedirector";

        public static bool IsInstalled => ServiceInstalled("RDMS");

        public static List<string> RolesUsing(string thumbprint) => !IsInstalled ? []
            : PowerShell.TryRun("RD Connection Broker",
                    "Import-Module RemoteDesktop\nGet-RDCertificate | Where-Object { $_.Thumbprint -eq $env:PAL_THUMBPRINT } | ForEach-Object { [string]$_.Role }",
                    ("THUMBPRINT", thumbprint))
                .Where(r => r is Publishing or Redirector).ToList();

        public static string Use(X509Certificate2 cert, string role)
        {
            if (role is not (Publishing or Redirector))
            {
                throw new PalException("Unknown Remote Desktop role.");
            }
            if (!IsInstalled)
            {
                throw new PalException("Not a Connection Broker. This PC doesn't run the RD Connection Broker role.");
            }
            PowerShell.Run("RD Connection Broker",
                """
                Import-Module RemoteDesktop
                Set-RDCertificate -Role $env:PAL_ROLE -Thumbprint $env:PAL_THUMBPRINT -Force
                """, ("ROLE", role), ("THUMBPRINT", cert.Thumbprint));
            BindLog.Set(role == Publishing ? UsePublishing : UseRedirector, cert.Thumbprint);
            AppLog.Info($"RD Connection Broker {role} uses {cert.Thumbprint}");
            return role == Publishing ? "RD Connection Broker signs RDP files with it." : "RD Connection Broker uses it for single sign-on.";
        }
    }

    // ── IIS (appcmd) ────────────────────────────────────────────────

    internal static class Iis
    {
        private static string AppCmd => Path.Combine(Environment.SystemDirectory, "inetsrv", "appcmd.exe");

        public static bool IsInstalled => File.Exists(AppCmd);

        /// <summary>The sites, or null when IIS isn't installed or this account can't read its configuration.</summary>
        public static List<IisSite>? TryListSites()
        {
            if (!IsInstalled)
            {
                return null;
            }
            try
            {
                return BindingRules.ParseSites(Run("list", "site", "/config", "/xml"));
            }
            catch (PalException e)
            {
                AppLog.Debug("Couldn't list IIS sites: " + e.Message);
                return null;
            }
        }

        public static string Bind(string site, int port, string host, string thumbprint)
        {
            if (!IsInstalled)
            {
                throw new PalException("IIS isn't installed. Add the Web Server (IIS) role or feature first.");
            }
            var found = BindingRules.ParseSites(Run("list", "site", "/config", "/xml"))
                .FirstOrDefault(s => string.Equals(s.Name, site, StringComparison.OrdinalIgnoreCase))
                ?? throw new PalException($"No such site. IIS has no site named {site}.");
            string info = BindingRules.BindingInformation(port, host);
            bool exists = found.Bindings.Any(b => b.Protocol == "https" && b.Port == port && string.Equals(b.Host, host, StringComparison.OrdinalIgnoreCase));
            // http.sys first: once the site has the binding, IIS serves that port with whatever http.sys holds.
            HttpSys.Bind(port, host, thumbprint);
            if (!exists)
            {
                string flags = host.Length > 0 ? "1" : "0";  // 1 = SNI
                Run("set", "site", found.Name, $"/+bindings.[protocol='https',bindingInformation='{info}',sslFlags='{flags}']");
                AppLog.Info($"Added https binding {info} to IIS site {found.Name}");
            }
            SetConfigHash(found.Name, info, thumbprint);
            return $"IIS site {found.Name} serves HTTPS on port {port}" + (host.Length > 0 ? $" for {host}." : ".");
        }

        /// <summary>
        /// Take the certificate out of service: every HTTPS binding http.sys serves with it goes, and
        /// so does the matching https binding on the IIS site, so the site isn't left with one that has no certificate.
        /// </summary>
        public static List<string> Remove(string thumbprint)
        {
            var notes = new List<string>();
            var sites = TryListSites() ?? [];
            foreach (var binding in HttpSys.List().Where(b => string.Equals(b.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase)))
            {
                string host = binding.Sni ? binding.Host ?? "" : "";
                foreach (var site in sites.Where(s => s.Bindings.Any(sb => sb.Protocol == "https" && sb.Port == binding.Port
                             && string.Equals(sb.Host, host, StringComparison.OrdinalIgnoreCase))))
                {
                    if (!BindingRules.IsValidSiteName(site.Name) || (host.Length > 0 && !BindingRules.IsValidHost(host)))
                    {
                        continue;  // never hand appcmd a name its syntax would read as something else
                    }
                    Run("set", "site", site.Name, $"/-bindings.[protocol='https',bindingInformation='{BindingRules.BindingInformation(binding.Port, host)}']");
                    notes.Add($"IIS site {site.Name} no longer serves HTTPS on port {binding.Port}" + (host.Length > 0 ? $" for {host}." : "."));
                }
                HttpSys.Remove(binding);
                notes.Add($"HTTPS {binding.Display} no longer has a certificate.");
            }
            return notes.Count > 0 ? notes : ["No HTTPS binding was using it."];
        }

        /// <summary>IIS also records the certificate on the binding (IIS Manager shows it); keep that in step. Best effort.</summary>
        public static void RepointConfig(string oldThumbprint, string newThumbprint)
        {
            foreach (var site in TryListSites() ?? [])
            {
                foreach (var binding in site.Bindings.Where(b => b.Protocol == "https" && string.Equals(b.CertificateHash, oldThumbprint, StringComparison.OrdinalIgnoreCase)))
                {
                    SetConfigHash(site.Name, binding.Information, newThumbprint);
                }
            }
        }

        private static void SetConfigHash(string site, string info, string thumbprint)
        {
            string selector = $"/bindings.[protocol='https',bindingInformation='{info}']";
            try
            {
                Run("set", "site", site, selector + ".certificateHash:" + thumbprint, selector + ".certificateStoreName:My");
            }
            catch (PalException e)
            {
                AppLog.Info($"IIS didn't record the certificate on {site} {info} (it still serves it): {e.Message}");
            }
        }

        /// <summary>Runs appcmd with each value as its own argument: never a shell, never a command line built from input.</summary>
        private static string Run(params string[] args)
        {
            var start = new ProcessStartInfo(AppCmd)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (string arg in args)
            {
                start.ArgumentList.Add(arg);
            }
            using var process = Process.Start(start) ?? throw new PalException("IIS's appcmd didn't start.");
            var stderr = process.StandardError.ReadToEndAsync();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0)
            {
                string why = (output + " " + stderr.GetAwaiter().GetResult()).Trim();
                throw new PalException("IIS refused. " + (why.Length > 300 ? why[..300] : why));
            }
            return output;
        }
    }

    // ── http.sys SSL bindings (httpapi.dll) ─────────────────────────

    /// <summary>
    /// The http.sys SSL bindings, through its API rather than netsh, whose output Windows translates.
    /// Both kinds: address:port (IIS "*" bindings, other HTTPS servers) and host:port (SNI).
    /// </summary>
    internal static unsafe class HttpSys
    {
        /// <summary>The application id IIS gives its bindings.</summary>
        private static readonly Guid IisAppId = new("4dc3e181-e14b-4a21-b022-59fc669b0914");

        private const int ConfigSslCertInfo = 1;
        private const int ConfigSslSniCertInfo = 7;
        private const int QueryNext = 1;
        private const uint NoError = 0;
        private const uint ErrorFileNotFound = 2;
        private const uint ErrorInsufficientBuffer = 122;
        private const uint ErrorNoMoreItems = 259;
        private const uint InitializeConfig = 2;
        private const ushort AfInet = 2;
        private const ushort AfInet6 = 23;

        /// <summary>One SSL binding, with every setting kept so a repoint changes only the certificate.</summary>
        internal sealed class SslBinding
        {
            public required bool Sni { get; init; }
            public required byte[] SockAddr { get; init; }  // 128 bytes (SOCKADDR_STORAGE)
            public string? Host { get; init; }
            public required string Thumbprint { get; init; }
            public Guid AppId { get; init; }
            public string? StoreName { get; init; }
            public uint CertCheckMode { get; init; }
            public uint RevocationFreshnessTime { get; init; }
            public uint RevocationUrlRetrievalTimeout { get; init; }
            public string? CtlIdentifier { get; init; }
            public string? CtlStoreName { get; init; }
            public uint Flags { get; init; }

            public int Port => (SockAddr[2] << 8) | SockAddr[3];

            public string Display => Sni
                ? $"{Host}:{Port}"
                : BitConverter.ToUInt16(SockAddr, 0) == AfInet6
                    ? $"[{new IPAddress(SockAddr.AsSpan(8, 16))}]:{Port}"
                    : $"{new IPAddress(SockAddr.AsSpan(4, 4))}:{Port}";
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ApiVersion
        {
            public ushort Major;
            public ushort Minor;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SslParam
        {
            public uint SslHashLength;
            public IntPtr SslHash;
            public Guid AppId;
            public IntPtr SslCertStoreName;
            public uint DefaultCertCheckMode;
            public uint DefaultRevocationFreshnessTime;
            public uint DefaultRevocationUrlRetrievalTimeout;
            public IntPtr DefaultSslCtlIdentifier;
            public IntPtr DefaultSslCtlStoreName;
            public uint DefaultFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SslSet
        {
            public IntPtr IpPort;
            public SslParam Param;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SslQuery
        {
            public int QueryDesc;
            public IntPtr IpPort;
            public uint Token;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SockAddrStorage
        {
            public fixed long Data[16];  // 128 bytes, 8-byte aligned like SOCKADDR_STORAGE
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SniKey
        {
            public SockAddrStorage IpPort;
            public IntPtr Host;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SniSet
        {
            public SniKey Key;
            public SslParam Param;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SniQuery
        {
            public int QueryDesc;
            public SniKey Key;
            public uint Token;
        }

        public static List<SslBinding> List()
        {
            return WithApi(() =>
            {
                var bindings = new List<SslBinding>();
                foreach (bool sni in (ReadOnlySpan<bool>)[false, true])
                {
                    for (uint token = 0; ; token++)
                    {
                        var binding = QueryAt(sni, token);
                        if (binding is null)
                        {
                            break;
                        }
                        bindings.Add(binding);
                    }
                }
                return bindings;
            });
        }

        /// <summary>Serve <paramref name="thumbprint"/> on *:port (empty host) or host:port (SNI), keeping an existing binding's settings.</summary>
        public static void Bind(int port, string host, string thumbprint)
        {
            byte[] sockaddr = new byte[128];
            BitConverter.TryWriteBytes(sockaddr.AsSpan(0, 2), AfInet);
            sockaddr[2] = (byte)(port >> 8);
            sockaddr[3] = (byte)port;  // address 0.0.0.0: every address (and SNI keys must use it)
            bool sni = host.Length > 0;
            var existing = List().FirstOrDefault(b => b.Sni == sni && b.Port == port
                && (sni ? string.Equals(b.Host, host, StringComparison.OrdinalIgnoreCase) : b.SockAddr.AsSpan(0, 8).SequenceEqual(sockaddr.AsSpan(0, 8))));
            if (existing is not null)
            {
                if (existing.Thumbprint != thumbprint)
                {
                    Replace(existing, thumbprint);
                }
                return;
            }
            WithApi(() =>
            {
                Check(Set(new SslBinding { Sni = sni, SockAddr = sockaddr, Host = sni ? host : null, Thumbprint = thumbprint, AppId = IisAppId, StoreName = "MY" }),
                    "add the HTTPS binding");
                return true;
            });
            AppLog.Info($"http.sys: {(sni ? host : BindingRules.AnyAddress)}:{port} → {thumbprint}");
        }

        /// <summary>Delete one binding: that address and port then has no certificate.</summary>
        public static void Remove(SslBinding binding)
        {
            WithApi(() =>
            {
                Check(Delete(binding), "remove the HTTPS binding");
                return true;
            });
            AppLog.Info($"http.sys: {binding.Display} removed (was {binding.Thumbprint})");
        }

        /// <summary>Swap the certificate on one binding; on failure, the old one is put back.</summary>
        public static void Replace(SslBinding binding, string thumbprint)
        {
            WithApi(() =>
            {
                Check(Delete(binding), "change the HTTPS binding");
                var updated = new SslBinding
                {
                    Sni = binding.Sni, SockAddr = binding.SockAddr, Host = binding.Host, Thumbprint = thumbprint, AppId = binding.AppId,
                    StoreName = binding.StoreName, CertCheckMode = binding.CertCheckMode, RevocationFreshnessTime = binding.RevocationFreshnessTime,
                    RevocationUrlRetrievalTimeout = binding.RevocationUrlRetrievalTimeout, CtlIdentifier = binding.CtlIdentifier,
                    CtlStoreName = binding.CtlStoreName, Flags = binding.Flags,
                };
                uint error = Set(updated);
                if (error != NoError)
                {
                    Set(binding);  // put the old certificate back rather than leave the port without one
                    Check(error, "change the HTTPS binding");
                }
                return true;
            });
            AppLog.Info($"http.sys: {binding.Display} {binding.Thumbprint} → {thumbprint}");
        }

        private static T WithApi<T>(Func<T> action)
        {
            var version = new ApiVersion { Major = 1, Minor = 0 };
            Check(HttpInitialize(version, InitializeConfig, IntPtr.Zero), "read the HTTPS bindings");
            try
            {
                return action();
            }
            finally
            {
                _ = HttpTerminate(InitializeConfig, IntPtr.Zero);
            }
        }

        private static void Check(uint error, string what)
        {
            if (error != NoError)
            {
                throw new PalException($"Windows couldn't {what} (error {error}). See pal.log.");
            }
        }

        private static SslBinding? QueryAt(bool sni, uint token)
        {
            int size = 4096;
            while (true)
            {
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try
                {
                    uint returned;
                    uint error;
                    if (sni)
                    {
                        var query = new SniQuery { QueryDesc = QueryNext, Token = token };
                        error = HttpQueryServiceConfiguration(IntPtr.Zero, ConfigSslSniCertInfo, &query, (uint)sizeof(SniQuery),
                            (void*)buffer, (uint)size, &returned, IntPtr.Zero);
                    }
                    else
                    {
                        var query = new SslQuery { QueryDesc = QueryNext, Token = token };
                        error = HttpQueryServiceConfiguration(IntPtr.Zero, ConfigSslCertInfo, &query, (uint)sizeof(SslQuery),
                            (void*)buffer, (uint)size, &returned, IntPtr.Zero);
                    }
                    if (error == ErrorNoMoreItems || error == ErrorFileNotFound)
                    {
                        return null;
                    }
                    if (error == ErrorInsufficientBuffer && returned > size)
                    {
                        size = (int)returned;
                        continue;
                    }
                    Check(error, "read the HTTPS bindings");
                    return sni ? ReadSni((SniSet*)buffer) : ReadSsl((SslSet*)buffer);
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }

        private static SslBinding ReadSsl(SslSet* set)
        {
            byte[] sockaddr = new byte[128];
            ushort family = *(ushort*)set->IpPort;
            new ReadOnlySpan<byte>((void*)set->IpPort, family == AfInet6 ? 28 : 16).CopyTo(sockaddr);
            return FromParam(false, sockaddr, null, set->Param);
        }

        private static SslBinding ReadSni(SniSet* set)
        {
            byte[] sockaddr = new byte[128];
            new ReadOnlySpan<byte>(set->Key.IpPort.Data, 128).CopyTo(sockaddr);
            return FromParam(true, sockaddr, Marshal.PtrToStringUni(set->Key.Host), set->Param);
        }

        private static SslBinding FromParam(bool sni, byte[] sockaddr, string? host, SslParam p) => new()
        {
            Sni = sni,
            SockAddr = sockaddr,
            Host = host,
            Thumbprint = Convert.ToHexString(new ReadOnlySpan<byte>((void*)p.SslHash, (int)p.SslHashLength)),
            AppId = p.AppId,
            StoreName = Marshal.PtrToStringUni(p.SslCertStoreName),
            CertCheckMode = p.DefaultCertCheckMode,
            RevocationFreshnessTime = p.DefaultRevocationFreshnessTime,
            RevocationUrlRetrievalTimeout = p.DefaultRevocationUrlRetrievalTimeout,
            CtlIdentifier = Marshal.PtrToStringUni(p.DefaultSslCtlIdentifier),
            CtlStoreName = Marshal.PtrToStringUni(p.DefaultSslCtlStoreName),
            Flags = p.DefaultFlags,
        };

        private static uint Set(SslBinding b) => WithStructs(b, (set, size, id) => HttpSetServiceConfiguration(IntPtr.Zero, id, set, size, IntPtr.Zero));

        private static uint Delete(SslBinding b) => WithStructs(b, (set, size, id) => HttpDeleteServiceConfiguration(IntPtr.Zero, id, set, size, IntPtr.Zero));

        private delegate uint ConfigCall(void* set, uint size, int configId);

        /// <summary>Lays a binding out in unmanaged memory as http.sys expects, for one call.</summary>
        private static uint WithStructs(SslBinding b, ConfigCall call)
        {
            var allocated = new List<IntPtr>();
            IntPtr Alloc(byte[] bytes)
            {
                IntPtr p = Marshal.AllocHGlobal(bytes.Length);
                Marshal.Copy(bytes, 0, p, bytes.Length);
                allocated.Add(p);
                return p;
            }
            IntPtr Str(string? s)
            {
                if (s is null)
                {
                    return IntPtr.Zero;
                }
                IntPtr p = Marshal.StringToHGlobalUni(s);
                allocated.Add(p);
                return p;
            }
            try
            {
                byte[] hash = Convert.FromHexString(b.Thumbprint);
                var param = new SslParam
                {
                    SslHashLength = (uint)hash.Length,
                    SslHash = Alloc(hash),
                    AppId = b.AppId,
                    SslCertStoreName = Str(b.StoreName),
                    DefaultCertCheckMode = b.CertCheckMode,
                    DefaultRevocationFreshnessTime = b.RevocationFreshnessTime,
                    DefaultRevocationUrlRetrievalTimeout = b.RevocationUrlRetrievalTimeout,
                    DefaultSslCtlIdentifier = Str(b.CtlIdentifier),
                    DefaultSslCtlStoreName = Str(b.CtlStoreName),
                    DefaultFlags = b.Flags,
                };
                if (b.Sni)
                {
                    var set = new SniSet { Param = param };
                    b.SockAddr.AsSpan(0, 128).CopyTo(new Span<byte>(set.Key.IpPort.Data, 128));
                    set.Key.Host = Str(b.Host);
                    return call(&set, (uint)sizeof(SniSet), ConfigSslSniCertInfo);
                }
                else
                {
                    var set = new SslSet { IpPort = Alloc(b.SockAddr), Param = param };
                    return call(&set, (uint)sizeof(SslSet), ConfigSslCertInfo);
                }
            }
            finally
            {
                allocated.ForEach(Marshal.FreeHGlobal);
            }
        }

        [DllImport("httpapi.dll")]
        private static extern uint HttpInitialize(ApiVersion version, uint flags, IntPtr reserved);

        [DllImport("httpapi.dll")]
        private static extern uint HttpTerminate(uint flags, IntPtr reserved);

        [DllImport("httpapi.dll")]
        private static extern uint HttpQueryServiceConfiguration(IntPtr serviceHandle, int configId, void* input, uint inputLength,
            void* output, uint outputLength, uint* returnLength, IntPtr overlapped);

        [DllImport("httpapi.dll")]
        private static extern uint HttpSetServiceConfiguration(IntPtr serviceHandle, int configId, void* config, uint configLength, IntPtr overlapped);

        [DllImport("httpapi.dll")]
        private static extern uint HttpDeleteServiceConfiguration(IntPtr serviceHandle, int configId, void* config, uint configLength, IntPtr overlapped);
    }
}
