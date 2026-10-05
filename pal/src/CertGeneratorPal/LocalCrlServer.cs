using System.Diagnostics;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>
/// The endpoint-hosted CRL: this PC answers its CA's placeholder CRL address itself, so revocation
/// checks work even when it can't reach the server (a laptop away from the LAN).
///
/// The same listener as the v2.7 install bundles (app/crl_local_server.py), sharing its state,
/// so the two never fight: a hosts entry sends pki.&lt;domain&gt; to 127.0.0.1, an HTTP.sys address
/// reserved for LOCAL SERVICE only, serve-crl.ps1 and the CRLs in a folder only Administrators
/// can change, and the "Cert Generator CRL server" task starting it at boot as LOCAL SERVICE.
/// </summary>
internal static partial class LocalCrlServer
{
    public const string TaskName = "Cert Generator CRL server";
    private const string Mark = "# cert-generator";
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier LocalService = new(WellKnownSidType.LocalServiceSid, null);

    private static string Base => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CertGenerator");
    private static string CrlDir => Path.Combine(Base, "crl");
    private static string HostList => Path.Combine(Base, "crl-hosts.txt");
    private static string PalRecord => Path.Combine(Base, "pal-crls.json");
    private static string System32 => Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static string HostsFile => Path.Combine(System32, "drivers", "etc", "hosts");

    [GeneratedRegex(@"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")]
    private static partial Regex HostPattern();

    [GeneratedRegex(@"^[A-Za-z0-9._-]{1,120}\.crl$")]
    private static partial Regex FilePattern();

    // ── Status (no elevation needed) ────────────────────────────────

    /// <summary>For each CA address: does this PC answer it right now?</summary>
    public static async Task<Dictionary<string, bool>> ProbeAsync(IEnumerable<SelfHostedCrl> addresses)
    {
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(2) };
        var result = new Dictionary<string, bool>();
        foreach (var a in addresses)
        {
            try
            {
                using var response = await http.SendAsync(new HttpRequestMessage(HttpMethod.Head, a.Url)).ConfigureAwait(false);
                var resolved = await Dns.GetHostAddressesAsync(a.Host).ConfigureAwait(false);
                result[a.Url] = response.IsSuccessStatusCode && resolved.Any(IPAddress.IsLoopback);  // answered by this PC, not the network
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or System.Net.Sockets.SocketException)
            {
                result[a.Url] = false;
            }
        }
        return result;
    }

    // ── Install / update (elevated) ─────────────────────────────────

    public static async Task<OpResult> InstallAsync(List<SelfHostedCrl> crls)
    {
        if (crls.Count == 0)
        {
            throw new PalException("Nothing to serve. The server didn't send any CRLs.");
        }
        foreach (var c in crls)
        {
            if (!HostPattern().IsMatch(c.Host) || !FilePattern().IsMatch(c.File) || c.Url != $"http://{c.Host}/crl/{c.File}" || c.Crl is null)
            {
                throw new PalException($"Bad CRL address from the server: {c.Url}");
            }
        }
        SecureBase();
        Directory.CreateDirectory(CrlDir);
        foreach (var c in crls)
        {
            DeviceState.AtomicWrite(Path.Combine(CrlDir, c.File), Convert.FromBase64String(c.Crl!));
        }
        await using (var script = typeof(LocalCrlServer).Assembly.GetManifestResourceStream("CertGeneratorPal.serve-crl.ps1")
                     ?? throw new PalException("The listener script is missing from this build."))
        await using (var file = File.Create(Path.Combine(Base, "serve-crl.ps1")))
        {
            await script.CopyToAsync(file).ConfigureAwait(false);
        }
        var hosts = ReadLines(HostList);
        foreach (string host in crls.Select(c => c.Host).Distinct())
        {
            if (!hosts.Contains(host))
            {
                hosts.Add(host);
            }
            AddHostsEntry(host);
            Run("netsh.exe", ["http", "delete", "urlacl", $"url=http://{host}:80/crl/"], allowFailure: true);  // an earlier install's reservation
            Run("netsh.exe", ["http", "add", "urlacl", $"url=http://{host}:80/crl/", "sddl=D:(A;;GX;;;LS)"]);
        }
        File.WriteAllLines(HostList, hosts);
        var record = ReadRecord();
        foreach (var c in crls)
        {
            record.RemoveAll(r => r.Url == c.Url);
            record.Add(new SelfHostedCrl { CaName = c.CaName, Url = c.Url, Host = c.Host, File = c.File, NextUpdate = c.NextUpdate });
        }
        File.WriteAllBytes(PalRecord, JsonSerializer.SerializeToUtf8Bytes(record, Json.Options));
        RegisterTask();
        Run("schtasks.exe", ["/End", "/TN", TaskName], allowFailure: true);  // restart: it reads the host list on start
        Run("schtasks.exe", ["/Run", "/TN", TaskName]);

        var probe = new Dictionary<string, bool>();
        for (int attempt = 0; attempt < 10 && !(probe.Count > 0 && probe.Values.All(v => v)); attempt++)
        {
            await Task.Delay(1000).ConfigureAwait(false);
            probe = await ProbeAsync(crls).ConfigureAwait(false);
        }
        if (!probe.Values.All(v => v))
        {
            throw new PalException("Listener not answering. The CRL server was installed but doesn't answer. " +
                "Is another program using port 80? It retries at the next restart.");
        }
        AppLog.Info("Endpoint-hosted CRL installed for " + string.Join(", ", crls.Select(c => c.Host).Distinct()));
        return OpResult.Success($"This PC now answers revocation checks itself for {string.Join(", ", crls.Select(c => c.CaName))}, " +
            "even away from your network. Use Update after your admin revokes a certificate.");
    }

    /// <summary>
    /// ProgramData lets any user create folders. One made in advance (or a link to elsewhere) would
    /// stay theirs, and they could swap the script the listener runs as LOCAL SERVICE, so it is
    /// moved aside rather than reused. Then: Administrators and SYSTEM change it, LOCAL SERVICE reads it.
    /// </summary>
    private static void SecureBase()
    {
        var info = new DirectoryInfo(Base);
        if (info.Exists)
        {
            bool link = info.Attributes.HasFlag(FileAttributes.ReparsePoint);
            var owner = link ? null : info.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (link || owner is null || !(owner.Equals(Administrators) || owner.Equals(LocalSystem)))
            {
                string aside = Base + ".untrusted-" + DateTime.Now.ToString("yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture);
                AppLog.Info($"{Base} isn't owned by Administrators: moving it aside to {aside}");
                Directory.Move(Base, aside);
                info = new DirectoryInfo(Base);
            }
        }
        var security = new DirectorySecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(LocalService, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (info.Exists)
        {
            info.SetAccessControl(security);
        }
        else
        {
            info.Create(security);
        }
    }

    private static void AddHostsEntry(string host)
    {
        string entry = $"127.0.0.1 {host} {Mark}";
        string raw = File.Exists(HostsFile) ? File.ReadAllText(HostsFile) : "";
        if (raw.Split('\n').Any(line => line.TrimEnd('\r') == entry))
        {
            return;
        }
        string prefix = raw.Length > 0 && !raw.EndsWith('\n') ? Environment.NewLine : "";  // don't join the last line
        File.AppendAllText(HostsFile, prefix + entry + Environment.NewLine, Encoding.ASCII);
    }

    private static void RegisterTask()
    {
        string powershell = Path.Combine(System32, "WindowsPowerShell", "v1.0", "powershell.exe");
        string script = Path.Combine(Base, "serve-crl.ps1");
        // SECURITY: ExecutionPolicy Bypass for this one script, as the v2.7 bundles do (accepted by the
        // project owner). The script lives in the folder only Administrators can change.
        string xml = $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Description>Answers this PC's CRL checks for Cert Generator (installed by Cert Generator Pal or an install bundle).</Description></RegistrationInfo>
              <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
              <Principals><Principal id="Author"><UserId>S-1-5-19</UserId><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
                <Enabled>true</Enabled>
              </Settings>
              <Actions Context="Author"><Exec><Command>{SecurityElement(powershell)}</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{SecurityElement(script)}"</Arguments></Exec></Actions>
            </Task>
            """;
        string temp = Path.Combine(Base, "task.xml");
        File.WriteAllText(temp, xml, Encoding.Unicode);
        try
        {
            Run("schtasks.exe", ["/Create", "/TN", TaskName, "/XML", temp, "/F"]);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    private static string SecurityElement(string text) => System.Security.SecurityElement.Escape(text) ?? "";

    // ── Remove (elevated) ───────────────────────────────────────────

    /// <summary>Take out what the Pal added. The task and folder go only when no other host (a v2.7 bundle's) still uses them.</summary>
    public static OpResult Remove()
    {
        var record = ReadRecord();
        if (record.Count == 0)
        {
            return OpResult.Success("The endpoint-hosted CRL isn't installed by Cert Generator Pal on this PC.");
        }
        var ours = record.Select(r => r.Host).Distinct().ToList();
        foreach (var r in record)
        {
            File.Delete(Path.Combine(CrlDir, r.File));
        }
        if (File.Exists(HostsFile))
        {
            var entries = ours.Select(h => $"127.0.0.1 {h} {Mark}").ToHashSet();
            var kept = File.ReadAllLines(HostsFile).Where(line => !entries.Contains(line.TrimEnd())).ToArray();
            File.WriteAllLines(HostsFile, kept, Encoding.ASCII);
        }
        foreach (string host in ours)
        {
            Run("netsh.exe", ["http", "delete", "urlacl", $"url=http://{host}:80/crl/"], allowFailure: true);
        }
        var left = ReadLines(HostList).Where(h => !ours.Contains(h)).ToList();
        Run("schtasks.exe", ["/End", "/TN", TaskName], allowFailure: true);
        if (left.Count == 0)
        {
            Run("schtasks.exe", ["/Delete", "/TN", TaskName, "/F"], allowFailure: true);
            Directory.Delete(Base, recursive: true);
            AppLog.Info("Endpoint-hosted CRL removed (listener and folder)");
            return OpResult.Success("Removed. This PC no longer answers revocation checks itself.");
        }
        File.WriteAllLines(HostList, left);
        File.Delete(PalRecord);
        Run("schtasks.exe", ["/Run", "/TN", TaskName], allowFailure: true);
        AppLog.Info("Endpoint-hosted CRL removed; listener kept for " + string.Join(", ", left));
        return OpResult.Success($"Removed. The listener keeps running for {string.Join(", ", left)} (installed by an install bundle).");
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private static List<string> ReadLines(string path) =>
        File.Exists(path) ? File.ReadAllLines(path).Select(l => l.Trim()).Where(l => HostPattern().IsMatch(l)).ToList() : [];

    private static List<SelfHostedCrl> ReadRecord()
    {
        try
        {
            return File.Exists(PalRecord) ? JsonSerializer.Deserialize<List<SelfHostedCrl>>(File.ReadAllBytes(PalRecord), Json.Options) ?? [] : [];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>Run a System32 tool with an argument list (no shell, no string building from input).</summary>
    private static void Run(string tool, IEnumerable<string> args, bool allowFailure = false)
    {
        var start = new ProcessStartInfo(Path.Combine(System32, tool))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string a in args)
        {
            start.ArgumentList.Add(a);
        }
        using var process = Process.Start(start) ?? throw new PalException($"Couldn't start {tool}.");
        string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0 && !allowFailure)
        {
            throw new PalException($"{tool} failed. {output.Trim()}");
        }
    }
}
