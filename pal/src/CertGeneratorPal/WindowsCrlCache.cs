using System.Diagnostics;
using System.Runtime.InteropServices;
using CertGeneratorPal.Core;
using Microsoft.Win32;

namespace CertGeneratorPal;

/// <summary>
/// What Windows itself has cached for a CRL address, and the two ways to make it look again. The cache
/// read here is this account's: services that run as SYSTEM keep their own, which only a forced re-check reaches.
/// </summary>
internal static class WindowsCrlCache
{
    private const string ChainConfig = @"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Config";
    private static readonly IntPtr ContextOidCrl = 2;
    private const uint CacheOnlyRetrieval = 0x00000002;  // never the network: only what is cached already

    /// <summary>The CRL Windows holds for this address, or null when it holds none.</summary>
    public static CrlList? Read(string url)
    {
        if (!IsWebAddress(url))
        {
            return null;
        }
        try
        {
            if (!NativeMethods.CryptRetrieveObjectByUrl(url, ContextOidCrl, CacheOnlyRetrieval, 0, out IntPtr context, 0, 0, 0, 0) || context == 0)
            {
                return null;
            }
            try
            {
                // CRL_CONTEXT: dwCertEncodingType, pbCrlEncoded, cbCrlEncoded, …
                IntPtr encoded = Marshal.ReadIntPtr(context, IntPtr.Size);
                int length = Marshal.ReadInt32(context, 2 * IntPtr.Size);
                if (encoded == 0 || length is <= 0 or > 16 * 1024 * 1024)
                {
                    return null;
                }
                byte[] der = new byte[length];
                Marshal.Copy(encoded, der, 0, length);
                return CrlList.Parse(der);
            }
            finally
            {
                NativeMethods.CertFreeCRLContext(context);
            }
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            AppLog.Error("Couldn't read Windows' CRL cache", e);
            return null;
        }
    }

    /// <summary>When a re-check was last forced on this PC (ChainCacheResyncFiletime), or null when never.</summary>
    public static DateTimeOffset? ResyncTime()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(ChainConfig);
            return key?.GetValue("ChainCacheResyncFiletime") is byte[] { Length: 8 } time
                ? DateTimeOffset.FromFileTime(BitConverter.ToInt64(time))
                : null;
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    /// <summary>Drop this account's cached copy of each address (certutil -urlcache &lt;address&gt; delete). No elevation.</summary>
    public static void Clear(IEnumerable<string> urls)
    {
        foreach (string url in urls.Where(IsWebAddress).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var (code, output) = Certutil("-urlcache", url, "delete");
            AppLog.Info($"Cleared Windows' cached CRL for {url}: certutil exit {code}");
            AppLog.Debug(output);
        }
    }

    /// <summary>The elevated half: certutil -setreg chain\ChainCacheResyncFiletime @now, for every account, service and running program.</summary>
    public static OpResult ForceResync()
    {
        var (code, output) = Certutil("-setreg", @"chain\ChainCacheResyncFiletime", "@now");
        if (code != 0)
        {
            AppLog.Error("certutil -setreg chain\\ChainCacheResyncFiletime failed: " + output);
            return OpResult.Failure("Windows refused. certutil couldn't set the re-check time. See pal.log.");
        }
        AppLog.Info("Forced a revocation re-check (ChainCacheResyncFiletime set to now)");
        return OpResult.Success("Re-check forced: Windows fetches again anything it cached before now.");
    }

    /// <summary>Only an http(s) address goes on certutil's command line, so nothing a server sent can read as an option.</summary>
    private static bool IsWebAddress(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    /// <summary>Runs System32's certutil with each value as its own argument: never a shell.</summary>
    private static (int Code, string Output) Certutil(params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "certutil.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (string arg in args)
        {
            start.ArgumentList.Add(arg);
        }
        try
        {
            using var process = Process.Start(start);
            if (process is null)
            {
                return (-1, "certutil didn't start.");
            }
            var stderr = process.StandardError.ReadToEndAsync();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return (process.ExitCode, (output + " " + stderr.GetAwaiter().GetResult()).Trim());
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            return (-1, "certutil didn't start: " + e.Message);
        }
    }
}
