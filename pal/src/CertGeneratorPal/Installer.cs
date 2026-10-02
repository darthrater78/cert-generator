using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>Puts certificates where Windows looks for them.</summary>
internal static class Installer
{
    /// <summary>
    /// Make sure the CA chain is trusted before installing a certificate from it: the root in
    /// Root and intermediates in Intermediate CAs, added only where missing. Machine scope
    /// writes LocalMachine (elevated); user scope uses LocalMachine if it is already there,
    /// otherwise CurrentUser (Windows asks the user to confirm a new root).
    /// Returns what was added.
    /// </summary>
    public static List<string> EnsureChain(IReadOnlyList<string> chainRootFirst, string rootSha256, bool machine)
    {
        if (!ChainCheck.RootMatches(chainRootFirst, rootSha256))
        {
            throw new PalException("The CA chain doesn't match the root this PC was paired with. Nothing was installed.");
        }
        var added = new List<string>();
        for (int i = 0; i < chainRootFirst.Count; i++)
        {
            using var cert = X509Certificate2.CreateFromPem(chainRootFirst[i]);
            var storeName = i == 0 ? StoreName.Root : StoreName.CertificateAuthority;
            if (Contains(StoreLocation.LocalMachine, storeName, cert) || (!machine && Contains(StoreLocation.CurrentUser, storeName, cert)))
            {
                continue;
            }
            var location = machine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
            using var store = new X509Store(storeName, location);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);
            added.Add($"{cert.GetNameInfo(X509NameType.SimpleName, false)} → {location}\\{storeName}");
            AppLog.Info($"Added {cert.Subject} to {location}\\{storeName}");
        }
        return added;
    }

    private static bool Contains(StoreLocation location, StoreName name, X509Certificate2 cert)
    {
        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, validOnly: false).Count > 0;
    }

    /// <summary>The CA's CRLs, into the Intermediate CAs store, so revocation works even offline. Newer replaces older.</summary>
    public static void AddCrls(IEnumerable<CrlEntry> crls, bool machine)
    {
        using var store = new X509Store(StoreName.CertificateAuthority, machine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        foreach (var crl in crls)
        {
            byte[] der;
            try
            {
                der = Convert.FromBase64String(crl.Crl);
            }
            catch (FormatException)
            {
                continue;
            }
            if (!NativeMethods.CertAddEncodedCRLToStore(store.StoreHandle, NativeMethods.X509AsnEncoding | NativeMethods.Pkcs7AsnEncoding,
                    der, (uint)der.Length, NativeMethods.CertStoreAddNewer, IntPtr.Zero))
            {
                int error = System.Runtime.InteropServices.Marshal.GetLastPInvokeError();
                if (error != unchecked((int)0x80092005))  // CRYPT_E_EXISTS: already have this one or newer
                {
                    AppLog.Error($"Couldn't add the CRL for {crl.CaName} (0x{error:X8})");
                }
            }
        }
    }

    /// <summary>Install an issued certificate with its CNG key into My. Returns the thumbprint.</summary>
    public static string InstallLeaf(string certPem, CngKey key, bool machine)
    {
        using var issued = X509Certificate2.CreateFromPem(certPem);
        using var ecdsa = new ECDsaCng(key);
        if (!ecdsa.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(issued.PublicKey.ExportSubjectPublicKeyInfo()))
        {
            throw new PalException("The server sent a certificate for a different key. Nothing was installed.");
        }
        using var withKey = issued.CopyWithPrivateKey(ecdsa);
        using var store = new X509Store(StoreName.My, machine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(withKey);
        AppLog.Info($"Installed {issued.Subject} ({issued.Thumbprint}) in {(machine ? "LocalMachine" : "CurrentUser")}\\My");
        return issued.Thumbprint;
    }

    /// <summary>Remove a certificate; its key too, when the Pal made it.</summary>
    public static void Remove(StoreLocation location, string storeName, string thumbprint)
    {
        using var store = new X509Store(storeName, location);
        store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
        foreach (var cert in store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false))
        {
            string? keyName = null;
            if (cert.HasPrivateKey)
            {
                try
                {
                    using var key = cert.GetECDsaPrivateKey();
                    keyName = (key as ECDsaCng)?.Key.KeyName;
                }
                catch (CryptographicException)
                {
                    // not a CNG ECDSA key: not one the Pal made
                }
            }
            store.Remove(cert);
            Keys.DeleteIfOurs(keyName, location == StoreLocation.LocalMachine);
            AppLog.Info($"Removed {cert.Subject} ({thumbprint}) from {location}\\{storeName}");
            cert.Dispose();
        }
    }
}
