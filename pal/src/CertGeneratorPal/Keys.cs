using System.Security.AccessControl;
using System.Security.Cryptography;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>
/// Every key the Pal makes is a persisted, non-exportable CNG key: in the TPM when the PC has
/// one, otherwise in the software key store. Private keys never leave this PC.
/// </summary>
internal static class Keys
{
    public const string Prefix = "CertGeneratorPal-";
    private const CngPropertyOptions DaclSecurityInformation = (CngPropertyOptions)4;
    private const string SecurityDescriptorProperty = "Security Descr";

    /// <summary>
    /// The device key (machine store, ECDSA P-256). Administrators and SYSTEM own it; signed-in
    /// users may use it, so the Pal can request "Me" certificates without elevating.
    /// </summary>
    public static CngKey CreateDeviceKey()
    {
        var sd = new RawSecurityDescriptor("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)");
        byte[] sdBytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(sdBytes, 0);
        var acl = new CngProperty(SecurityDescriptorProperty, sdBytes, DaclSecurityInformation);
        return Create(Prefix + "Device-" + Guid.NewGuid().ToString("N"), machine: true, extra: acl);
    }

    public static CngKey CreateLeafKey(bool machine) => Create(Prefix + Guid.NewGuid().ToString("N"), machine, extra: null);

    private static CngKey Create(string name, bool machine, CngProperty? extra)
    {
        foreach (var provider in new[] { CngProvider.MicrosoftPlatformCryptoProvider, CngProvider.MicrosoftSoftwareKeyStorageProvider })
        {
            foreach (bool withExtra in extra is null ? new[] { false } : new[] { true, false })
            {
                var parameters = new CngKeyCreationParameters
                {
                    Provider = provider,
                    ExportPolicy = CngExportPolicies.None,
                    KeyUsage = CngKeyUsages.Signing,
                    KeyCreationOptions = machine ? CngKeyCreationOptions.MachineKey : CngKeyCreationOptions.None,
                };
                if (withExtra)
                {
                    parameters.Parameters.Add(extra!.Value);
                }
                try
                {
                    var key = CngKey.Create(CngAlgorithm.ECDsaP256, name, parameters);
                    AppLog.Info($"Created {(machine ? "machine" : "user")} key in {provider.Provider}{(withExtra ? " with user access" : "")}");
                    return key;
                }
                catch (CryptographicException e)
                {
                    AppLog.Info($"{provider.Provider}{(withExtra ? " with ACL" : "")} couldn't make the key ({e.Message}); trying the next option");
                }
            }
        }
        throw new PalException("Windows couldn't create a key for this certificate. See pal.log for details.");
    }

    /// <summary>Where a key lives, as the server records it: "tpm" or "software".</summary>
    public static string Storage(CngKey key) => key.Provider == CngProvider.MicrosoftPlatformCryptoProvider ? "tpm" : "software";

    /// <summary>The same for a certificate in a store; null when it has no key here or this process may not read it.</summary>
    public static string? Storage(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        if (!cert.HasPrivateKey)
        {
            return null;
        }
        try
        {
            using var ecdsa = System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions.GetECDsaPrivateKey(cert) as ECDsaCng;
            return ecdsa is null ? null : Storage(ecdsa.Key);
        }
        catch (CryptographicException)
        {
            return null;  // a machine key, and the Pal isn't elevated
        }
    }

    /// <summary>Open a key the Pal made, from whichever provider holds it.</summary>
    public static CngKey Open(string name, bool machine)
    {
        var options = machine ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        try
        {
            return CngKey.Open(name, CngProvider.MicrosoftPlatformCryptoProvider, options);
        }
        catch (CryptographicException)
        {
            return CngKey.Open(name, CngProvider.MicrosoftSoftwareKeyStorageProvider, options);
        }
    }

    public static bool Exists(string name, bool machine)
    {
        var options = machine ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
        return CngKey.Exists(name, CngProvider.MicrosoftPlatformCryptoProvider, options)
            || CngKey.Exists(name, CngProvider.MicrosoftSoftwareKeyStorageProvider, options);
    }

    public static void DeleteIfOurs(string? name, bool machine)
    {
        if (name is null || !name.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return;
        }
        try
        {
            using var key = Open(name, machine);
            key.Delete();
        }
        catch (CryptographicException e)
        {
            AppLog.Error("Couldn't delete key " + name, e);
        }
    }

    /// <summary>A PEM certificate request for <paramref name="key"/>. The server reads only the key from it.</summary>
    public static string CsrPem(CngKey key)
    {
        using var ecdsa = new ECDsaCng(key);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest(
            "CN=" + LocalIdentity.Hostname, ecdsa, HashAlgorithmName.SHA256);
        return PemEncoding.WriteString("CERTIFICATE REQUEST", request.CreateSigningRequest());
    }

    public static byte[] SubjectPublicKeyInfo(CngKey key)
    {
        using var ecdsa = new ECDsaCng(key);
        return ecdsa.ExportSubjectPublicKeyInfo();
    }
}

/// <summary>Signs device API requests with the device key.</summary>
internal sealed class DeviceSigner : IDeviceSigner, IDisposable
{
    private readonly ECDsaCng _key;

    public DeviceSigner(DeviceState state)
    {
        DeviceId = state.DeviceId;
        try
        {
            _key = new ECDsaCng(Keys.Open(state.DeviceKeyName, machine: true));
        }
        catch (CryptographicException e)
        {
            throw new DeviceKeyUnavailableException(e);
        }
    }

    public string DeviceId { get; }

    public string KeyStorage => Keys.Storage(_key.Key);

    public byte[] Sign(byte[] data) => _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

    public byte[] SignP1363(byte[] data) => _key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    public void Dispose() => _key.Dispose();
}

/// <summary>The device key exists but this (unelevated) process may not use it: run the operation elevated instead.</summary>
internal sealed class DeviceKeyUnavailableException : Exception
{
    public DeviceKeyUnavailableException() { }

    public DeviceKeyUnavailableException(string message) : base(message) { }

    public DeviceKeyUnavailableException(string message, Exception inner) : base(message, inner) { }

    public DeviceKeyUnavailableException(Exception inner) : base("The device key can't be used from this account", inner) { }
}
