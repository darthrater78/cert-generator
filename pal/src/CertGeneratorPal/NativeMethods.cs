using System.Runtime.InteropServices;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace CertGeneratorPal;

internal static partial class NativeMethods
{
    public const uint X509AsnEncoding = 0x00000001;
    public const uint Pkcs7AsnEncoding = 0x00010000;
    public const uint CertStoreAddNewer = 6;
    public const int NameDisplay = 3;
    public const int NameUserPrincipal = 8;

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CertAddEncodedCRLToStore(IntPtr hCertStore, uint dwCertEncodingType, byte[] pbCrlEncoded,
        uint cbCrlEncoded, uint dwAddDisposition, IntPtr ppCrlContext);

    [LibraryImport("secur32.dll", EntryPoint = "GetUserNameExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetUserNameEx(int nameFormat, [Out] char[] lpNameBuffer, ref uint nSize);
}
