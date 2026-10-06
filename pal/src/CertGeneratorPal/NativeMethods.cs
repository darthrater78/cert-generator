using System.Runtime.InteropServices;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace CertGeneratorPal;

internal static partial class NativeMethods
{
    public const uint X509AsnEncoding = 0x00000001;
    public const uint Pkcs7AsnEncoding = 0x00010000;
    public const uint CertStoreAddNewer = 6;
    public const uint CertKeyProvInfoPropId = 2;
    public const int NameDisplay = 3;
    public const int NameUserPrincipal = 8;

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CertAddEncodedCRLToStore(IntPtr hCertStore, uint dwCertEncodingType, byte[] pbCrlEncoded,
        uint cbCrlEncoded, uint dwAddDisposition, IntPtr ppCrlContext);

    [LibraryImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);

    [LibraryImport("cryptnet.dll", EntryPoint = "CryptRetrieveObjectByUrlW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CryptRetrieveObjectByUrl(string pszUrl, IntPtr pszObjectOid, uint dwRetrievalFlags, uint dwTimeout,
        out IntPtr ppvObject, IntPtr hAsyncRetrieve, IntPtr pCredentials, IntPtr pvVerify, IntPtr pAuxInfo);

    [LibraryImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CertFreeCRLContext(IntPtr pCrlContext);

    [LibraryImport("secur32.dll", EntryPoint = "GetUserNameExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetUserNameEx(int nameFormat, [Out] char[] lpNameBuffer, ref uint nSize);
}
