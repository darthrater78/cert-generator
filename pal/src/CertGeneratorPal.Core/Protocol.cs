using System.Security.Cryptography;
using System.Text;

namespace CertGeneratorPal.Core;

/// <summary>
/// The wire format shared with the server (app/pal.py; docs/cert-generator-pal.md §2).
/// Every string built here must match the Python side byte for byte.
/// </summary>
public static class Protocol
{
    public const string PairingPrefix = "CGP1.";
    public const string EnrollProofLabel = "CGP1-ENROLL";
    public const string EnrolledMacLabel = "CGP1-ENROLLED";
    public const string RequestLabel = "CGP1-REQ";
    public const string ApiPrefix = "/api/pal/v1/";

    public static string B64Url(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] B64UrlDecode(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        foreach (char c in text)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_'))
            {
                throw new FormatException("Malformed base64url value");
            }
        }
        string padded = text.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - (padded.Length % 4)) % 4);
        return Convert.FromBase64String(padded);
    }

    public static string Sha256Hex(ReadOnlySpan<byte> data) =>
        Convert.ToHexStringLower(SHA256.HashData(data));

    private static byte[] Mac(byte[] key, string label, ReadOnlySpan<byte> body) =>
        HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(label + "\n" + Sha256Hex(body)));

    /// <summary>Proves to the server that this PC holds the pairing key, without sending it.</summary>
    public static string EnrollProof(byte[] key, ReadOnlySpan<byte> body) => B64Url(Mac(key, EnrollProofLabel, body));

    /// <summary>True when the server's reply was MACed with the pairing key, i.e. came from the server that made the code.</summary>
    public static bool VerifyEnrolledMac(byte[] key, ReadOnlySpan<byte> body, string? mac)
    {
        if (string.IsNullOrEmpty(mac))
        {
            return false;
        }
        byte[] given;
        try
        {
            given = B64UrlDecode(mac);
        }
        catch (FormatException)
        {
            return false;
        }
        return CryptographicOperations.FixedTimeEquals(given, Mac(key, EnrolledMacLabel, body));
    }

    /// <summary>What the device key signs for every request after pairing.</summary>
    public static byte[] RequestSigningString(string method, string path, string timestamp, string nonce, ReadOnlySpan<byte> body) =>
        Encoding.UTF8.GetBytes($"{RequestLabel}\n{method.ToUpperInvariant()}\n{path}\n{timestamp}\n{nonce}\n{Sha256Hex(body)}");

    public static string NewNonce() => B64Url(RandomNumberGenerator.GetBytes(16));
}
