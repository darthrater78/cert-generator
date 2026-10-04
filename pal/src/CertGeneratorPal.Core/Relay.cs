using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace CertGeneratorPal.Core;

/// <summary>
/// The remote relay's sealed envelope (docs/cert-generator-pal.md §8; app/relay.py), the PC's side:
/// seal a whole signed LAN request to the server's relay key, open the server's sealed reply.
/// A one-time P-256 key per request does the key agreement (the device key only signs).
/// </summary>
public static class Relay
{
    public const int Version = 1;
    private static readonly byte[] Salt = Encoding.ASCII.GetBytes("CGP1-RELAY");

    /// <summary>A sealed request: its JSON, and the key that opens its reply.</summary>
    public sealed record SealedRequest(byte[] Json, byte[] ReplyKey, string Nonce);

    public static byte[] SigningString(string deviceId, long timestamp, string nonce, string epk, string iv, string ciphertext) =>
        Encoding.UTF8.GetBytes(string.Join('\n', "CGP1-RELAY", deviceId, timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            nonce, epk, iv, ciphertext));

    public static byte[] RequestAad(string deviceId, long timestamp, string nonce) =>
        Encoding.UTF8.GetBytes($"CGP1-RELAY-REQ\n{deviceId}\n{timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture)}\n{nonce}");

    public static byte[] ReplyAad(string deviceId, string nonce) => Encoding.UTF8.GetBytes($"CGP1-RELAY-REP\n{deviceId}\n{nonce}");

    /// <param name="signP1363">Signs with the device key: ECDSA P-256 / SHA-256, raw r‖s (what WebCrypto verifies).</param>
    /// <param name="oneTime">The one-time key; a new one unless a test supplies it.</param>
    public static SealedRequest SealRequest(string deviceId, byte[] relayPublic, byte[] inner, long timestamp, string nonce,
        Func<byte[], byte[]> signP1363, ECDiffieHellman? oneTime = null, byte[]? iv = null)
    {
        ArgumentNullException.ThrowIfNull(signP1363);
        using var owned = oneTime is null ? ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256) : null;
        var key = oneTime ?? owned!;
        byte[] epk = PublicPoint(key);
        var (kReq, kRep) = Keys(key, epk, relayPublic);
        iv ??= RandomNumberGenerator.GetBytes(12);
        byte[] sealedInner = Encrypt(kReq, iv, inner, RequestAad(deviceId, timestamp, nonce));
        CryptographicOperations.ZeroMemory(kReq);
        string e = Protocol.B64Url(epk), i = Protocol.B64Url(iv), c = Protocol.B64Url(sealedInner);
        byte[] signature = signP1363(SigningString(deviceId, timestamp, nonce, e, i, c));
        if (signature.Length != 64)
        {
            throw new PalException("Relay signature must be raw r‖s.");
        }
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["v"] = Version, ["d"] = deviceId, ["t"] = timestamp, ["n"] = nonce,
            ["e"] = e, ["i"] = i, ["c"] = c, ["s"] = Protocol.B64Url(signature),
        });
        return new SealedRequest(json, kRep, nonce);
    }

    /// <summary>The inner reply, only if it was sealed by the server for this very request.</summary>
    public static byte[] OpenReply(SealedRequest request, string deviceId, ReadOnlySpan<byte> replyJson)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            using var doc = JsonDocument.Parse(replyJson.ToArray());
            var root = doc.RootElement;
            if (root.GetProperty("v").GetInt32() != Version || root.GetProperty("n").GetString() != request.Nonce)
            {
                throw new PalException("Relay reply is for another request.");
            }
            byte[] iv = Protocol.B64UrlDecode(root.GetProperty("i").GetString() ?? "");
            byte[] sealedInner = Protocol.B64UrlDecode(root.GetProperty("c").GetString() ?? "");
            return Decrypt(request.ReplyKey, iv, sealedInner, ReplyAad(deviceId, request.Nonce));
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException
            or AuthenticationTagMismatchException or ArgumentException)
        {
            throw new PalException("The relay's reply didn't come from your server.", e);
        }
    }

    /// <summary>The request's inner bytes opened with the relay's private key: the server's side, for tests.</summary>
    public static byte[] OpenRequestForTest(ECDiffieHellman relayKey, string deviceId, long timestamp, string nonce, string epk, string iv, string ciphertext)
    {
        ArgumentNullException.ThrowIfNull(relayKey);
        byte[] epkRaw = Protocol.B64UrlDecode(epk);
        using var peer = FromPoint(epkRaw);
        byte[] okm = Hkdf(relayKey.DeriveRawSecretAgreement(peer.PublicKey), epkRaw, PublicPoint(relayKey));
        return Decrypt(okm[..32], Protocol.B64UrlDecode(iv), Protocol.B64UrlDecode(ciphertext), RequestAad(deviceId, timestamp, nonce));
    }

    public static byte[] PublicPoint(ECDiffieHellman key)
    {
        ArgumentNullException.ThrowIfNull(key);
        var q = key.ExportParameters(false).Q;
        return [0x04, .. q.X!, .. q.Y!];
    }

    private static ECDiffieHellman FromPoint(byte[] raw)
    {
        if (raw.Length != 65 || raw[0] != 0x04)
        {
            throw new PalException("Bad relay key.");
        }
        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = raw[1..33], Y = raw[33..65] },
        });
    }

    private static (byte[] Req, byte[] Rep) Keys(ECDiffieHellman oneTime, byte[] epk, byte[] relayPublic)
    {
        using var relay = FromPoint(relayPublic);
        byte[] okm = Hkdf(oneTime.DeriveRawSecretAgreement(relay.PublicKey), epk, relayPublic);
        return (okm[..32], okm[32..]);
    }

    private static byte[] Hkdf(byte[] shared, byte[] epk, byte[] relayPublic)
    {
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, 64, Salt, [.. epk, .. relayPublic]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(shared);
        }
    }

    private static byte[] Encrypt(byte[] key, byte[] iv, byte[] plain, byte[] aad)
    {
        using var aes = new AesGcm(key, 16);
        byte[] output = new byte[plain.Length + 16];
        aes.Encrypt(iv, plain, output.AsSpan(0, plain.Length), output.AsSpan(plain.Length), aad);
        return output;
    }

    private static byte[] Decrypt(byte[] key, byte[] iv, byte[] sealedData, byte[] aad)
    {
        if (iv.Length != 12 || sealedData.Length < 16)
        {
            throw new PalException("Bad relay envelope.");
        }
        using var aes = new AesGcm(key, 16);
        byte[] plain = new byte[sealedData.Length - 16];
        aes.Decrypt(iv, sealedData.AsSpan(0, plain.Length), sealedData.AsSpan(plain.Length), plain, aad);
        return plain;
    }
}
