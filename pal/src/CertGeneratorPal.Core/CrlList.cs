using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace CertGeneratorPal.Core;

/// <summary>One revoked certificate on a CRL: its serial (upper-case hex, no leading zeros) and when it was revoked.</summary>
public sealed record RevokedSerial(string Serial, DateTimeOffset RevokedAt);

/// <summary>What a DER CRL says: who issued it, when, and which serials it revokes. The signature is not checked here.</summary>
public sealed record CrlList(string Issuer, DateTimeOffset ThisUpdate, DateTimeOffset? NextUpdate, IReadOnlyList<RevokedSerial> Revoked)
{
    public bool Stale => NextUpdate is { } next && next < DateTimeOffset.UtcNow;

    /// <summary>Is this copy older than <paramref name="live"/>, the CRL its address serves now?</summary>
    public bool IsBehind(CrlList live) => live is not null && live.ThisUpdate > ThisUpdate;

    /// <summary>The CRL, or null when the bytes aren't one.</summary>
    public static CrlList? Parse(byte[] der)
    {
        ArgumentNullException.ThrowIfNull(der);
        try
        {
            var tbs = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSequence();
            if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                tbs.ReadInteger();  // version
            }
            tbs.ReadSequence();  // signature algorithm
            string issuer = new X500DistinguishedName(tbs.ReadEncodedValue().Span).Name;
            DateTimeOffset thisUpdate = ReadTime(tbs);
            DateTimeOffset? nextUpdate = tbs.HasData && IsTime(tbs.PeekTag()) ? ReadTime(tbs) : null;
            var revoked = new List<RevokedSerial>();
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var list = tbs.ReadSequence();
                while (list.HasData)
                {
                    var entry = list.ReadSequence();
                    string serial = Convert.ToHexString(entry.ReadIntegerBytes().Span).TrimStart('0');
                    revoked.Add(new RevokedSerial(serial.Length == 0 ? "0" : serial, ReadTime(entry)));
                }
            }
            return new CrlList(issuer, thisUpdate, nextUpdate, revoked);
        }
        catch (Exception e) when (e is AsnContentException or System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    private static bool IsTime(Asn1Tag tag) => tag.HasSameClassAndValue(Asn1Tag.UtcTime) || tag.HasSameClassAndValue(Asn1Tag.GeneralizedTime);

    private static DateTimeOffset ReadTime(AsnReader reader) =>
        reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? reader.ReadUtcTime() : reader.ReadGeneralizedTime();
}
