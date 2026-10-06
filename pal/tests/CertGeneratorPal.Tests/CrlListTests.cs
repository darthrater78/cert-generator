using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertGeneratorPal.Core;
using Xunit;

namespace CertGeneratorPal.Tests;

public class CrlListTests
{
    [Fact]
    public void ReadsIssuerDatesAndRevokedSerials()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test Root CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var revokedAt = new DateTimeOffset(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);
        var builder = new CertificateRevocationListBuilder();
        builder.AddEntry([0x00, 0xAB, 0xCD], revokedAt);
        builder.AddEntry([0x7F], revokedAt.AddHours(1));
        var next = DateTimeOffset.UtcNow.AddDays(7);
        byte[] der = builder.Build(ca, BigInteger.One, next, HashAlgorithmName.SHA256);

        var crl = CrlList.Parse(der);

        Assert.NotNull(crl);
        Assert.Equal("CN=Test Root CA", crl.Issuer);
        Assert.False(crl.Stale);
        Assert.Equal(next.ToUnixTimeSeconds(), crl.NextUpdate!.Value.ToUnixTimeSeconds());
        Assert.Equal([new RevokedSerial("ABCD", revokedAt), new RevokedSerial("7F", revokedAt.AddHours(1))], crl.Revoked);
    }

    [Fact]
    public void AnEmptyCrlHasNoEntriesAndRubbishIsNotACrl()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Empty CA", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        byte[] der = new CertificateRevocationListBuilder().Build(ca, BigInteger.One, DateTimeOffset.UtcNow.AddDays(-1), HashAlgorithmName.SHA256,
            thisUpdate: DateTimeOffset.UtcNow.AddDays(-8));

        var crl = CrlList.Parse(der);

        Assert.NotNull(crl);
        Assert.Empty(crl.Revoked);
        Assert.True(crl.Stale);
        Assert.Null(CrlList.Parse("<html>not found</html>"u8.ToArray()));
        Assert.Null(CrlList.Parse([]));
    }
}
