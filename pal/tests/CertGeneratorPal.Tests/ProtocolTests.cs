using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertGeneratorPal.Core;
using Xunit;

namespace CertGeneratorPal.Tests;

/// <summary>Vectors produced by the Python server (app/pal.py): both sides must agree byte for byte.</summary>
public class ProtocolTests
{
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    private static readonly byte[] Body = Encoding.UTF8.GetBytes("{\"code_id\":\"abc\",\"ts\":1}");

    private const string PythonCode =
        "CGP1.eyJ2IjoxLCJ1IjoiaHR0cDovLzEwLjAuMC4yNTI6NTAwMCIsImkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImsiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4IiwiciI6ImFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWIifQ";

    [Fact]
    public void EnrollProofMatchesServer() =>
        Assert.Equal("FINKfpdQTVNbwgFsMJrrfq8NAvRWPULEzrghUsZ_nRE", Protocol.EnrollProof(Key, Body));

    [Fact]
    public void EnrolledMacMatchesServer()
    {
        Assert.True(Protocol.VerifyEnrolledMac(Key, Body, "4GeRY9KmKn2PwXSiRttseWGGetzvC49saCX679DD6Gw"));
        Assert.False(Protocol.VerifyEnrolledMac(Key, Body, "5GeRY9KmKn2PwXSiRttseWGGetzvC49saCX679DD6Gw"));
        Assert.False(Protocol.VerifyEnrolledMac(Key, Body, null));
        Assert.False(Protocol.VerifyEnrolledMac(Key, Body, "not base64!"));
        Assert.False(Protocol.VerifyEnrolledMac(Key, [.. Body, (byte)' '], "4GeRY9KmKn2PwXSiRttseWGGetzvC49saCX679DD6Gw"));
    }

    [Fact]
    public void RequestSigningStringMatchesServer()
    {
        byte[] s = Protocol.RequestSigningString("post", "/api/pal/v1/requests", "1700000000", "AAAAAAAAAAAAAAAAAAAAAA", Encoding.UTF8.GetBytes("{\"a\":1}"));
        Assert.Equal("CGP1-REQ\nPOST\n/api/pal/v1/requests\n1700000000\nAAAAAAAAAAAAAAAAAAAAAA\n" +
                     "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862", Encoding.UTF8.GetString(s));
    }

    [Fact]
    public void ParsesServerPairingCode()
    {
        var code = PairingCode.Parse("  " + PythonCode[..40] + "\r\n" + PythonCode[40..] + " ");  // pasted with line breaks
        Assert.Equal(new Uri("http://10.0.0.252:5000"), code.Server);
        Assert.Equal("0123456789abcdef0123456789abcdef", code.CodeId);
        Assert.Equal(Key, code.Key);
        Assert.Equal(new string('a', 0) + string.Concat(Enumerable.Repeat("ab", 32)), code.RootSha256);
    }

    [Theory]
    [InlineData("hello")]
    [InlineData("CGP1.")]
    [InlineData("CGP1.!!!!")]
    [InlineData("CGP1.eyJ2IjoyfQ")]  // {"v":2}
    public void RejectsBadPairingCodes(string text) => Assert.Throws<PalException>(() => PairingCode.Parse(text));

    [Fact]
    public void B64UrlRoundTrips()
    {
        byte[] data = RandomNumberGenerator.GetBytes(37);
        Assert.Equal(data, Protocol.B64UrlDecode(Protocol.B64Url(data)));
        Assert.DoesNotContain('=', Protocol.B64Url(data));
    }

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.0.1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("169.254.1.1", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("100.64.0.1", true)]
    [InlineData("100.127.255.254", true)]
    [InlineData("100.63.255.255", false)]
    [InlineData("100.128.0.1", false)]
    [InlineData("::ffff:100.100.1.1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("2001:db8::1", false)]
    [InlineData("::ffff:10.0.0.1", true)]
    [InlineData("::ffff:8.8.8.8", false)]
    public void LanAddressesMatchServer(string address, bool expected) =>
        Assert.Equal(expected, LanAddress.IsPrivate(IPAddress.Parse(address)));

    [Fact]
    public void RootPinChecksFirstCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Test Root", key, HashAlgorithmName.SHA256);
        using var root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        string pem = root.ExportCertificatePem();
        string pin = Protocol.Sha256Hex(root.RawData);
        Assert.True(ChainCheck.RootMatches([pem], pin));
        Assert.True(ChainCheck.RootMatches([pem], pin.ToUpperInvariant()));
        Assert.False(ChainCheck.RootMatches([pem], new string('0', 64)));
        Assert.False(ChainCheck.RootMatches([], pin));
        Assert.False(ChainCheck.RootMatches(["garbage"], pin));
    }
}
