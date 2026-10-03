using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertGeneratorPal.Core;
using Xunit;

namespace CertGeneratorPal.Tests;

/// <summary>The relay envelope against vectors made by the server (scripts/make_relay_vectors.py).</summary>
public sealed class RelayTests : IDisposable
{
    private readonly JsonElement _v;
    private readonly ECDsa _device = ECDsa.Create();
    private readonly ECDiffieHellman _relay = ECDiffieHellman.Create();
    private readonly ECDiffieHellman _oneTime = ECDiffieHellman.Create();

    public RelayTests()
    {
        _v = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "relay-vectors.json"))).RootElement;
        _device.ImportPkcs8PrivateKey(Bytes("device_private_pkcs8"), out _);
        _relay.ImportPkcs8PrivateKey(Bytes("relay_private_pkcs8"), out _);
        _oneTime.ImportPkcs8PrivateKey(Bytes("one_time_private_pkcs8"), out _);
    }

    public void Dispose()
    {
        _device.Dispose();
        _relay.Dispose();
        _oneTime.Dispose();
    }

    private byte[] Bytes(string name) => Convert.FromBase64String(_v.GetProperty(name).GetString()!);

    private string Str(string name) => _v.GetProperty(name).GetString()!;

    private string Envelope(string name) => _v.GetProperty("envelope").GetProperty(name).GetString()!;

    private Relay.SealedRequest Seal() => Relay.SealRequest(Str("device_id"), Relay.PublicPoint(_relay), Bytes("inner_request"),
        _v.GetProperty("timestamp").GetInt64(), Str("nonce"),
        data => _device.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
        _oneTime, Protocol.B64UrlDecode(Str("iv_request")));

    [Fact]
    public void SealsTheSameBytesAsTheServer()
    {
        using var doc = JsonDocument.Parse(Seal().Json);
        var mine = doc.RootElement;
        foreach (string field in new[] { "d", "n", "e", "i", "c" })
        {
            Assert.Equal(Envelope(field), mine.GetProperty(field).GetString());
        }
        Assert.Equal(_v.GetProperty("timestamp").GetInt64(), mine.GetProperty("t").GetInt64());
        Assert.Equal(1, mine.GetProperty("v").GetInt32());
    }

    [Fact]
    public void ServerSignatureVerifiesTheWayTheWorkerChecksIt()
    {
        byte[] message = Relay.SigningString(Str("device_id"), _v.GetProperty("timestamp").GetInt64(), Str("nonce"),
            Envelope("e"), Envelope("i"), Envelope("c"));
        Assert.True(_device.VerifyData(message, Protocol.B64UrlDecode(Envelope("s")), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void OpensTheServersReply()
    {
        byte[] reply = Encoding.UTF8.GetBytes(_v.GetProperty("reply").GetRawText());
        Assert.Equal(Bytes("inner_reply"), Relay.OpenReply(Seal(), Str("device_id"), reply));
    }

    [Fact]
    public void RelayKeyOpensTheRequest() =>
        Assert.Equal(Bytes("inner_request"), Relay.OpenRequestForTest(_relay, Str("device_id"), _v.GetProperty("timestamp").GetInt64(),
            Str("nonce"), Envelope("e"), Envelope("i"), Envelope("c")));

    [Fact]
    public void RefusesATamperedOrForeignReply()
    {
        var sealedRequest = Seal();
        string reply = _v.GetProperty("reply").GetRawText();
        string tampered = reply.Replace(_v.GetProperty("reply").GetProperty("c").GetString()![..4], "AAAA", StringComparison.Ordinal);
        Assert.Throws<PalException>(() => Relay.OpenReply(sealedRequest, Str("device_id"), Encoding.UTF8.GetBytes(tampered)));
        Assert.Throws<PalException>(() => Relay.OpenReply(sealedRequest, "f" + Str("device_id")[1..], Encoding.UTF8.GetBytes(reply)));
        var other = Relay.SealRequest(Str("device_id"), Relay.PublicPoint(_relay), Bytes("inner_request"), 1, Str("nonce"),
            data => _device.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.Throws<PalException>(() => Relay.OpenReply(other, Str("device_id"), Encoding.UTF8.GetBytes(reply)));
    }

    [Fact]
    public void FreshSealsRoundTrip()
    {
        var request = Relay.SealRequest(Str("device_id"), Relay.PublicPoint(_relay), [1, 2, 3], 42, Protocol.NewNonce(),
            data => _device.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using var doc = JsonDocument.Parse(request.Json);
        var env = doc.RootElement;
        Assert.Equal([1, 2, 3], Relay.OpenRequestForTest(_relay, Str("device_id"), 42, request.Nonce,
            env.GetProperty("e").GetString()!, env.GetProperty("i").GetString()!, env.GetProperty("c").GetString()!));
    }
}
