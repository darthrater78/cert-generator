using CertGeneratorPal.Core;
using Xunit;

namespace CertGeneratorPal.Tests;

/// <summary>What the elevated helper accepts for IIS / Remote Desktop binding, and how appcmd's output is read.</summary>
public class BindingTests
{
    private static readonly string[] Names = ["web.home.arpa", "intranet.home.arpa"];

    [Fact]
    public void AcceptsSiteWithSpacesAndCertificateHost()
    {
        BindingRules.Validate(new BindRequest { IisSite = "Default Web Site", Port = 443, Host = "" }, Names);
        BindingRules.Validate(new BindRequest { IisSite = "Intranet", Port = 8443, Host = "INTRANET.home.arpa" }, Names);
        BindingRules.Validate(new BindRequest { Rdp = true }, []);
    }

    [Fact]
    public void ComputerCertificatesBindOnlyToRemoteDesktop()
    {
        var both = new BindRequest { Rdp = true, IisSite = "Default Web Site", Port = 443 };
        Assert.Same(both, BindingRules.ForUseCase(UseCases.WebServer, both));
        var computer = BindingRules.ForUseCase(UseCases.Computer, both);
        Assert.NotNull(computer);
        Assert.True(computer.Rdp);
        Assert.Null(computer.IisSite);
        Assert.Null(BindingRules.ForUseCase(UseCases.Computer, new BindRequest { IisSite = "Default Web Site" }));
        Assert.Null(BindingRules.ForUseCase(UseCases.User, new BindRequest { Rdp = true }));
        Assert.Null(BindingRules.ForUseCase(UseCases.WebServer, new BindRequest()));
        Assert.Null(BindingRules.ForUseCase(UseCases.WebServer, null));
    }

    [Theory]
    [InlineData("Site'] /+bindings.[protocol='http")]
    [InlineData("a\"b")]
    [InlineData("a/b")]
    [InlineData("100%")]
    [InlineData(" Default Web Site")]
    [InlineData("")]
    public void RefusesSiteNamesAppcmdWouldParse(string site) =>
        Assert.Throws<PalException>(() => BindingRules.Validate(new BindRequest { IisSite = site }, Names));

    [Theory]
    [InlineData(0)]
    [InlineData(65536)]
    public void RefusesPortsOutOfRange(int port) =>
        Assert.Throws<PalException>(() => BindingRules.Validate(new BindRequest { IisSite = "Default Web Site", Port = port }, Names));

    [Theory]
    [InlineData("other.home.arpa")]  // not in the certificate
    [InlineData("*.home.arpa")]
    [InlineData("web.home.arpa:443")]
    [InlineData("web home.arpa")]
    public void RefusesHostsOutsideTheCertificate(string host) =>
        Assert.Throws<PalException>(() => BindingRules.Validate(new BindRequest { IisSite = "Default Web Site", Host = host }, Names));

    [Fact]
    public void BuildsIisBindingInformation()
    {
        Assert.Equal("*:443:", BindingRules.BindingInformation(443, ""));
        Assert.Equal("*:8443:web.home.arpa", BindingRules.BindingInformation(8443, "web.home.arpa"));
    }

    [Fact]
    public void ThumbprintsAreHexOnly()
    {
        Assert.Equal("ABCDEF0123456789ABCDEF0123456789ABCDEF01", BindingRules.ValidThumbprint("abcdef0123456789abcdef0123456789abcdef01"));
        Assert.Null(BindingRules.ValidThumbprint("abcdef0123456789abcdef0123456789abcdef0g"));
        Assert.Null(BindingRules.ValidThumbprint("abcd"));
        Assert.Null(BindingRules.ValidThumbprint(null));
    }

    [Fact]
    public void ReadsAppcmdConfigXml()
    {
        const string xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <appcmd>
                <SITE SITE.NAME="Default Web Site" SITE.ID="1" bindings="http/*:80:,https/*:443:" state="Started">
                    <site name="Default Web Site" id="1">
                        <bindings>
                            <binding protocol="http" bindingInformation="*:80:" />
                            <binding protocol="https" bindingInformation="*:443:" sslFlags="0" certificateHash="aabbccddeeff00112233445566778899aabbccdd" certificateStoreName="My" />
                            <binding protocol="https" bindingInformation="*:8443:web.home.arpa" sslFlags="1" />
                        </bindings>
                    </site>
                </SITE>
                <SITE SITE.NAME="Intranet" SITE.ID="2" bindings="http/*:8080:" state="Stopped" />
            </appcmd>
            """;
        var sites = BindingRules.ParseSites(xml);
        Assert.Equal(["Default Web Site", "Intranet"], sites.Select(s => s.Name));
        var https = sites[0].Bindings.Where(b => b.Protocol == "https").ToList();
        Assert.Equal(2, https.Count);
        Assert.Equal("AABBCCDDEEFF00112233445566778899AABBCCDD", https[0].CertificateHash);
        Assert.Equal((443, ""), (https[0].Port, https[0].Host));
        Assert.Equal((8443, "web.home.arpa"), (https[1].Port, https[1].Host));
        Assert.Null(https[1].CertificateHash);
        // without /config, the bindings attribute is used
        Assert.Equal(new IisBinding("http", "*:8080:"), Assert.Single(sites[1].Bindings));
    }

    [Fact]
    public void BadAppcmdOutputIsAPalError() =>
        Assert.Throws<PalException>(() => BindingRules.ParseSites("ERROR ( message:Access denied. )"));
}
