using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>How this Pal reaches its server: automatically (the LAN, else the relay), or the relay only
/// (Connect to remote: for testing, or a LAN that answers but shouldn't be used). For this session.</summary>
internal static class Connectivity
{
    public static PalRoute Route { get; set; } = PalRoute.Auto;
}
