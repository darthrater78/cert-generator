using System.Text.Json;

namespace CertGeneratorPal.Core;

/// <summary>The one string an admin copies from cert-generator's "Add a PC" to this PC.</summary>
public sealed record PairingCode(Uri Server, string CodeId, byte[] Key, string RootSha256)
{
    public static PairingCode Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        string trimmed = string.Concat(text.Where(c => !char.IsWhiteSpace(c)));
        if (!trimmed.StartsWith(Protocol.PairingPrefix, StringComparison.Ordinal))
        {
            throw new PalException("That isn't a Cert Generator Pal pairing code. It starts with CGP1.");
        }
        JsonElement payload;
        try
        {
            using var doc = JsonDocument.Parse(Protocol.B64UrlDecode(trimmed[Protocol.PairingPrefix.Length..]));
            payload = doc.RootElement.Clone();
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            throw new PalException("The pairing code is damaged. Copy it again from Cert Generator.", e);
        }
        if (payload.ValueKind != JsonValueKind.Object || !payload.TryGetProperty("v", out var v) || v.ValueKind != JsonValueKind.Number || v.GetInt32() != 1)
        {
            throw new PalException("This pairing code is from a newer Cert Generator. Update Cert Generator Pal.");
        }
        string server = Field(payload, "u");
        string codeId = Field(payload, "i");
        string root = Field(payload, "r");
        byte[] key = Protocol.B64UrlDecode(Field(payload, "k"));
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new PalException("The pairing code has an invalid server address.");
        }
        if (key.Length != 32 || codeId.Length is < 16 or > 64 || root.Length != 64 || !root.All(Uri.IsHexDigit))
        {
            throw new PalException("The pairing code is damaged. Copy it again from Cert Generator.");
        }
        return new PairingCode(uri, codeId, key, root.ToLowerInvariant());
    }

    private static string Field(JsonElement payload, string name) =>
        payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : throw new PalException("The pairing code is damaged. Copy it again from Cert Generator.");
}
