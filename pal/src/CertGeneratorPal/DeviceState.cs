using System.Text.Json;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>
/// One pairing ("profile source"): ProgramData\CertGeneratorPal\profiles\&lt;device id&gt;.json. A PC
/// can hold several, from different codes. Each allowed revocation type of a pairing is a
/// profile; exactly one (pairing + type) is active, recorded in active.json. No secrets here:
/// the device keys are in CNG.
/// </summary>
internal sealed class DeviceState
{
    public string Server { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string DeviceKeyName { get; set; } = "";
    public string RootSha256 { get; set; } = "";
    public string CaName { get; set; } = "";
    public string Label { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public List<string> Chain { get; set; } = [];
    public List<string> CrlDps { get; set; } = [];
    public DateTimeOffset ConnectedAt { get; set; }

    /// <summary>The server's remote relay, learnt at pairing (MACed with the pairing key) or later over the LAN.</summary>
    public RelayInfo? Relay { get; set; }

    /// <summary>The revocation type this profile issues with (set on the active one when loaded); "" until the user picks one.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string CrlDp { get; set; } = "";

    public Uri ServerUri => new(Server);

    private sealed class ActiveProfile
    {
        public string DeviceId { get; set; } = "";
        public string CrlDp { get; set; } = "";
    }

    private static string ProfilesDir => Path.Combine(Paths.MachineDir, "profiles");
    private static string ActiveFile => Path.Combine(Paths.MachineDir, "active.json");
    private string ProfileFile => Path.Combine(ProfilesDir, DeviceId + ".json");

    /// <summary>Every pairing on this PC (including one from before profiles: device.json).</summary>
    public static List<DeviceState> LoadAll()
    {
        var all = new List<DeviceState>();
        try
        {
            if (Directory.Exists(ProfilesDir))
            {
                all.AddRange(Directory.GetFiles(ProfilesDir, "*.json").Select(Read).OfType<DeviceState>());
            }
            if (File.Exists(Paths.DeviceFile) && Read(Paths.DeviceFile) is { } legacy && all.All(p => p.DeviceId != legacy.DeviceId))
            {
                all.Add(legacy);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't list profiles", e);
        }
        return all.OrderBy(p => p.ConnectedAt).ToList();
    }

    /// <summary>The active profile, or null when none is.</summary>
    public static DeviceState? Load()
    {
        var all = LoadAll();
        ActiveProfile? active = null;
        try
        {
            if (File.Exists(ActiveFile))
            {
                active = JsonSerializer.Deserialize<ActiveProfile>(File.ReadAllBytes(ActiveFile), Json.Options);
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't read active.json", e);
        }
        var state = active is null
            ? (File.Exists(Paths.DeviceFile) ? all.FirstOrDefault(p => p.DeviceId == Read(Paths.DeviceFile)?.DeviceId) : null)  // before profiles
            : all.FirstOrDefault(p => p.DeviceId == active.DeviceId);
        if (state is not null)
        {
            // A relay learnt over the LAN after pairing is kept per user (the profile is written only elevated).
            if (ReadRelayCache(state.DeviceId) is { } cached)
            {
                state.Relay = cached;
            }
            // "" = paired, but no CRL profile picked yet (the user must choose one). A pairing from
            // before profiles (no active.json) keeps the revocation type it was issuing with.
            state.CrlDp = active is not null ? active.CrlDp : state.CrlDps.FirstOrDefault() ?? "";
        }
        return state;
    }

    private static string RelayCacheFile(string deviceId) => Path.Combine(Paths.UserDir, "relay-" + deviceId + ".json");

    private static RelayInfo? ReadRelayCache(string deviceId)
    {
        try
        {
            string path = RelayCacheFile(deviceId);
            return File.Exists(path) && JsonSerializer.Deserialize<RelayInfo>(File.ReadAllBytes(path), Json.Options) is { IsUsable: true } relay
                ? relay : null;
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Keep the relay details the server sent over the LAN (never ones that arrived through the relay itself).</summary>
    public void RememberRelay(DeviceInfo device)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (device.ArrivedVia != PalRoute.Lan || device.Relay is not { IsUsable: true } relay
            || (Relay?.Url == relay.Url && Relay?.PublicKey == relay.PublicKey))
        {
            return;
        }
        Relay = relay;
        try
        {
            AtomicWrite(RelayCacheFile(DeviceId), JsonSerializer.SerializeToUtf8Bytes(relay, Json.Options));
            AppLog.Info($"Remote relay: {relay.Url}");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't save the relay details", e);
        }
    }

    /// <summary>A client for this pairing: the LAN, falling back to the relay (or the route <see cref="Connectivity.Route"/> forces).</summary>
    public PalClient Client(PalRoute? route = null) => new(ServerUri, RootSha256, Relay, route ?? Connectivity.Route);

    private static DeviceState? Read(string path)
    {
        try
        {
            var state = JsonSerializer.Deserialize<DeviceState>(File.ReadAllBytes(path), Json.Options);
            return state is not null && state.DeviceId.Length == 32 && Uri.IsWellFormedUriString(state.Server, UriKind.Absolute) ? state : null;
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't read " + path, e);
            return null;
        }
    }

    /// <summary>Elevated only: writes into the protected machine folder (and retires device.json).</summary>
    public void Save()
    {
        Paths.EnsureMachineDir();
        Directory.CreateDirectory(ProfilesDir);
        AtomicWrite(ProfileFile, JsonSerializer.SerializeToUtf8Bytes(this, Json.Options));
        if (File.Exists(Paths.DeviceFile) && Read(Paths.DeviceFile)?.DeviceId == DeviceId)
        {
            File.Delete(Paths.DeviceFile);
        }
    }

    /// <summary>Elevated only: make this pairing, with this revocation type, the active profile.</summary>
    public void Activate(string crlDp)
    {
        Save();
        CrlDp = crlDp;
        AtomicWrite(ActiveFile, JsonSerializer.SerializeToUtf8Bytes(new ActiveProfile { DeviceId = DeviceId, CrlDp = crlDp }, Json.Options));
    }

    public static void ClearActive()
    {
        if (File.Exists(ActiveFile))
        {
            File.Delete(ActiveFile);
        }
    }

    /// <summary>Elevated only: forget this pairing.</summary>
    public void DeleteProfile()
    {
        foreach (string file in new[] { ProfileFile, Paths.DeviceFile })
        {
            if (File.Exists(file) && Read(file)?.DeviceId == DeviceId)
            {
                File.Delete(file);
            }
        }
    }

    public static void AtomicWrite(string path, byte[] data)
    {
        string temp = path + ".tmp";
        File.WriteAllBytes(temp, data);
        File.Move(temp, path, overwrite: true);
    }
}

/// <summary>Requests waiting for approval, with the name of the key made for each. Machine ones in ProgramData, "Me" ones per user.</summary>
/// <summary>
/// Certificates removed on this PC that the server hasn't been told to revoke yet, per pairing.
/// Kept in the user's folder so a removal made while the server (and the relay) can't be reached
/// is still revoked at the next check-in. The server revokes only this PC's own certificates,
/// so a made-up entry here does nothing.
/// </summary>
internal static class PendingRevokes
{
    private static string FilePath => Path.Combine(Paths.UserDir, "revokes.json");

    private static Dictionary<string, List<string>> LoadAll()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<Dictionary<string, List<string>>>(File.ReadAllBytes(FilePath), Json.Options) ?? []
                : [];
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't read " + FilePath, e);
            return [];
        }
    }

    public static void Add(string deviceId, IEnumerable<string> serials)
    {
        var all = LoadAll();
        all[deviceId] = [.. all.GetValueOrDefault(deviceId, []).Concat(serials).Distinct(StringComparer.OrdinalIgnoreCase)];
        Save(all);
    }

    private static void Save(Dictionary<string, List<string>> all)
    {
        try
        {
            File.WriteAllBytes(FilePath, JsonSerializer.SerializeToUtf8Bytes(all, Json.Options));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't write " + FilePath, e);
        }
    }

    /// <summary>
    /// Send what is waiting for this pairing, over whichever route the client uses (the LAN, or the
    /// relay). True when nothing is left waiting; false keeps it for the next check-in.
    /// </summary>
    public static async Task<bool> FlushAsync(PalClient client, IDeviceSigner signer, string deviceId)
    {
        var all = LoadAll();
        if (all.GetValueOrDefault(deviceId) is not { Count: > 0 } waiting)
        {
            return true;
        }
        try
        {
            var done = await client.RevokeAsync(signer, waiting).ConfigureAwait(false);
            AppLog.Info($"Told the server about {waiting.Count} removed certificate(s): {done.Count} revoked");
            all.Remove(deviceId);
            Save(all);
            return true;
        }
        catch (Exception e) when (e is PalException or HttpRequestException or TaskCanceledException)
        {
            AppLog.Error($"Couldn't tell the server about {waiting.Count} removed certificate(s); it will be tried again", e);
            return false;
        }
    }
}

/// <summary>
/// What the server last said about each certificate on this PC, per pairing, so the Pal can tell
/// the user when the server did something since: a certificate that was valid and is now revoked.
/// </summary>
internal static class SeenStatus
{
    private static string FilePath => Path.Combine(Paths.UserDir, "seen.json");

    private static Dictionary<string, Dictionary<string, string>> LoadAll()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<Dictionary<string, Dictionary<string, string>>>(File.ReadAllBytes(FilePath), Json.Options) ?? []
                : [];
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't read " + FilePath, e);
            return [];
        }
    }

    private static void Save(Dictionary<string, Dictionary<string, string>> all)
    {
        try
        {
            File.WriteAllBytes(FilePath, JsonSerializer.SerializeToUtf8Bytes(all, Json.Options));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't write " + FilePath, e);
        }
    }

    /// <summary>Record the server's current answers; returns the serials that were not revoked last time and are now.</summary>
    public static HashSet<string> Update(string deviceId, IReadOnlyDictionary<string, string> now)
    {
        var all = LoadAll();
        var before = all.GetValueOrDefault(deviceId, []);
        var newlyRevoked = now.Where(kv => kv.Value == "revoked" && before.TryGetValue(kv.Key, out var was) && was != "revoked")
            .Select(kv => kv.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        all[deviceId] = new Dictionary<string, string>(now, StringComparer.OrdinalIgnoreCase);
        Save(all);
        return newlyRevoked;
    }

    /// <summary>A revocation this PC asked for itself is not news.</summary>
    public static void MarkRevoked(string deviceId, IEnumerable<string> serials)
    {
        var all = LoadAll();
        var seen = all.GetValueOrDefault(deviceId, []);
        foreach (string serial in serials)
        {
            seen[serial] = "revoked";
        }
        all[deviceId] = seen;
        Save(all);
    }
}

internal sealed class PendingStore
{
    public sealed class Entry
    {
        public string KeyName { get; set; } = "";
        public string UseCase { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string? ReplaceThumbprint { get; set; }

        /// <summary>Where to use the certificate once the admin approves it (web server only).</summary>
        public BindRequest? Bind { get; set; }
    }

    private readonly string _path;
    private readonly bool _machine;

    public Dictionary<int, Entry> Items { get; private set; } = [];

    private PendingStore(string path, bool machine)
    {
        _path = path;
        _machine = machine;
    }

    public static PendingStore Open(bool machine)
    {
        var store = new PendingStore(machine ? Paths.MachinePendingFile : Paths.UserPendingFile, machine);
        try
        {
            if (File.Exists(store._path))
            {
                store.Items = JsonSerializer.Deserialize<Dictionary<int, Entry>>(File.ReadAllBytes(store._path), Json.Options) ?? [];
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't read " + store._path, e);
        }
        return store;
    }

    public void Save()
    {
        if (_machine)
        {
            Paths.EnsureMachineDir();
        }
        DeviceState.AtomicWrite(_path, JsonSerializer.SerializeToUtf8Bytes(Items, Json.Options));
    }
}

/// <summary>
/// Binds the admin has yet to approve (the computer's folder, written elevated): the server's
/// bind id → which certificate and which role, applied by Check again once it is approved.
/// </summary>
internal sealed class PendingBinds
{
    public sealed class Entry
    {
        public string DeviceId { get; set; } = "";
        public string Thumbprint { get; set; } = "";
        public string Target { get; set; } = "";

        /// <summary>That one role's part of what was asked (an IIS site's name, port and host, say).</summary>
        public BindRequest Part { get; set; } = new();
    }

    public Dictionary<int, Entry> Items { get; private set; } = [];

    public static PendingBinds Open()
    {
        var store = new PendingBinds();
        try
        {
            if (File.Exists(Paths.PendingBindsFile))
            {
                store.Items = JsonSerializer.Deserialize<Dictionary<int, Entry>>(File.ReadAllBytes(Paths.PendingBindsFile), Json.Options) ?? [];
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't read " + Paths.PendingBindsFile, e);
        }
        return store;
    }

    public void Save()
    {
        Paths.EnsureMachineDir();
        DeviceState.AtomicWrite(Paths.PendingBindsFile, JsonSerializer.SerializeToUtf8Bytes(Items, Json.Options));
    }
}

/// <summary>
/// The roles the Pal bound that Windows only reveals to an administrator (RD Gateway, the RD
/// Connection Broker's two certificates): role → thumbprint, written by the elevated helper so
/// the unelevated list can still say what uses a certificate. One certificate per role.
/// </summary>
internal static class BindLog
{
    public static Dictionary<string, string> Read()
    {
        try
        {
            if (File.Exists(Paths.BindLogFile))
            {
                return JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllBytes(Paths.BindLogFile), Json.Options) ?? [];
            }
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
            AppLog.Error("Couldn't read " + Paths.BindLogFile, e);
        }
        return [];
    }

    /// <summary>Elevated only: <paramref name="role"/> now uses this certificate.</summary>
    public static void Set(string role, string thumbprint)
    {
        var roles = Read();
        roles[role] = thumbprint.ToUpperInvariant();
        Paths.EnsureMachineDir();
        DeviceState.AtomicWrite(Paths.BindLogFile, JsonSerializer.SerializeToUtf8Bytes(roles, Json.Options));
    }
}
