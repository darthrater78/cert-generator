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
            // "" = paired, but no CRL profile picked yet (the user must choose one). A pairing from
            // before profiles (no active.json) keeps the revocation type it was issuing with.
            state.CrlDp = active is not null ? active.CrlDp : state.CrlDps.FirstOrDefault() ?? "";
        }
        return state;
    }

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
internal sealed class PendingStore
{
    public sealed class Entry
    {
        public string KeyName { get; set; } = "";
        public string UseCase { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string? ReplaceThumbprint { get; set; }
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
