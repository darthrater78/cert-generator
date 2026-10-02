using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>An operation's outcome, passed back from the elevated helper as JSON.</summary>
internal sealed class OpResult
{
    public bool Ok { get; set; }
    public string Message { get; set; } = "";
    public string? Status { get; set; }
    public int? RequestId { get; set; }

    public static OpResult Success(string message, string? status = null, int? requestId = null) =>
        new() { Ok = true, Message = message, Status = status, RequestId = requestId };

    public static OpResult Failure(string message) => new() { Ok = false, Message = message };
}

/// <summary>What the Pal does. Machine-scope operations run elevated (see Elevation); "Me" and code signing run as the user.</summary>
internal static class Operations
{
    // ── Profiles: connect, switch, remove ──────────────────────────

    /// <summary>Pair with a new code: it becomes a new profile and the active one (backing out the current profile).</summary>
    public static async Task<OpResult> ConnectAsync(string codeText)
    {
        var code = PairingCode.Parse(codeText);
        string fqdn = LocalIdentity.Fqdn(code.Server);
        using var deviceKey = Keys.CreateDeviceKey();
        DeviceState state;
        try
        {
            using var client = new PalClient(code.Server, code.RootSha256);
            var result = await client.EnrollAsync(code, Keys.SubjectPublicKeyInfo(deviceKey), LocalIdentity.Hostname, fqdn,
                LocalIdentity.OsDescription).ConfigureAwait(false);
            var device = result.Device;
            state = new DeviceState
            {
                Server = code.Server.ToString().TrimEnd('/'),
                DeviceId = device.DeviceId,
                DeviceKeyName = deviceKey.KeyName!,
                RootSha256 = code.RootSha256,
                CaName = device.CaName,
                Label = device.Label,
                Fqdn = device.Fqdn,
                Chain = device.Chain,
                CrlDps = device.CrlDps.Count > 0 ? device.CrlDps : [device.CrlDp],
                ConnectedAt = DateTimeOffset.UtcNow,
            };
            state.Save();
            AppLog.Info($"Connected as {device.Fqdn} to {code.Server.Host} (device {device.DeviceId[..8]})");
        }
        catch
        {
            deviceKey.Delete();
            throw;
        }
        var switched = await SwitchAsync(state.DeviceId, state.CrlDps[0]).ConfigureAwait(false);
        return OpResult.Success($"Connected to {code.Server.Host} as {state.Fqdn}. " + switched.Message +
            (state.CrlDps.Count > 1 ? $" This code allows {state.CrlDps.Count} revocation types: switch profiles at the top." : ""));
    }

    /// <summary>
    /// Make (pairing, revocation type) the active profile. The current profile is backed out first:
    /// its certificates and keys leave this PC, its self-hosted listener goes, its pending requests
    /// are dropped, and its server is told. The root stays trusted (TLS inspection may rely on it).
    /// </summary>
    public static async Task<OpResult> SwitchAsync(string deviceId, string crlDp)
    {
        var target = DeviceState.LoadAll().FirstOrDefault(p => p.DeviceId == deviceId)
            ?? throw new PalException("Profile not found. It may have been removed.");
        if (!target.CrlDps.Contains(crlDp) && target.CrlDps.Count > 0)
        {
            throw new PalException($"Revocation type not allowed. This pairing allows {string.Join(", ", target.CrlDps.Select(CrlTypes.Label))}.");
        }
        var notes = new List<string>();
        if (DeviceState.Load() is { } current)
        {
            notes.Add(await BackOutAsync(current).ConfigureAwait(false));
        }
        target.Activate(crlDp);
        var added = Installer.EnsureChain(target.Chain, target.RootSha256, machine: true);
        if (added.Count > 0)
        {
            notes.Add($"{target.CaName} is now trusted on this PC.");
        }
        if (crlDp == "placeholder")
        {
            try
            {
                await InstallLocalCrlAsync(target).ConfigureAwait(false);
                notes.Add("The self-hosted CRL is running.");
            }
            catch (Exception e) when (e is PalException or IOException or UnauthorizedAccessException)
            {
                notes.Add("The self-hosted CRL couldn't be set up yet (" + FriendlyMessage(e) + "). Use Repair.");
            }
        }
        AppLog.Info($"Active profile: {target.CaName} ({target.DeviceId[..8]}), revocation {crlDp}");
        return OpResult.Success($"Profile: {target.CaName} · {CrlTypes.Label(crlDp)}. " + string.Join(" ", notes.Where(n => n.Length > 0)));
    }

    /// <summary>Take the active profile's certificates, listener and pending requests off this PC.</summary>
    private static async Task<string> BackOutAsync(DeviceState profile)
    {
        int removed = 0;
        using var root = X509Certificate2.CreateFromPem(profile.Chain[0]);
        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            using var store = new X509Store(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);
            foreach (var cert in store.Certificates)
            {
                // A certificate the Pal made (its key is one of ours) from this profile's CA.
                if (PalKeyName(cert) is not null && ChainsTo(cert, root, profile.Chain))
                {
                    Installer.Remove(location, "My", cert.Thumbprint);
                    removed++;
                }
                cert.Dispose();
            }
        }
        foreach (bool machine in new[] { true, false })
        {
            var pending = PendingStore.Open(machine);
            foreach (var (id, entry) in pending.Items.Where(kv => kv.Value.DeviceId == profile.DeviceId || kv.Value.DeviceId.Length == 0).ToList())
            {
                Keys.DeleteIfOurs(entry.KeyName, machine);
                pending.Items.Remove(id);
            }
            pending.Save();
        }
        string listener = "";
        if (profile.CrlDp == "placeholder")
        {
            listener = " " + LocalCrlServer.Remove().Message;
        }
        try
        {
            using var signer = new DeviceSigner(profile);
            using var client = new PalClient(profile.ServerUri, profile.RootSha256);
            await client.StatusAsync(signer, []).ConfigureAwait(false);  // tells the server they're gone
        }
        catch (PalException e)
        {
            AppLog.Info("Couldn't tell the server about the backed-out profile: " + e.Message);
        }
        DeviceState.ClearActive();
        AppLog.Info($"Backed out profile {profile.DeviceId[..8]}: {removed} certificates");
        return $"Backed out {profile.CaName} · {CrlTypes.Label(profile.CrlDp)}: {removed} certificate{(removed == 1 ? "" : "s")} removed.{listener}";
    }

    private static string? PalKeyName(X509Certificate2 cert)
    {
        if (!cert.HasPrivateKey)
        {
            return null;
        }
        try
        {
            using var key = cert.GetECDsaPrivateKey();
            string? name = (key as ECDsaCng)?.Key.KeyName;
            return name is not null && name.StartsWith(Keys.Prefix, StringComparison.Ordinal) ? name : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static bool ChainsTo(X509Certificate2 cert, X509Certificate2 root, List<string> chainPems)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        foreach (string pem in chainPems.Skip(1))
        {
            chain.ChainPolicy.ExtraStore.Add(X509Certificate2.CreateFromPem(pem));
        }
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        return chain.Build(cert) && chain.ChainElements[^1].Certificate.Thumbprint == root.Thumbprint;
    }

    /// <summary>Forget a profile's pairing (backing it out first if it's active).</summary>
    public static async Task<OpResult> RemoveProfileAsync(string deviceId)
    {
        var profile = DeviceState.LoadAll().FirstOrDefault(p => p.DeviceId == deviceId)
            ?? throw new PalException("Profile not found.");
        string backedOut = "";
        if (DeviceState.Load() is { } active && active.DeviceId == deviceId)
        {
            backedOut = await BackOutAsync(active).ConfigureAwait(false) + " ";
        }
        Keys.DeleteIfOurs(profile.DeviceKeyName, machine: true);
        profile.DeleteProfile();
        AppLog.Info($"Removed profile {deviceId[..8]}");
        return OpResult.Success(backedOut + $"Removed the {profile.CaName} pairing from this PC. To use it again you'll need a new pairing code.");
    }

    // ── Requests ────────────────────────────────────────────────────

    public static async Task<OpResult> RequestAsync(DeviceState state, string useCase, Dictionary<string, object> names, int? lifetime,
        int? renewOf, string? replaceThumbprint)
    {
        bool machine = UseCases.IsMachine(useCase);
        using var signer = new DeviceSigner(state);
        using var key = Keys.CreateLeafKey(machine);
        RequestView view;
        try
        {
            using var client = new PalClient(state.ServerUri, state.RootSha256);
            view = await client.CreateRequestAsync(signer, useCase, names, Keys.CsrPem(key), lifetime, renewOf,
                state.CrlDp.Length > 0 ? state.CrlDp : null).ConfigureAwait(false);
        }
        catch
        {
            key.Delete();
            throw;
        }
        if (view.Status == "issued")
        {
            Install(state, view, key, machine, replaceThumbprint);
            return OpResult.Success($"{UseCases.Label(useCase)} certificate for {view.Names.Display} installed. Expires {ExpiryText(view)}.", "issued", view.Id);
        }
        var pending = PendingStore.Open(machine);
        pending.Items[view.Id] = new PendingStore.Entry
        {
            KeyName = key.KeyName!, UseCase = useCase, ReplaceThumbprint = replaceThumbprint, DeviceId = state.DeviceId,
        };
        pending.Save();
        return OpResult.Success($"Sent. Your admin approves {UseCases.Label(useCase)} certificates: choose Check again once they have.", "pending", view.Id);
    }

    /// <summary>Install whatever the admin approved since; forget what they denied.</summary>
    public static async Task<OpResult> CollectAsync(DeviceState state, bool machine)
    {
        var pending = PendingStore.Open(machine);
        if (pending.Items.Count == 0)
        {
            return OpResult.Success("Nothing waiting.");
        }
        using var signer = new DeviceSigner(state);
        using var client = new PalClient(state.ServerUri, state.RootSha256);
        var messages = new List<string>();
        foreach (var (id, entry) in pending.Items.Where(kv => kv.Value.DeviceId == state.DeviceId || kv.Value.DeviceId.Length == 0).ToList())
        {
            var view = await client.GetRequestAsync(signer, id).ConfigureAwait(false);
            if (view.Status == "issued")
            {
                using var key = Keys.Open(entry.KeyName, machine);
                Install(state, view, key, machine, entry.ReplaceThumbprint);
                messages.Add($"{UseCases.Label(entry.UseCase)} for {view.Names.Display}: approved and installed.");
                pending.Items.Remove(id);
            }
            else if (view.Status == "denied")
            {
                Keys.DeleteIfOurs(entry.KeyName, machine);
                messages.Add($"{UseCases.Label(entry.UseCase)} for {view.Names.Display}: denied" + (view.Reason.Length > 0 ? $" ({view.Reason})." : "."));
                pending.Items.Remove(id);
            }
            else
            {
                messages.Add($"{UseCases.Label(entry.UseCase)} for {view.Names.Display}: still waiting for your admin.");
            }
        }
        pending.Save();
        return OpResult.Success(string.Join(Environment.NewLine, messages));
    }

    private static void Install(DeviceState state, RequestView view, CngKey key, bool machine, string? replaceThumbprint)
    {
        if (view.Cert is null || view.Chain is null)
        {
            throw new PalException("The server said the certificate was issued but didn't send it. Try Check again.");
        }
        Installer.EnsureChain(view.Chain, state.RootSha256, machine);
        Installer.InstallLeaf(view.Cert, key, machine);
        if (replaceThumbprint is not null)
        {
            Installer.Remove(machine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser, "My", replaceThumbprint);
        }
    }

    private static string ExpiryText(RequestView view) =>
        DateTimeOffset.TryParse(view.NotAfter, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var t)
            ? t.ToLocalTime().ToString("d MMM yyyy", System.Globalization.CultureInfo.CurrentCulture) : "later";

    /// <summary>The CA chain is in the computer's stores: the root in Trusted Root, intermediates in Intermediate CAs.</summary>
    public static bool IsTrusted(DeviceState state)
    {
        for (int i = 0; i < state.Chain.Count; i++)
        {
            using var cert = X509Certificate2.CreateFromPem(state.Chain[i]);
            using var store = new X509Store(i == 0 ? StoreName.Root : StoreName.CertificateAuthority, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            if (store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, validOnly: false).Count == 0)
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Trust the CA machine-wide, for TLS inspection: a firewall or proxy re-signing HTTPS with a
    /// certificate from this CA is then accepted by browsers and apps on this PC.
    /// </summary>
    public static async Task<OpResult> TrustAsync(DeviceState state)
    {
        var chain = state.Chain;
        List<CrlEntry> crls = [];
        try
        {
            using var signer = new DeviceSigner(state);
            using var client = new PalClient(state.ServerUri, state.RootSha256);
            var device = await client.GetDeviceAsync(signer).ConfigureAwait(false);
            if (ChainCheck.RootMatches(device.Chain, state.RootSha256))
            {
                chain = device.Chain;
                crls = device.Crls;
            }
        }
        catch (PalException e)
        {
            AppLog.Info("Trusting from the saved chain; the server didn't answer: " + e.Message);
        }
        var added = Installer.EnsureChain(chain, state.RootSha256, machine: true);
        Installer.AddCrls(crls, machine: true);
        return OpResult.Success(added.Count == 0
            ? $"{state.CaName} was already trusted on this PC."
            : $"{state.CaName} is now trusted on this PC, including for TLS inspection:\n" + string.Join("\n", added));
    }

    /// <summary>Install or refresh the self-hosted CRL with freshly signed CRLs from the server.</summary>
    public static async Task<OpResult> InstallLocalCrlAsync(DeviceState state)
    {
        using var signer = new DeviceSigner(state);
        using var client = new PalClient(state.ServerUri, state.RootSha256);
        var crls = await client.GetSelfHostedCrlsAsync(signer).ConfigureAwait(false);
        return await LocalCrlServer.InstallAsync(crls).ConfigureAwait(false);
    }

    public static int PendingCount() =>
        PendingStore.Open(machine: true).Items.Count + PendingStore.Open(machine: false).Items.Count;

    /// <summary>Remove several certificates in one go (one elevated pass for the computer's stores).</summary>
    public static OpResult RemoveMany(StoreLocation location, List<RemoveTarget> targets)
    {
        var failed = new List<string>();
        foreach (var target in targets)
        {
            try
            {
                Installer.Remove(location, target.Store, target.Thumbprint);
            }
            catch (Exception e) when (e is CryptographicException or UnauthorizedAccessException)
            {
                failed.Add($"{target.Thumbprint[..8]}… in {target.Store}: {e.Message}");
            }
        }
        return failed.Count == 0
            ? OpResult.Success(targets.Count == 1 ? "Removed." : $"Removed {targets.Count} certificates.")
            : OpResult.Failure("Not all removed. " + string.Join("\n", failed));
    }

    public static OpResult Remove(StoreLocation location, string storeName, string thumbprint)
    {
        Installer.Remove(location, storeName, thumbprint);
        return OpResult.Success("Removed.");
    }

    public static void Log(Exception e) => AppLog.Error("Operation failed", e);

    public static string FriendlyMessage(Exception e) => e switch
    {
        PalException p => p.Message,
        DeviceKeyUnavailableException => "This account can't use the PC's connection key. Run Cert Generator Pal as an administrator.",
        CryptographicException c => "Windows refused a key or certificate operation: " + c.Message,
        UnauthorizedAccessException => "Windows refused access. This needs administrator approval.",
        JsonException => "The server's answer couldn't be read.",
        _ => e.Message,
    };
}
