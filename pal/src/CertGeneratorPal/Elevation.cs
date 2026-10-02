using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>An operation handed to the elevated helper. Only these, with these fields, are accepted.</summary>
internal sealed class RemoveTarget
{
    public string Store { get; set; } = "";
    public string Thumbprint { get; set; } = "";
}

internal sealed class HelperOp
{
    public string Op { get; set; } = "";
    public string? Code { get; set; }
    public string? UseCase { get; set; }
    public Dictionary<string, object>? Names { get; set; }
    public int? LifetimeDays { get; set; }
    public int? RenewOf { get; set; }
    public string? ReplaceThumbprint { get; set; }
    public List<RemoveTarget>? Targets { get; set; }
    public bool Machine { get; set; } = true;
    public string? DeviceId { get; set; }
    public string? CrlDp { get; set; }
}

/// <summary>
/// The app runs unelevated (asInvoker). Machine-store work relaunches this EXE with
/// "--helper &lt;file&gt;" through UAC; the operation travels in a file in the user's own
/// profile, never on the command line, and the helper accepts only the allowlisted operations.
/// </summary>
internal static class Elevation
{
    private static readonly HashSet<string> MachineStores = ["My", "Root", "CA", "WebHosting", "Remote Desktop", "TrustedPeople"];

    public static bool IsElevated
    {
        get
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static async Task<OpResult> RunAsync(HelperOp op)
    {
        if (IsElevated)
        {
            return await ExecuteAsync(op).ConfigureAwait(false);
        }
        string path = Path.Combine(Paths.OpsDir, Guid.NewGuid().ToString("N") + ".json");
        string resultPath = path + ".result";
        File.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(op, Json.Options));
        try
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!)
            {
                UseShellExecute = true,
                Verb = "runas",
                ArgumentList = { "--helper", path },
            };
            using var process = Process.Start(start) ?? throw new PalException("Windows didn't start the administrator step.");
            await process.WaitForExitAsync().ConfigureAwait(false);
            if (!File.Exists(resultPath))
            {
                return OpResult.Failure("The administrator step ended without a result. See pal.log.");
            }
            return JsonSerializer.Deserialize<OpResult>(File.ReadAllBytes(resultPath), Json.Options) ?? OpResult.Failure("No result.");
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            return OpResult.Failure("Cancelled: this step needs administrator approval.");
        }
        finally
        {
            File.Delete(path);
            File.Delete(resultPath);
        }
    }

    /// <summary>The elevated side: read the operation from the user's ops folder, run it, write the result next to it.</summary>
    public static int RunHelper(string path)
    {
        string full;
        try
        {
            full = Path.GetFullPath(path);
        }
        catch (ArgumentException)
        {
            return 2;
        }
        string name = Path.GetFileName(full);
        bool inOpsDir = string.Equals(Path.GetDirectoryName(full), Path.GetFullPath(Paths.OpsDir), StringComparison.OrdinalIgnoreCase);
        if (!inOpsDir || name.Length != 37 || !Guid.TryParseExact(name[..32], "N", out _) || !name.EndsWith(".json", StringComparison.Ordinal))
        {
            AppLog.Error("Helper refused an operation file outside the ops folder (elevating as a different user isn't supported)");
            return 2;
        }
        OpResult result;
        try
        {
            var op = JsonSerializer.Deserialize<HelperOp>(File.ReadAllBytes(full), Json.Options) ?? throw new PalException("Empty operation.");
            File.Delete(full);
            result = ExecuteAsync(op).GetAwaiter().GetResult();
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Operations.Log(e);
            result = OpResult.Failure(Operations.FriendlyMessage(e));
        }
        DeviceState.AtomicWrite(full + ".result", JsonSerializer.SerializeToUtf8Bytes(result, Json.Options));
        return result.Ok ? 0 : 1;
    }

    private static async Task<OpResult> ExecuteAsync(HelperOp op)
    {
        try
        {
            switch (op.Op)
            {
                case "connect" when op.Code is not null:
                    return await Operations.ConnectAsync(op.Code).ConfigureAwait(false);
                case "trust":
                    return await Operations.TrustAsync(RequireState()).ConfigureAwait(false);
                case "crl-install":
                    return await Operations.InstallLocalCrlAsync(RequireState()).ConfigureAwait(false);
                case "crl-remove":
                    return LocalCrlServer.Remove();
                case "switch" when op.DeviceId is { Length: 32 } && op.CrlDp is not null:
                    return await Operations.SwitchAsync(op.DeviceId, op.CrlDp).ConfigureAwait(false);
                case "remove-profile" when op.DeviceId is { Length: 32 }:
                    return await Operations.RemoveProfileAsync(op.DeviceId).ConfigureAwait(false);
                case "request" when op.UseCase is not null && UseCases.All.Contains(op.UseCase) && op.Names is not null:
                    return await Operations.RequestAsync(RequireState(), op.UseCase, op.Names, op.LifetimeDays, op.RenewOf,
                        ValidThumbprint(op.ReplaceThumbprint)).ConfigureAwait(false);
                case "collect":
                    return await Operations.CollectAsync(RequireState(), op.Machine).ConfigureAwait(false);
                case "remove" when op.Targets is { Count: > 0 and <= 500 } targets
                                   && targets.All(t => MachineStores.Contains(t.Store) && ValidThumbprint(t.Thumbprint) is not null):
                    return Operations.RemoveMany(StoreLocation.LocalMachine, targets);
                default:
                    return OpResult.Failure("Unknown operation.");
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Operations.Log(e);
            return OpResult.Failure(Operations.FriendlyMessage(e));
        }
    }

    private static DeviceState RequireState() =>
        DeviceState.Load() ?? throw new PalException("This PC isn't connected. Paste a pairing code first.");

    private static string? ValidThumbprint(string? thumbprint) =>
        thumbprint is { Length: 40 } t && t.All(Uri.IsHexDigit) ? t : null;
}
