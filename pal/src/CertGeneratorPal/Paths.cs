using System.Security.AccessControl;
using System.Security.Principal;

namespace CertGeneratorPal;

/// <summary>
/// Where the Pal keeps its state. The machine folder in ProgramData holds the PC's connection
/// (written only elevated); the user folder holds the log, pending "Me" requests and the
/// hand-off files for the elevated helper.
/// </summary>
internal static class Paths
{
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);

    public static string MachineDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "CertGeneratorPal");

    public static string UserDir
    {
        get
        {
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CertGeneratorPal");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    public static string OpsDir
    {
        get
        {
            string dir = Path.Combine(UserDir, "ops");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    public static string DeviceFile => Path.Combine(MachineDir, "device.json");

    public static string MachinePendingFile => Path.Combine(MachineDir, "pending.json");

    public static string UserPendingFile => Path.Combine(UserDir, "pending.json");

    public static string PendingBindsFile => Path.Combine(MachineDir, "pending-binds.json");

    public static string BindLogFile => Path.Combine(MachineDir, "binds.json");

    /// <summary>
    /// Create the machine folder (elevated only) with Administrators/SYSTEM full control and
    /// Users read. ProgramData lets any user create folders, so a folder someone else made
    /// first (and could plant files in) is refused rather than trusted.
    /// </summary>
    public static void EnsureMachineDir()
    {
        var info = new DirectoryInfo(MachineDir);
        if (info.Exists)
        {
            var existing = info.GetAccessControl();
            var owner = existing.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner is null || !(owner.Equals(Administrators) || owner.Equals(LocalSystem)))
            {
                throw new Core.PalException($"{MachineDir} exists but isn't owned by Administrators. Delete it, then connect again.");
            }
        }
        var security = new DirectorySecurity();
        security.SetOwner(Administrators);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (info.Exists)
        {
            info.SetAccessControl(security);
        }
        else
        {
            info.Create(security);
        }
    }
}
