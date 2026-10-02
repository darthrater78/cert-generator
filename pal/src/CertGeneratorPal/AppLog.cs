using System.Globalization;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>A small log in %LOCALAPPDATA%\CertGeneratorPal\pal.log, for troubleshooting. Never pairing codes or keys.</summary>
internal static class AppLog
{
    private const long MaxBytes = 1024 * 1024;
    private static readonly Lock Gate = new();

    public static string LogPath => Path.Combine(Paths.UserDir, "pal.log");

    private static string DebugFlag => Path.Combine(Paths.UserDir, "debug.on");

    /// <summary>Debug logging: every server request and connectivity check (method, path, status, time).
    /// Kept as a flag file so it survives restarts, and the elevated helper of the same user follows it.</summary>
    public static bool DebugEnabled
    {
        get => File.Exists(DebugFlag);
        set
        {
            try
            {
                if (value)
                {
                    File.WriteAllText(DebugFlag, "");
                }
                else if (File.Exists(DebugFlag))
                {
                    File.Delete(DebugFlag);
                }
                Info("Debug logging " + (value ? "on" : "off"));
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                Error("Couldn't change debug logging", e);
            }
            PalClient.Trace = value ? Debug : null;
        }
    }

    public static void Info(string message) => Write("INFO", message);

    public static void Debug(string message)
    {
        if (DebugEnabled)
        {
            Write("DEBUG", message);
        }
    }

    public static void Error(string message, Exception? e = null) =>
        Write("ERROR", e is null ? message : message + ": " + e.GetType().Name + ": " + e.Message);

    private static void Write(string level, string message)
    {
        try
        {
            string path = LogPath;
            lock (Gate)
            {
                var info = new FileInfo(path);
                if (info.Exists && info.Length > MaxBytes)
                {
                    File.Move(path, path + ".1", overwrite: true);
                }
                string elevated = Elevation.IsElevated ? " [admin]" : "";
                File.AppendAllText(path, string.Create(CultureInfo.InvariantCulture,
                    $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss} {level}{elevated} {message}{Environment.NewLine}"));
            }
        }
        catch (IOException)
        {
            // logging must never break the app
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
