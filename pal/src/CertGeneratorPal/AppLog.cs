using System.Globalization;

namespace CertGeneratorPal;

/// <summary>A small log in %LOCALAPPDATA%\CertGeneratorPal\pal.log, for troubleshooting. Never pairing codes or keys.</summary>
internal static class AppLog
{
    private const long MaxBytes = 1024 * 1024;
    private static readonly Lock Gate = new();

    public static void Info(string message) => Write("INFO", message);

    public static void Error(string message, Exception? e = null) =>
        Write("ERROR", e is null ? message : message + ": " + e.GetType().Name + ": " + e.Message);

    private static void Write(string level, string message)
    {
        try
        {
            string path = Path.Combine(Paths.UserDir, "pal.log");
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
