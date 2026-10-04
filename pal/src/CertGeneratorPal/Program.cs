namespace CertGeneratorPal;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--helper")
        {
            if (AppLog.DebugEnabled)
            {
                CertGeneratorPal.Core.PalClient.Trace = AppLog.Debug;
            }
            return Elevation.RunHelper(args[1]);
        }
        ApplicationConfiguration.Initialize();
        if (AppLog.DebugEnabled)
        {
            CertGeneratorPal.Core.PalClient.Trace = AppLog.Debug;
        }
        // An unexpected error is logged and reported in a plain message, never the .NET crash dialog.
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
        {
            AppLog.Error("Unexpected error", e.Exception);
            MessageBox.Show(Operations.FriendlyMessage(e.Exception) + "\n\nDetails are in the Pal's log.", "Cert Generator Pal",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        };
        Application.Run(new MainForm());
        return 0;
    }
}
