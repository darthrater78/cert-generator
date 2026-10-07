namespace CertGeneratorPal;

internal static class Program
{
    /// <summary>How long the process gets to end by itself once the window has closed.</summary>
    private static readonly TimeSpan ExitGrace = TimeSpan.FromSeconds(5);

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
        ExitCompletely();
        return 0;
    }

    /// <summary>
    /// The window is closed, so the process goes too. Says in the log what was still open, then keeps watch:
    /// if anything holds the process past <see cref="ExitGrace"/> (a thread stuck in the TPM, a store or a
    /// network call), that is logged and the process is ended. The watch is a background thread, so it
    /// never holds the process itself.
    /// </summary>
    private static void ExitCompletely()
    {
        int windows = Application.OpenForms.Count;
        AppLog.Info("Closed" + (windows > 0 ? $"; {windows} other window(s) still open, closing them" : "")
            + (Elevation.HelperRunning ? "; an administrator step is still running in its own process and its result is dropped" : ""));
        foreach (Form form in Application.OpenForms.Cast<Form>().ToList())
        {
            form.Close();
        }
        new Thread(() =>
        {
            Thread.Sleep(ExitGrace);
            using var self = System.Diagnostics.Process.GetCurrentProcess();
            AppLog.Error($"Still running {ExitGrace.TotalSeconds:0} seconds after closing ({self.Threads.Count} threads): ending the process");
            Environment.Exit(0);
        }) { IsBackground = true, Name = "exit watch" }.Start();
    }
}
