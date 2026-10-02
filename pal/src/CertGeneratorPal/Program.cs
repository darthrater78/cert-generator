namespace CertGeneratorPal;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--helper")
        {
            return Elevation.RunHelper(args[1]);
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }
}
