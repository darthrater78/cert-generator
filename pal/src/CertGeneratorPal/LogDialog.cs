using System.Diagnostics;

namespace CertGeneratorPal;

/// <summary>The Pal's log: the latest lines, a debug switch, and ways to hand the log to someone.</summary>
internal sealed class LogDialog : Form
{
    private const int TailLines = 400;
    private readonly TextBox _text = new()
    {
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill,
        Font = Theme.Mono, BorderStyle = BorderStyle.FixedSingle,
    };

    public LogDialog()
    {
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Cert Generator Pal log";
        ClientSize = new Size(860, 520);
        MinimumSize = new Size(520, 320);
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MinimizeBox = false;
        SizeGripStyle = SizeGripStyle.Show;

        var top = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(12, 10, 12, 6), WrapContents = true };
        var debug = new CheckBox
        {
            Text = "Debug logging: record every server request and connectivity check (never keys or pairing codes)",
            AutoSize = true, Checked = AppLog.DebugEnabled, Margin = new Padding(0, 4, 0, 0),
        };
        debug.CheckedChanged += (_, _) =>
        {
            AppLog.DebugEnabled = debug.Checked;
            LoadTail();
        };
        top.Controls.Add(debug);
        top.Controls.Add(new Label
        {
            Text = AppLog.LogPath, AutoSize = true, ForeColor = SystemColors.GrayText, Font = Theme.Mono, Margin = new Padding(0, 6, 0, 0),
        });

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12, 0, 12, 0) };
        body.Controls.Add(_text);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 8, 12, 12) };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var reload = new Button { Text = "Reload", AutoSize = true };
        var folder = new Button { Text = "Open folder", AutoSize = true };
        var save = new Button { Text = "Save a copy…", AutoSize = true };
        reload.Click += (_, _) => LoadTail();
        folder.Click += (_, _) => OpenFolder();
        save.Click += (_, _) => SaveCopy();
        buttons.Controls.AddRange([close, reload, folder, save]);

        Controls.Add(body);
        Controls.Add(top);
        Controls.Add(buttons);
        CancelButton = close;
        Theme.Apply(this);
        Shown += (_, _) => LoadTail();
        ResumeLayout(false);
        PerformLayout();
    }

    private void LoadTail()
    {
        try
        {
            var lines = File.Exists(AppLog.LogPath) ? ReadShared(AppLog.LogPath) : [];
            _text.Text = lines.Count == 0 ? "(the log is empty)" : string.Join(Environment.NewLine, lines.TakeLast(TailLines));
            _text.SelectionStart = _text.TextLength;
            _text.ScrollToCaret();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            _text.Text = "Couldn't read the log: " + e.Message;
        }
    }

    /// <summary>Read while the app may still be appending to it.</summary>
    private static List<string> ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var reader = new StreamReader(stream);
        var lines = new List<string>();
        while (reader.ReadLine() is { } line)
        {
            lines.Add(line);
        }
        return lines;
    }

    private static void OpenFolder()
    {
        string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        Process.Start(new ProcessStartInfo(explorer, "\"" + Paths.UserDir + "\"") { UseShellExecute = false })?.Dispose();
    }

    private void SaveCopy()
    {
        using var dialog = new SaveFileDialog { FileName = "CertGeneratorPal-log.txt", Filter = "Text (*.txt)|*.txt" };
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }
        try
        {
            var lines = new List<string>();
            string previous = AppLog.LogPath + ".1";
            if (File.Exists(previous))
            {
                lines.AddRange(ReadShared(previous));
            }
            if (File.Exists(AppLog.LogPath))
            {
                lines.AddRange(ReadShared(AppLog.LogPath));
            }
            File.WriteAllLines(dialog.FileName, lines);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, "Couldn't save the log: " + e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }
}
