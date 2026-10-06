using System.Drawing.Drawing2D;

namespace CertGeneratorPal;

/// <summary>
/// How Windows handles a CRL, and why a revocation can take days to show. Opens beside the main window
/// (not modal), so it can be read while testing.
/// </summary>
internal sealed class RevocationGuideDialog : Form
{
    private static string Days(int days) => days == 1 ? "1 day" : $"{days} days";

    /// <summary>Half a CRL's life, when the server re-signs it: "12 hours", "1 day", "3½ days".</summary>
    private static string Half(int days) => days == 1 ? "12 hours" : days % 2 == 0 ? Days(days / 2) : $"{days / 2}½ days";

    private const int Measure = 560;  // the text column, in 96-dpi pixels: about 75 characters of the serif

    private readonly Panel _scroll = new() { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(20, 16, 20, 0) };
    private readonly TableLayoutPanel _layout = new() { ColumnCount = 1, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Top };
    private readonly List<Control> _wide = [];
    private readonly List<Label> _noteBodies = [];

    /// <param name="crlDays">How long this CA's published CRL is valid (read from the CRL itself); 7, the server's default, when unknown.</param>
    public RevocationGuideDialog(int crlDays = 7)
    {
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "How Windows checks revocation";
        ClientSize = new Size(640, 620);
        MinimumSize = new Size(440, 320);
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MinimizeBox = false;
        SizeGripStyle = SizeGripStyle.Show;

        AddOverview(crlDays);
        AddHowWindowsChecks();
        AddTimings(crlDays);
        AddTesting();

        _scroll.Controls.Add(_layout);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 8, 12, 12) };
        var close = new Button { Text = "Close", AutoSize = true };
        close.Click += (_, _) => Close();
        buttons.Controls.Add(close);
        Controls.Add(_scroll);
        Controls.Add(buttons);
        CancelButton = close;
        Theme.Apply(this);
        Resize += (_, _) => FitWidth();
        ResumeLayout(false);
        PerformLayout();
        FitWidth();
    }

    private void AddOverview(int crlDays)
    {
        Section("The short version", first: true);
        Para("The server publishes a new CRL the moment you revoke. A PC that already holds a copy of the old one keeps using it " +
             $"until that copy runs out, which on this CA is up to {Days(crlDays)}. Your admin sets that time on the CA.");
        Wide(new DayStrip(crlDays) { Margin = new Padding(0, 6, 0, 4) });

        Section("Once the copy runs out");
        Para("Until then the revoked certificate works exactly as before. Then the first check fetches the new CRL, " +
             "finds the certificate's serial on it, and from that moment:");
        Note("Programs that check refuse it", "Remote Desktop, a server checking this PC's certificate and smart card sign-in stop " +
             "accepting it or warn, and certutil -verify says REVOKED. It stays revoked: only a new certificate fixes it.", Theme.Danger);
        Note("Nothing removes it", "The certificate and its key stay in the store, the certificate window still says it is OK, and " +
             "programs that don't check keep accepting it. The Pal marks it revoked; Remove takes it off this PC.");
        Note("If the CRL can't be reached", "Windows can't tell that it is revoked. Many programs then carry on accepting " +
             "it, so a revoked certificate keeps working wherever the CRL can't be fetched.", Theme.Warning);
        Para("The wait happens on the machine doing the checking. For a certificate this PC presents to a server, it is the " +
             "server's cached copy that has to run out, not this PC's.", dim: true);
    }

    private void AddHowWindowsChecks()
    {
        Section("When Windows looks at a CRL");
        Para("Only when a program asks Windows to verify a certificate with revocation checking. Nothing checks in the background.");
        Note("Checks", "Remote Desktop, a web or VPN server checking this PC's certificate, smart card sign-in, certutil -verify -urlfetch.");
        Note("Doesn't check", "The certificate window (\"This certificate is OK\"), and Chrome or Edge for a private CA such as yours.");

        Section("Where it gets the CRL");
        Para("From the address written into the certificate when it was issued. That address comes from the CRL profile in use at the " +
             "time; switching profile later doesn't change certificates already issued.");
    }

    /// <summary>The timings ledger. The lifetime is the CA's own: the server re-signs at half of it (app/crl_publisher.py).</summary>
    private void AddTimings(int crlDays)
    {
        string life = Days(crlDays);
        Section("Timings");
        Wide(new Ledger(
        [
            ("You revoke a certificate", "new CRL published at once"),
            ("How long one CRL is good for", life),
            ("Server re-signs with nothing revoked", $"when {Half(crlDays)} are left".Replace("1 day are", "1 day is", StringComparison.Ordinal)),
            ("PC with a cached CRL notices", $"up to {life}"),
            ("PC with nothing cached notices", "at the next check"),
            ("Windows waits for a CRL address", "15 seconds"),
            ("Copy ran out, no new CRL to be had", "the program decides"),
        ]) { Margin = new Padding(0, 0, 0, 4) });
        Para("When the copy has run out and no new CRL can be fetched, many programs carry on and some warn or refuse.", dim: true);
    }

    private void AddTesting()
    {
        Section("Can a program ask early?");
        Para("Yes, if it was written to. When a program asks Windows to verify a certificate it can set a maximum age for the CRL, " +
             "and Windows then fetches a newer one even though the cached copy hasn't run out. It can also download the CRL itself.");
        Para("Remote Desktop, web servers, smart card sign-in and the rest of Windows don't do this, and there is no setting that " +
             "makes them. They use the cached copy until it runs out, so what shortens the wait for them is a shorter-lived CRL " +
             "on the server, or Force re-check now on this PC.");

        Section("More than one cache");
        Para("Each Windows account keeps its own copies on disk, and so do services that run as SYSTEM. A program that is already " +
             "running also keeps a copy in memory. The Windows cache rows in the Pal show your account's copies only.");

        Section("Making Windows look again (for testing)");
        Note("Clear cached CRLs", "Deletes your account's copies of this CA's CRLs.");
        Note("Force re-check now", "Tells every account, service and running program to stop trusting anything cached before this moment.");
        Note("Then check a certificate", "certutil -verify -urlfetch cert.cer says REVOKED once Windows has the new CRL.");
        _layout.Controls.Add(new Panel { Height = 14, Width = 1, Margin = new Padding(0) });
    }

    private void Section(string title, bool first = false)
    {
        var eyebrow = Theme.Eyebrow(title);
        eyebrow.Margin = new Padding(0, first ? 0 : 18, 0, 5);
        _layout.Controls.Add(eyebrow);
    }

    private void Para(string text, bool dim = false)
    {
        var label = new Label { Text = text, AutoSize = true, Font = Theme.Serif, Margin = new Padding(0, 0, 0, 6) };
        if (dim)
        {
            label.ForeColor = Theme.TextDim;
        }
        Wide(label);
    }

    /// <summary>A labelled point under a left rule, in <paramref name="ink"/> when it is a refusal or a risk: the text hangs clear of the rule.</summary>
    private void Note(string label, string text, Color? ink = null)
    {
        var note = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Padding = new Padding(12, 0, 0, 0), Margin = new Padding(0, 2, 0, 7) };
        var eyebrow = Theme.Eyebrow(label);
        eyebrow.ForeColor = ink ?? Theme.TextDim;
        eyebrow.Margin = new Padding(0, 0, 0, 1);
        var body = new Label { Text = text, AutoSize = true, Font = Theme.Serif, Margin = new Padding(0) };
        note.Controls.Add(eyebrow);
        note.Controls.Add(body);
        note.Paint += (_, e) =>
        {
            using var rule = new SolidBrush(ink ?? Theme.Rule);
            e.Graphics.FillRectangle(rule, 0, 0, LogicalToDeviceUnits(3), note.Height);
        };
        _noteBodies.Add(body);
        _layout.Controls.Add(note);
    }

    private void Wide(Control control)
    {
        _wide.Add(control);
        _layout.Controls.Add(control);
    }

    /// <summary>Text wraps at the window's width, up to the measure; the strip and the ledger span the same column.</summary>
    private void FitWidth()
    {
        int room = _scroll.ClientSize.Width - _scroll.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth;
        int width = Math.Clamp(room, 200, LogicalToDeviceUnits(Measure));
        foreach (var control in _wide)
        {
            if (control is Label label)
            {
                label.MaximumSize = new Size(width, 0);
            }
            else
            {
                control.Width = width;
            }
        }
        foreach (var body in _noteBodies)
        {
            body.MaximumSize = new Size(width - LogicalToDeviceUnits(12), 0);
        }
    }

    /// <summary>
    /// One cached CRL over its life, labelled: trusted rightly until the revocation, wrongly from then until
    /// the copy runs out, then refused. Drawn for this CA's own CRL lifetime.
    /// </summary>
    private sealed class DayStrip : Control
    {
        private const TextFormatFlags Flags = TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine;
        private readonly string[] _when;
        private static readonly string[] State = ["trusted", "still trusted, wrongly", "refused"];
        private static readonly string[] Event = ["PC fetches CRL", "revoked on the server", "copy runs out"];

        public DayStrip(int crlDays)
        {
            ResizeRedraw = true;
            // The revocation is drawn 3/8 of the way through the copy's life. Short lifetimes read better in hours.
            _when = crlDays < 4
                ? ["hour 0", $"hour {crlDays * 9}", $"hour {crlDays * 24}"]
                : ["day 0", $"day {(int)Math.Round(crlDays * 3 / 8.0)}", $"day {crlDays}"];
            Height = Theme.SerifItalic.Height + Bar + 2 * Theme.Mono.Height + 10;
        }

        private static int Bar => 14;

        protected override void OnPaint(PaintEventArgs e)
        {
            int[] x = [0, Width * 3 / 11, Width * 8 / 11, Width - 1];  // eleven parts drawn: fetched at 0, revoked at 3, runs out at 8
            int top = Theme.SerifItalic.Height + 3, below = top + Bar + 3;
            using var current = new SolidBrush(Theme.Success);
            using var behind = new HatchBrush(HatchStyle.WideUpwardDiagonal, Theme.Warning, Theme.Bg);
            using var rule = new Pen(Theme.Rule);
            for (int i = 0; i < 3; i++)
            {
                e.Graphics.FillRectangle(i == 1 ? behind : current, x[i], top, x[i + 1] - x[i], Bar);
                e.Graphics.DrawLine(rule, x[i], top, x[i], Height - 1);
                TextRenderer.DrawText(e.Graphics, State[i], Theme.SerifItalic, new Point(x[i] + 5, 0), i == 1 ? Theme.Warning : Theme.Text, Flags);
                TextRenderer.DrawText(e.Graphics, _when[i], Theme.Mono, new Point(x[i] + 5, below), Theme.Text, Flags);
                TextRenderer.DrawText(e.Graphics, Event[i], Theme.Mono, new Point(x[i] + 5, below + Theme.Mono.Height), Theme.TextDim, Flags);
            }
            e.Graphics.DrawRectangle(rule, 0, top, Width - 1, Bar);
        }
    }

    /// <summary>The register's label and value pairs: an italic serif label, a dotted leader, the value in mono at the right edge.</summary>
    private sealed class Ledger : Control
    {
        private const TextFormatFlags Flags = TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.WordBreak;
        private readonly (string What, string When)[] _rows;

        public Ledger((string What, string When)[] rows)
        {
            _rows = rows;
            ResizeRedraw = true;
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            Height = Rows(null);
        }

        protected override void OnPaint(PaintEventArgs e) => Rows(e.Graphics);

        /// <summary>Lays the rows out at the current width, drawing them when given somewhere to draw; the height they take.</summary>
        private int Rows(Graphics? g)
        {
            int y = 0;
            using var leader = new Pen(Theme.Rule) { DashStyle = DashStyle.Dot };
            foreach (var (what, when) in _rows)
            {
                Size label = TextRenderer.MeasureText(what, Theme.SerifItalic, new Size(Width * 6 / 10, 0), Flags);
                Size value = TextRenderer.MeasureText(when, Theme.Mono, new Size(Width * 4 / 10 - 16, 0), Flags);
                if (g is not null)
                {
                    TextRenderer.DrawText(g, what, Theme.SerifItalic, new Rectangle(0, y, label.Width, label.Height), Theme.Text, Flags);
                    TextRenderer.DrawText(g, when, Theme.Mono, new Rectangle(Width - value.Width, y + 2, value.Width, value.Height), Theme.Text, Flags | TextFormatFlags.Right);
                    int line = y + Theme.SerifItalic.Height - 5;
                    g.DrawLine(leader, label.Width + 8, line, Width - value.Width - 8, line);
                }
                y += Math.Max(label.Height, value.Height + 2) + 6;
            }
            return y;
        }
    }
}
