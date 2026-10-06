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

    private readonly Panel _scroll = new() { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(20, 16, 20, 0) };
    private readonly TableLayoutPanel _layout = new() { ColumnCount = 1, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Top };
    private readonly List<Control> _wide = [];
    private readonly List<Label> _half = [];

    /// <param name="crlDays">How long this CA's published CRL is valid (read from the CRL itself); 7, the server's default, when unknown.</param>
    public RevocationGuideDialog(int crlDays = 7)
    {
        string life = Days(crlDays);
        (string What, string When)[] timings =
        [
            ("You revoke a certificate", "new CRL published at once"),
            ("How long one CRL is good for", $"{life} (Issued → Next update)"),
            ("Server re-signs with nothing revoked", $"when {Half(crlDays)} are left".Replace("1 day are", "1 day is", StringComparison.Ordinal)),
            ("PC with a cached CRL notices", $"when its copy runs out: up to {life}"),
            ("PC with nothing cached notices", "at the next check"),
            ("Windows waits for a CRL address", "15 seconds"),
            ("Copy ran out and no new CRL can be fetched", "the program decides: many carry on, some warn or refuse"),
        ];
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

        _layout.Controls.Add(new Label { Text = "How Windows checks revocation", AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 0, 0, 6) });
        Wide(new Panel { Height = 2, BackColor = Theme.Rule, Margin = new Padding(0, 0, 0, 12) });

        Section("The short version");
        Para("The server publishes a new CRL the moment you revoke. A PC that already holds a copy of the old CRL keeps using it " +
             $"until that copy runs out, which can be up to {life}. Your admin sets that time on the CA.");
        Wide(new DayStrip { Height = 14, Margin = new Padding(0, 2, 0, 4) });
        Para("With a 7-day CRL: day 0, this PC fetches the CRL.  Day 2: revoked on the server; this PC still trusts it.  Day 7: the copy runs out, " +
             "this PC fetches the new CRL and the certificate is refused.", dim: true);

        Section("A revoked certificate, after the copy runs out");
        Para("Until the copy runs out, the revoked certificate works exactly as before. Then the first check fetches the new CRL, " +
             "finds the certificate's serial on it, and from that moment:");
        Para("•  Programs that check refuse it. Remote Desktop, a server checking this PC's certificate and smart card sign-in stop " +
             "accepting it or warn, and certutil -verify says REVOKED. It stays revoked: only a new certificate fixes it.");
        Para("•  Nothing removes it. The certificate and its key stay in the store, the certificate window still says it is OK, and " +
             "programs that don't check keep accepting it. The Pal marks it revoked; Remove takes it off this PC.");
        Para("•  If the CRL address can't be reached, Windows can't tell that it is revoked. Many programs then carry on accepting " +
             "it, so a revoked certificate keeps working wherever the CRL can't be fetched.");
        Para("The wait happens on the machine doing the checking. For a certificate this PC presents to a server, it is the " +
             "server's cached copy that has to run out, not this PC's.");

        Section("When Windows looks at a CRL");
        Para("Only when a program asks Windows to verify a certificate with revocation checking. Nothing checks in the background.");
        Para("•  Checks: Remote Desktop, a web or VPN server checking this PC's certificate, smart card sign-in, certutil -verify -urlfetch.");
        Para("•  Doesn't check: the certificate window (\"This certificate is OK\"), and Chrome or Edge for a private CA such as yours.");

        Section("Where it gets the CRL");
        Para("From the address written into the certificate when it was issued. That address comes from the CRL profile in use at the " +
             "time; switching profile later doesn't change certificates already issued.");

        Section("Timings");
        var ledger = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Margin = new Padding(0, 0, 0, 4) };
        foreach (var (what, when) in timings)
        {
            var label = new Label { Text = what, AutoSize = true, Font = Theme.SerifItalic, Margin = new Padding(0, 3, 14, 3) };
            var value = new Label { Text = when, AutoSize = true, Font = Theme.Mono, Margin = new Padding(0, 4, 0, 3) };
            ledger.Controls.Add(label);
            ledger.Controls.Add(value);
            _half.Add(label);
            _half.Add(value);
        }
        _layout.Controls.Add(ledger);

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
        Para("•  Clear cached CRLs deletes your account's copies of this CA's CRLs.");
        Para("•  Force re-check now tells every account, service and running program to stop trusting anything cached before this moment.");
        Para("•  Then check a certificate: certutil -verify -urlfetch cert.cer says REVOKED once Windows has the new CRL.");

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

    private void Section(string title)
    {
        var eyebrow = Theme.Eyebrow(title);
        eyebrow.Margin = new Padding(0, 12, 0, 4);
        _layout.Controls.Add(eyebrow);
    }

    private void Para(string text, bool dim = false)
    {
        var label = new Label { Text = text, AutoSize = true, Margin = new Padding(0, 0, 0, 5) };
        if (dim)
        {
            label.ForeColor = Theme.TextDim;
        }
        Wide(label);
    }

    private void Wide(Control control)
    {
        _wide.Add(control);
        _layout.Controls.Add(control);
    }

    /// <summary>Text wraps at the window's width; the rule and the day strip span it.</summary>
    private void FitWidth()
    {
        int width = Math.Max(200, _scroll.ClientSize.Width - _scroll.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth);
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
        foreach (var label in _half)
        {
            label.MaximumSize = new Size((width - 14) / 2, 0);
        }
    }

    /// <summary>One cached CRL: trusted rightly until the revocation, wrongly from then until it runs out, then replaced.</summary>
    private sealed class DayStrip : Control
    {
        public DayStrip() => ResizeRedraw = true;

        protected override void OnPaint(PaintEventArgs e)
        {
            int split = Width * 2 / 9, end = Width * 7 / 9;  // nine days drawn: the revocation on day 2, the copy runs out on day 7
            using var current = new SolidBrush(Theme.Success);
            using var behind = new HatchBrush(HatchStyle.WideUpwardDiagonal, Theme.Warning, Theme.Bg);
            using var rule = new Pen(Theme.Rule);
            e.Graphics.FillRectangle(current, 0, 0, split, Height - 1);
            e.Graphics.FillRectangle(behind, split, 0, end - split, Height - 1);
            e.Graphics.FillRectangle(current, end, 0, Width - end - 1, Height - 1);
            e.Graphics.DrawRectangle(rule, 0, 0, Width - 1, Height - 1);
            e.Graphics.DrawLine(rule, split, 0, split, Height - 1);
            e.Graphics.DrawLine(rule, end, 0, end, Height - 1);
        }
    }
}
