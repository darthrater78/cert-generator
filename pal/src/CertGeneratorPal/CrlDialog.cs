using System.Globalization;
using System.Text;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>A CRL as its address serves it now: who issued it, when, and every serial it revokes.</summary>
internal sealed class CrlDialog : Form
{
    /// <param name="onThisPc">Normalized serial → names, for certificates in this PC's stores.</param>
    public CrlDialog(string type, string url, CrlList crl, IReadOnlyDictionary<string, string> onThisPc)
    {
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "CRL · " + type;
        ClientSize = new Size(760, 460);
        MinimumSize = new Size(520, 300);
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MinimizeBox = false;
        SizeGripStyle = SizeGripStyle.Show;

        var text = new TextBox
        {
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill,
            Font = Theme.Mono, BorderStyle = BorderStyle.FixedSingle, Text = Describe(url, crl, onThisPc),
        };
        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12, 12, 12, 0) };
        body.Controls.Add(text);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 8, 12, 12) };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        buttons.Controls.Add(close);
        Controls.Add(body);
        Controls.Add(buttons);
        CancelButton = close;
        Theme.Apply(this);
        Shown += (_, _) => text.Select(0, 0);
        ResumeLayout(false);
        PerformLayout();
    }

    private static string Describe(string url, CrlList crl, IReadOnlyDictionary<string, string> onThisPc)
    {
        var lines = new StringBuilder()
            .AppendLine($"Address      {url}")
            .AppendLine($"Issuer       {crl.Issuer}")
            .AppendLine($"Issued       {CrlCheck.Date(crl.ThisUpdate)}")
            .AppendLine($"Next update  {(crl.NextUpdate is { } next ? CrlCheck.Date(next) + (crl.Stale ? "  (STALE: Windows rejects it)" : "") : "none")}")
            .AppendLine()
            .AppendLine($"Revoked certificates: {crl.Revoked.Count.ToString(CultureInfo.CurrentCulture)}");
        if (crl.Revoked.Count > 0)
        {
            int width = Math.Max(6, crl.Revoked.Max(r => r.Serial.Length));
            lines.AppendLine().AppendLine($"{"Serial".PadRight(width)}  Revoked");
            foreach (var entry in crl.Revoked.OrderByDescending(r => r.RevokedAt))
            {
                string here = onThisPc.TryGetValue(StoreAudit.NormalizeSerial(entry.Serial), out string? names) ? $"  ← on this PC: {names}" : "";
                lines.AppendLine($"{entry.Serial.PadRight(width)}  {CrlCheck.Date(entry.RevokedAt)}{here}");
            }
        }
        return lines.ToString();
    }
}
