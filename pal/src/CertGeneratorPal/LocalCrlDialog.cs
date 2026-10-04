using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>The self-hosted CRL: what it does, whether this PC answers now, and Install / Update / Remove.</summary>
internal sealed class LocalCrlDialog : Form
{
    public string? Choice { get; private set; }

    public LocalCrlDialog(DeviceInfo device, Dictionary<string, bool> answering, bool recommended)
    {
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Self-hosted CRL";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(18);

        bool installed = answering.Count > 0 && answering.Values.Any(v => v);
        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Fill };
        layout.Controls.Add(new Label { Text = "Self-hosted CRL", AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 0, 0, 8) });
        layout.Controls.Add(new Label
        {
            Text = "This PC answers its own revocation checks for your CA, so certificates keep validating even when " +
                   "the PC can't reach your server (a laptop away from home). A small listener starts with Windows " +
                   "and serves the CA's CRL on this PC only.\n\nIt's the same listener the install bundles use, and they share it.",
            AutoSize = true,
            MaximumSize = new Size(480, 0),
            Margin = new Padding(0, 0, 0, 10),
        });
        if (recommended && !installed)
        {
            layout.Controls.Add(new Label
            {
                Text = "Recommended: your admin set this PC's certificates to check revocation on the PC itself.",
                AutoSize = true, MaximumSize = new Size(480, 0), ForeColor = Theme.Warning, Margin = new Padding(0, 0, 0, 8),
            });
        }
        layout.Controls.Add(Theme.Eyebrow("Status"));
        foreach (var a in device.SelfHosted)
        {
            bool up = answering.GetValueOrDefault(a.Url);
            layout.Controls.Add(new Label
            {
                Text = $"{(up ? "✓ Answering" : "✗ Not installed")}  ·  {a.CaName}\n     {a.Url}",
                AutoSize = true,
                ForeColor = up ? Theme.Success : Theme.TextDim,
                Font = Theme.Mono,
                Margin = new Padding(0, 2, 0, 4),
            });
        }
        layout.Controls.Add(new Label
        {
            Text = "Install and Remove change the hosts file, an HTTP.sys address and a startup task, so Windows asks for " +
                   "administrator approval once.",
            AutoSize = true, MaximumSize = new Size(480, 0), ForeColor = SystemColors.GrayText, Margin = new Padding(0, 10, 0, 0),
        });

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 14, 0, 0) };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var install = new Button { Text = installed ? "Update CRL" : "Install", AutoSize = true, Tag = Theme.ButtonKind.Primary };
        var remove = new Button { Text = "Remove", AutoSize = true, Tag = Theme.ButtonKind.Danger, Enabled = installed };
        install.Click += (_, _) => { Choice = "crl-install"; DialogResult = DialogResult.OK; };
        remove.Click += (_, _) => { Choice = "crl-remove"; DialogResult = DialogResult.OK; };
        buttons.Controls.AddRange([close, install, remove]);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
        CancelButton = close;
        Theme.Apply(this);
        ResumeLayout(false);
        PerformLayout();
    }
}
