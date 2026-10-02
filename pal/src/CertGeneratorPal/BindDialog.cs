using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>
/// "Use for Remote Desktop" and "Bind to IIS site": part of the Web server / RDP request, and
/// the Bind… dialog for a certificate already installed.
/// </summary>
internal sealed class BindPanel : TableLayoutPanel
{
    private const string AllNames = "Every name (no SNI)";
    private readonly CheckBox _rdp = new() { Text = "Use for Remote Desktop", AutoSize = true };
    private readonly CheckBox _iis = new() { Text = "Bind to an IIS site", AutoSize = true };
    private readonly ComboBox _site = new() { Width = 220 };
    private readonly NumericUpDown _port = new() { Minimum = 1, Maximum = 65535, Value = 443, Width = 80 };
    private readonly ComboBox _host = new() { Width = 220, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly Func<IEnumerable<string>> _names;

    public BindPanel(Func<IEnumerable<string>> certificateNames, IReadOnlyCollection<string> usedBy)
    {
        _names = certificateNames;
        ColumnCount = 1;
        AutoSize = true;
        Margin = new Padding(0, 10, 0, 0);
        Controls.Add(new Label { Text = "Use it for", AutoSize = true, Font = new Font(Font, FontStyle.Bold) });
        if (usedBy.Count > 0)
        {
            Controls.Add(Hint("In use now: " + string.Join(", ", usedBy) + "."));
        }
        Controls.Add(_rdp);
        Controls.Add(Hint("Remote Desktop connections to this PC present this certificate instead of a self-signed one."));

        if (Binder.Iis.IsInstalled)
        {
            Controls.Add(_iis);
            var sites = Binder.Iis.TryListSites();
            if (sites is { Count: > 0 })
            {
                _site.Items.AddRange([.. sites.Select(s => s.Name)]);
                _site.SelectedIndex = 0;
            }
            else
            {
                // Reading IIS's configuration needs administrator rights: type the name as IIS Manager shows it.
                _site.Text = "Default Web Site";
            }
            var row = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(18, 2, 0, 0) };
            row.Controls.Add(Caption("Site"));
            row.Controls.Add(_site);
            row.Controls.Add(Caption("Port"));
            row.Controls.Add(_port);
            var hostRow = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(18, 2, 0, 0) };
            hostRow.Controls.Add(Caption("Host name"));
            hostRow.Controls.Add(_host);
            Controls.Add(row);
            Controls.Add(hostRow);
            Controls.Add(Hint(sites is null
                ? "The site's https binding is added if it has none; an existing one switches to this certificate. Type the site name as IIS Manager shows it."
                : "The site's https binding is added if it has none; an existing one switches to this certificate."));
            FillHosts();
            _host.DropDown += (_, _) => FillHosts();
            _iis.CheckedChanged += (_, _) => SyncEnabled();
            SyncEnabled();
        }
        else
        {
            Controls.Add(Hint("IIS isn't installed on this PC, so there's no site to bind."));
        }
    }

    public BindRequest Request => new()
    {
        Rdp = _rdp.Checked,
        IisSite = _iis.Checked ? _site.Text.Trim() : null,
        Port = (int)_port.Value,
        Host = _host.SelectedItem is string h && h != AllNames ? h : "",
    };

    /// <summary>Check the choices before any administrator prompt. Shows the problem and returns false.</summary>
    public bool ValidateFor(IWin32Window owner, string title)
    {
        try
        {
            BindingRules.Validate(Request, _names());
            return true;
        }
        catch (PalException e)
        {
            MessageBox.Show(owner, e.Message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }
    }

    private void FillHosts()
    {
        object? selected = _host.SelectedItem;
        _host.Items.Clear();
        _host.Items.Add(AllNames);
        _host.Items.AddRange([.. _names().Where(BindingRules.IsValidHost).Distinct(StringComparer.OrdinalIgnoreCase)]);
        _host.SelectedItem = selected is not null && _host.Items.Contains(selected) ? selected : AllNames;
    }

    private void SyncEnabled() => _site.Enabled = _port.Enabled = _host.Enabled = _iis.Checked;

    private static Label Caption(string text) => new() { Text = text, AutoSize = true, Margin = new Padding(0, 6, 6, 0) };

    private static Label Hint(string text) => new()
    {
        Text = text,
        AutoSize = true,
        MaximumSize = new Size(460, 0),
        ForeColor = SystemColors.GrayText,
        Margin = new Padding(18, 0, 0, 4),
    };
}

/// <summary>Bind… on a web server certificate already in the computer's Personal store.</summary>
internal sealed class BindDialog : Form
{
    private readonly BindPanel _panel;

    public BindRequest Request => _panel.Request;

    public BindDialog(AuditItem item)
    {
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Bind: " + item.Names;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(16);

        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Fill };
        layout.Controls.Add(new Label
        {
            Text = $"Use {item.Names} (expires {item.Cert.NotAfter:d MMM yyyy}) for Remote Desktop or an IIS site. " +
                   "When the Pal renews it, whatever uses it moves to the new certificate.",
            AutoSize = true,
            MaximumSize = new Size(460, 0),
        });
        _panel = new BindPanel(() => Binder.DnsNames(item.Cert), item.UsedBy);
        layout.Controls.Add(_panel);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 14, 0, 0) };
        var ok = new Button { Text = "Bind", AutoSize = true, Tag = Theme.ButtonKind.Primary };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) =>
        {
            if (Request.IsEmpty)
            {
                MessageBox.Show(this, "Choose Remote Desktop, an IIS site, or both.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else if (_panel.ValidateFor(this, Text))
            {
                DialogResult = DialogResult.OK;
            }
        };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
        Theme.Apply(this);
        ResumeLayout(false);
        PerformLayout();
    }
}
