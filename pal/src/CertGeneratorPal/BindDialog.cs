using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>
/// Bind… on a certificate in the computer's Personal store: one row per role, each saying where it
/// stands (in use by this certificate, needs the admin's approval, not allowed, not on this PC, or
/// the certificate's names don't fit). Ticked roles are asked of the server and then bound; a role
/// in use can be removed where Windows can run without it.
/// </summary>
internal sealed class BindDialog : Form
{
    public const string HelpUrl = "https://github.com/darthrater78/cert-generator#binding-a-certificate";
    private const string AllNames = "Every name (no SNI)";
    private const int TextWidth = 480;

    private readonly CheckBox _rdp = new() { Text = "Remote Desktop", AutoSize = true };
    private readonly CheckBox _winRm = new() { Text = "WinRM over HTTPS (PowerShell remoting)", AutoSize = true };
    private readonly CheckBox _iis = new() { Text = "IIS site", AutoSize = true };
    private readonly CheckBox _gateway = new() { Text = "RD Gateway", AutoSize = true };
    private readonly CheckBox _publishing = new() { Text = "RD Connection Broker: sign RDP files", AutoSize = true };
    private readonly CheckBox _redirector = new() { Text = "RD Connection Broker: single sign-on", AutoSize = true };
    private readonly ComboBox _site = new() { Width = 200 };
    private readonly NumericUpDown _port = new() { Minimum = 1, Maximum = 65535, Value = 443, Width = 70 };
    private readonly ComboBox _host = new() { Width = 200, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _note = new() { Width = TextWidth, MaxLength = 200 };
    private readonly List<string> _names;

    /// <summary>The roles ticked, to ask the server for and then bind.</summary>
    public BindRequest Request => new()
    {
        Rdp = _rdp.Checked,
        WinRm = _winRm.Checked,
        RdGateway = _gateway.Checked,
        RdPublishing = _publishing.Checked,
        RdRedirector = _redirector.Checked,
        IisSite = _iis.Checked ? _site.Text.Trim() : null,
        Port = (int)_port.Value,
        Host = _host.SelectedItem is string h && h != AllNames ? h : "",
    };

    public string? Note => _note.Text.Trim() is { Length: > 0 } note ? note : null;

    /// <summary>Set when a role's Remove was chosen instead of Bind: the role to take this certificate out of.</summary>
    public string? RemoveTarget { get; private set; }

    /// <param name="waiting">Roles with a bind for this certificate already waiting for the admin.</param>
    public BindDialog(AuditItem item, Policy policy, string fqdn, IReadOnlyCollection<string> waiting)
    {
        _names = Binder.DnsNames(item.Cert);
        var fits = BindingRules.TargetsFor(_names, fqdn);
        var inUse = item.UsedBy.Select(Binder.TargetOf).OfType<string>().ToHashSet();

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
            Text = $"A certificate does nothing for a Windows service until that service is told to use it. Tick what should use {item.Names} " +
                   $"(expires {item.Cert.NotAfter:d MMM yyyy}). When the Pal renews it, everything bound here moves to the new certificate.",
            AutoSize = true,
            MaximumSize = new Size(TextWidth, 0),
        });
        var help = new LinkLabel { Text = "What does binding do?", AutoSize = true, Margin = new Padding(3, 4, 0, 8) };
        help.LinkClicked += (_, _) => MainForm.OpenUrl(HelpUrl);
        layout.Controls.Add(help);

        AddRole(layout, BindKeys.Rdp, [_rdp], null,
            "Connections to this PC show this certificate instead of a self-signed one.",
            "Remote Desktop goes back to Windows' own self-signed certificate.");
        AddRole(layout, BindKeys.WinRm, [_winRm], null,
            "Adds an HTTPS listener on port 5986, or switches the existing one to this certificate. WinRM must already be on; Windows Firewall isn't changed.",
            "The HTTPS listener is removed. WinRM over HTTP, if it is on, is unchanged.");
        AddRole(layout, BindKeys.Iis, [_iis], Binder.Iis.IsInstalled ? null : "IIS isn't installed on this PC.",
            "The site's https binding is added if it has none; an existing one switches to this certificate.",
            "Every HTTPS binding that serves this certificate is removed, on the site and in Windows.", IisRows());
        AddRole(layout, BindKeys.RdGateway, [_gateway], Binder.RdGateway.IsInstalled ? null : "This PC doesn't run RD Gateway.",
            "Restarts the RD Gateway service: people connected through it are disconnected.", null);
        AddRole(layout, BindKeys.RdBroker, [_publishing, _redirector], Binder.RdBroker.IsInstalled ? null : "This PC isn't an RD Connection Broker.",
            "For RD Web Access, bind its IIS site above.", null);

        layout.Controls.Add(new Label { Text = "Note for your admin (optional):", AutoSize = true, Margin = new Padding(3, 10, 0, 0) });
        layout.Controls.Add(_note);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 14, 0, 0) };
        var ok = new Button { Text = "Bind", AutoSize = true, Tag = Theme.ButtonKind.Primary };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => Accept();
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
        Theme.Apply(this);
        ResumeLayout(false);
        PerformLayout();

        // One role's rows: its tick boxes, where it stands, what binding it does, and Remove when it is in use.
        void AddRole(TableLayoutPanel to, string key, CheckBox[] boxes, string? notHere, string what, string? removeEffect, Control? extra = null)
        {
            string mode = policy.BindMode(key);
            bool nameFits = fits.HasFlag(BindingRules.Flag(key));
            bool isWaiting = waiting.Contains(key);
            bool used = inUse.Contains(key);
            string? blocked = notHere
                ?? (mode == "off" ? "Your admin hasn't allowed this for this PC." : null)
                ?? (!nameFits ? $"This answers to the PC's own name ({fqdn}), which this certificate doesn't carry." : null)
                ?? (isWaiting ? "Already waiting for your admin. Choose Check again in the main window once they have approved it." : null);

            var head = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 0) };
            foreach (var box in boxes)
            {
                box.Enabled = blocked is null;
                box.Margin = new Padding(3, 3, 8, 0);
            }
            head.Controls.Add(boxes[0]);
            if (used)
            {
                head.Controls.Add(Chip("In use", Theme.Success));
            }
            if (blocked is null && mode == "approve")
            {
                head.Controls.Add(Chip("Needs approval", Theme.Warning));
            }
            else if (blocked is not null)
            {
                head.Controls.Add(Chip(notHere is not null ? "Not on this PC" : mode == "off" ? "Not allowed" : isWaiting ? "Waiting" : "Name doesn't fit", Theme.TextDim));
            }
            to.Controls.Add(head);
            foreach (var more in boxes.Skip(1))
            {
                to.Controls.Add(more);
            }
            to.Controls.Add(Hint(blocked ?? (used ? "This certificate serves it now. " : "") + what
                + (blocked is null && mode == "approve" ? " Your admin approves this one before it happens." : "")));
            if (extra is not null && blocked is null)
            {
                to.Controls.Add(extra);
            }
            if (used && removeEffect is not null)
            {
                var remove = new Button { Text = "Remove this bind", AutoSize = true, Tag = Theme.ButtonKind.Danger, Margin = new Padding(21, 2, 0, 4) };
                remove.Click += (_, _) =>
                {
                    if (MessageBox.Show(this, $"Stop {BindKeys.Label(key)} using this certificate?\n\n{removeEffect}", Text,
                            MessageBoxButtons.OKCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.OK)
                    {
                        RemoveTarget = key;
                        DialogResult = DialogResult.OK;
                    }
                };
                to.Controls.Add(remove);
            }
            else if (used)
            {
                to.Controls.Add(Hint("It can't run without a certificate: to change it, bind another certificate to it."));
            }
        }
    }

    private FlowLayoutPanel IisRows()
    {
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
        _host.Items.Add(AllNames);
        _host.Items.AddRange([.. _names.Where(BindingRules.IsValidHost).Distinct(StringComparer.OrdinalIgnoreCase)]);
        _host.SelectedItem = AllNames;
        var row = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(18, 0, 0, 4) };
        row.Controls.AddRange([Caption("Site"), _site, Caption("Port"), _port, Caption("Name"), _host]);
        _iis.CheckedChanged += (_, _) => _site.Enabled = _port.Enabled = _host.Enabled = _iis.Checked;
        _site.Enabled = _port.Enabled = _host.Enabled = false;
        return row;
    }

    private void Accept()
    {
        var request = Request;
        if (request.IsEmpty)
        {
            MessageBox.Show(this, "Tick at least one use.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        try
        {
            BindingRules.Validate(request, _names);  // before any administrator prompt
        }
        catch (PalException e)
        {
            MessageBox.Show(this, e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        DialogResult = DialogResult.OK;
    }

    private static Label Caption(string text) => new() { Text = text, AutoSize = true, Margin = new Padding(3, 6, 4, 0) };

    private static Label Chip(string text, Color color) => new()
    {
        Text = text.ToUpperInvariant(),
        AutoSize = true,
        Font = Theme.MonoSmall,
        ForeColor = color,
        Margin = new Padding(0, 6, 8, 0),
    };

    private static Label Hint(string text) => new()
    {
        Text = text,
        AutoSize = true,
        MaximumSize = new Size(TextWidth - 20, 0),
        ForeColor = SystemColors.GrayText,
        Margin = new Padding(21, 0, 0, 2),
    };
}
