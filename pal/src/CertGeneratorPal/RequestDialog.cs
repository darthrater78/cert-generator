using CertGeneratorPal.Core;

namespace CertGeneratorPal;

/// <summary>
/// Confirms a request. Names are already filled in the way a Windows CA would build them;
/// "This computer" can't be edited at all, because the server issues it to the PC's own name.
/// </summary>
internal sealed class RequestDialog : Form
{
    private readonly string _useCase;
    private readonly TextBox? _names;
    private readonly NumericUpDown _lifetime;
    private readonly BindPanel? _bind;

    public Dictionary<string, object> Names { get; private set; } = [];

    public int LifetimeDays => (int)_lifetime.Value;

    /// <summary>Where to use a web server or This computer certificate once installed; null for other kinds or nothing chosen.</summary>
    public BindRequest? Bind => _bind?.Request is { IsEmpty: false } bind ? bind : null;

    public RequestDialog(string useCase, DeviceState state, Policy policy, bool rootTrusted)
    {
        _useCase = useCase;
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        Text = "Request: " + UseCases.Label(useCase);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(16);

        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Fill };
        layout.Controls.Add(new Label { Text = Describe(useCase), AutoSize = true, MaximumSize = new Size(460, 0), Margin = new Padding(0, 0, 0, 10) });

        switch (useCase)
        {
            case UseCases.Computer:
                layout.Controls.Add(new Label
                {
                    Text = $"Issued to: {state.Fqdn}\nThis PC's own name, recorded when it was connected, like a Windows CA's Computer certificate.",
                    AutoSize = true,
                    MaximumSize = new Size(460, 0),
                    Font = new Font(Font, FontStyle.Bold),
                });
                _bind = new BindPanel(() => [state.Fqdn], [], BindingRules.TargetsFor(UseCases.Computer));
                layout.Controls.Add(_bind);
                break;
            case UseCases.WebServer:
                layout.Controls.Add(new Label { Text = "Names (one per line). The first is the main one:", AutoSize = true });
                _names = new TextBox { Multiline = true, Width = 460, Height = 90, ScrollBars = ScrollBars.Vertical, Text = state.Fqdn };
                layout.Controls.Add(_names);
                layout.Controls.Add(Hint("Allowed by your admin: " + string.Join(", ", policy.Dns)));
                _bind = new BindPanel(() => SplitNames(_names.Text), [], BindingRules.TargetsFor(UseCases.WebServer));
                layout.Controls.Add(_bind);
                break;
            case UseCases.User:
                layout.Controls.Add(new Label { Text = "Your sign-in name (UPN):", AutoSize = true });
                _names = new TextBox { Width = 460, Text = LocalIdentity.SuggestedUpn(policy.Users) };
                layout.Controls.Add(_names);
                layout.Controls.Add(Hint("Allowed by your admin: " + string.Join(", ", policy.Users)));
                break;
            default:
                layout.Controls.Add(new Label { Text = "Name in the certificate (who signs):", AutoSize = true });
                _names = new TextBox { Width = 460, Text = LocalIdentity.DisplayName, MaxLength = 64 };
                layout.Controls.Add(_names);
                break;
        }

        var lifetimeRow = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 10, 0, 0) };
        lifetimeRow.Controls.Add(new Label { Text = "Valid for", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 6, 0) });
        int max = Math.Max(1, policy.MaxDays);
        _lifetime = new NumericUpDown { Minimum = 1, Maximum = max, Value = max, Width = 80 };
        lifetimeRow.Controls.Add(_lifetime);
        lifetimeRow.Controls.Add(new Label { Text = $"days (your admin allows up to {max})", AutoSize = true, Margin = new Padding(6, 6, 0, 0) });
        layout.Controls.Add(lifetimeRow);

        if (!rootTrusted)
        {
            string where = UseCases.IsMachine(useCase) || Elevation.IsElevated
                ? "It will be installed in the computer's Trusted Root store together with this certificate."
                : "It will be installed in your Trusted Root store together with this certificate; Windows asks you to confirm.";
            var notice = Hint($"{state.CaName} isn't trusted on this PC yet. {where}");
            notice.ForeColor = Theme.Warning;
            layout.Controls.Add(notice);
        }
        if (policy.Mode(useCase) == "approve")
        {
            layout.Controls.Add(Hint("Your admin approves these. After sending, choose Check again once they have."));
        }

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 14, 0, 0) };
        var ok = new Button { Text = "Request", AutoSize = true, DialogResult = DialogResult.None, Tag = Theme.ButtonKind.Primary };
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
    }

    private static Label Hint(string text) => new()
    {
        Text = text,
        AutoSize = true,
        MaximumSize = new Size(460, 0),
        ForeColor = SystemColors.GrayText,
        Margin = new Padding(0, 4, 0, 0),
    };

    private static string Describe(string useCase) => useCase switch
    {
        UseCases.Computer => "A machine certificate for Wi-Fi, VPN, 802.1X, Remote Desktop and WinRM. Installed in the computer's Personal store.",
        UseCases.WebServer => "A TLS certificate for IIS sites, RD Gateway and other Remote Desktop Services roles, with the extra names they need. Installed in the computer's Personal store.",
        UseCases.User => "A certificate for you: client authentication and smart card logon. Installed in your Personal store.",
        _ => "A code-signing certificate for scripts and programs. Installed in your Personal store.",
    };

    private static List<string> SplitNames(string text) =>
        text.Split(['\r', '\n', ',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private void Accept()
    {
        string text = _names?.Text.Trim() ?? "";
        switch (_useCase)
        {
            case UseCases.Computer:
                Names = [];
                break;
            case UseCases.WebServer:
                var dns = SplitNames(text);
                if (dns.Count == 0)
                {
                    MessageBox.Show(this, "Enter at least one name.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (_bind is not null && !_bind.ValidateFor(this, Text))
                {
                    return;
                }
                Names = new Dictionary<string, object> { ["dns"] = dns };
                break;
            case UseCases.User:
                Names = new Dictionary<string, object> { ["upn"] = text };
                break;
            default:
                Names = new Dictionary<string, object> { ["cn"] = text };
                break;
        }
        if (_useCase != UseCases.Computer && text.Length == 0)
        {
            MessageBox.Show(this, "Enter a name.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        DialogResult = DialogResult.OK;
    }
}
