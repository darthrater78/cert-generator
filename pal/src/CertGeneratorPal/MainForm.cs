using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

internal sealed class MainForm : Form
{
    private const string RepoUrl = "https://github.com/darthrater78/cert-generator";
    private const string HelpUrl = RepoUrl + "#using-the-pal";
    private const string TroubleshootingUrl = RepoUrl + "#troubleshooting";
    private static readonly string Version = PalClient.AppVersion;
    private static readonly string ReleaseNotesUrl = RepoUrl + "/releases/tag/v" + Version;

    private const string TrustTile = "trust";
    private const string CrlTile = "crl";
    private static readonly Dictionary<string, string> TileSubtitles = new()
    {
        [UseCases.Computer] = "Wi-Fi, VPN, 802.1X, device identity",
        [UseCases.WebServer] = "Other names: sites, aliases, gateways",
        [UseCases.User] = "You: Wi-Fi, VPN and websites",
        [UseCases.CodeSigning] = "Scripts and programs",
        [TrustTile] = "Trust the CA for HTTPS inspection",
        [CrlTile] = "Answer revocation checks on this PC",
    };

    private readonly SealControl _seal = new();
    private readonly Label _subtitle = new() { AutoSize = true, Font = Theme.SerifItalic, ForeColor = SystemColors.GrayText, Margin = new Padding(0, 2, 0, 10) };
    private readonly Panel _connectPanel = new() { Dock = DockStyle.Fill };
    private readonly TextBox _codeBox = new() { Multiline = true, Height = 90, Anchor = AnchorStyles.Left | AnchorStyles.Right, ScrollBars = ScrollBars.Vertical };
    private readonly Label _pcName = new() { AutoSize = true, Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(0, 0, 0, 10) };
    private readonly Button _connectButton = new() { Text = "Connect", AutoSize = true, Tag = Theme.ButtonKind.Primary };
    private readonly TableLayoutPanel _mainPanel = new() { Dock = DockStyle.Fill, ColumnCount = 1 };
    private readonly FlowLayoutPanel _tiles = new() { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true };
    private readonly Dictionary<string, TileButton> _tileButtons = [];
    private readonly FlowLayoutPanel _pendingBar = new() { AutoSize = true, Dock = DockStyle.Fill, Visible = false };
    private readonly Label _pendingLabel = new() { AutoSize = true, Margin = new Padding(0, 9, 8, 0), ForeColor = Theme.Warning };
    private readonly Label _listTitle = new() { AutoSize = true, Font = Theme.Heading, Margin = new Padding(0, 14, 0, 6) };
    private readonly ListView _list = new()
    {
        View = View.Details, FullRowSelect = true, Dock = DockStyle.Fill, MultiSelect = true, HideSelection = false,
        OwnerDraw = true, BorderStyle = BorderStyle.FixedSingle, HeaderStyle = ColumnHeaderStyle.Clickable,
    };
    // Column widths at 96 DPI; Notes, the last column, takes the rest.
    private static readonly (string Title, int Width)[] ListColumns =
        [("Certificate", 220), ("Use", 150), ("Store", 130), ("Key", 80), ("Expires", 95), ("Renew", 95), ("Status", 80)];
    private const int ElasticColumns = 3;  // Certificate, Use and Store give way in a narrow window; the short ones keep their width
    private const int NotesMinWidth = 120;
    private readonly int[] _columnWidths = ListColumns.Select(c => c.Width).ToArray();
    private bool _fitting;
    private bool _fitPending;
    private const int ListMinHeight = 150;  // the heading and about five rows, at 96 DPI
    private bool _listRoomChecked;
    private ILookup<string, string> _waitingBinds = Enumerable.Empty<string>().ToLookup(t => t);
    private int _sortColumn = -1;  // none: CA certificates last, then by store and name
    private bool _sortDescending;
    private readonly Button _renew = new() { Text = "Renew", AutoSize = true, Enabled = false };
    private readonly Button _remove = new() { Text = "Remove", AutoSize = true, Enabled = false, Tag = Theme.ButtonKind.Danger };
    private readonly Button _revoke = new() { Text = "Revoke", AutoSize = true, Enabled = false, Tag = Theme.ButtonKind.Danger };
    private readonly Button _details = new() { Text = "Details", AutoSize = true, Enabled = false };
    private readonly Button _bind = new() { Text = "Bind…", AutoSize = true, Enabled = false };
    private string? _deviceKeyStorage;  // where this PC's device key lives, once a refresh has read it
    private readonly Button _refresh = new() { Text = "Refresh", AutoSize = true };
    private readonly Label _status = new()
    {
        Dock = DockStyle.Bottom, AutoSize = false, Height = 26, TextAlign = ContentAlignment.MiddleLeft,
        Padding = new Padding(16, 0, 16, 0), BackColor = Theme.Surface, ForeColor = Theme.TextDim, Font = Theme.Mono,
        AutoEllipsis = true,
    };
    private readonly LinkLabel _disconnect = new() { Text = "Disconnect this PC", AutoSize = true, Visible = false };
    private readonly ComboBox _profileBox = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 460, FlatStyle = FlatStyle.Flat, Margin = new Padding(0, 0, 8, 0) };
    private readonly FlowLayoutPanel _profileRow = new() { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 6), Visible = false };
    private readonly TableLayoutPanel _crlPanel = new() { AutoSize = true, ColumnCount = 4, Margin = new Padding(0, 0, 0, 8), Visible = false };
    private readonly LinkLabel _drift = new() { AutoSize = true, Visible = false, Margin = new Padding(0, 0, 0, 8) };
    private bool _fillingProfiles;
    private readonly ToolTip _crlTip = new();

    /// <summary>The last check of each revocation type's address, by type.</summary>
    private Dictionary<string, CrlCheck.Result> _crlResults = [];
    private CrlCheck.Result? _serverCheck;   // over the LAN
    private CrlCheck.Result? _remoteCheck;   // through the relay

    /// <summary>One CRL profile: a pairing with one of the revocation types its code allowed.</summary>
    private sealed record ProfileChoice(DeviceState Pairing, string CrlDp)
    {
        public override string ToString() => CrlDp.Length == 0
            ? "None: pick a CRL profile"
            : $"{Pairing.CaName}  ·  {CrlTypes.Label(CrlDp)}  ·  {Pairing.ServerUri.Host}";
    }

    private DeviceState? _state;
    private DeviceInfo? _device;
    private Dictionary<string, bool> _crlAnswering = [];
    private List<AuditItem> _items = [];
    private bool _busy;

    public MainForm()
    {
        SuspendLayout();
        // Sizes below are at 96 DPI; WinForms scales them for the display (fixes clipping at 125-150%).
        AutoScaleDimensions = new SizeF(96F, 96F);
        Text = "Cert Generator Pal";
        Icon = Icon.ExtractAssociatedIcon(Environment.ProcessPath!);
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(1040, 720);
        MinimumSize = new Size(720, 520);
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(16, 12, 16, 8) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        // The app's masthead: mono eyebrow, serif title, italic subtitle, strong rule.
        // The CA's seal sits in the upper right, beside the first four rows; the rest span the full width.
        var header = new TableLayoutPanel { ColumnCount = 2, RowCount = 7, AutoSize = true, Dock = DockStyle.Fill };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        header.Controls.Add(Theme.Eyebrow("Certificate authority · Windows companion"), 0, 0);
        header.Controls.Add(new Label { Text = "Cert Generator Pal", AutoSize = true, Font = Theme.Display, Margin = new Padding(0) }, 0, 1);
        header.Controls.Add(_subtitle, 0, 2);
        var profileLabel = Theme.Eyebrow("CRL profile");
        profileLabel.Margin = new Padding(0, 8, 8, 0);
        _profileRow.Controls.AddRange([profileLabel, _profileBox]);
        _profileBox.SelectedIndexChanged += async (_, _) => await ProfileChosenAsync();
        header.Controls.Add(_profileRow, 0, 3);
        _seal.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        header.Controls.Add(_seal, 1, 0);
        header.SetRowSpan(_seal, 4);
        header.Controls.Add(_crlPanel, 0, 4);
        header.SetColumnSpan(_crlPanel, 2);
        _drift.LinkClicked += (_, _) => OpenServerDownload();
        header.Controls.Add(_drift, 0, 5);
        header.SetColumnSpan(_drift, 2);
        var rule = Theme.RuleLine();
        rule.Dock = DockStyle.None;
        rule.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        header.Controls.Add(rule, 0, 6);
        header.SetColumnSpan(rule, 2);
        root.Controls.Add(header);

        BuildConnectPanel();
        BuildMainPanel();
        var content = new Panel { Dock = DockStyle.Fill };
        content.Controls.Add(_mainPanel);
        content.Controls.Add(_connectPanel);
        root.Controls.Add(content);
        root.Controls.Add(BuildFooter());

        Controls.Add(root);
        Controls.Add(_status);
        Theme.Apply(this);
        Shown += async (_, _) => await LoadStateAsync();
        ResumeLayout(false);
        PerformLayout();
    }

    // ── Layout ──────────────────────────────────────────────────────

    private void BuildConnectPanel()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Label Wrapping(string text, Color? color = null, Padding? margin = null) => new()
        {
            Text = text,
            AutoSize = true,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,  // wraps to the window width
            ForeColor = color ?? SystemColors.ControlText,
            Margin = margin ?? new Padding(0, 0, 0, 8),
        };
        layout.Controls.Add(Wrapping("Connect this PC to your Cert Generator.\n\n" +
            "1. In Cert Generator, open Windows PCs and choose Add a PC.\n" +
            "2. Copy the pairing code and paste it here.\n" +
            "3. Choose Connect. Windows asks for administrator approval once, to trust your CA.", margin: new Padding(0, 6, 0, 10)));
        layout.Controls.Add(_pcName);

        var codeHeader = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        codeHeader.Controls.Add(new Label { Text = "Pairing code", AutoSize = true, Margin = new Padding(0, 7, 8, 0) });
        var paste = new Button { Text = "Paste", AutoSize = true, Margin = new Padding(0, 0, 0, 4) };
        paste.Click += (_, _) =>
        {
            try
            {
                if (Clipboard.ContainsText())
                {
                    _codeBox.Text = Clipboard.GetText().Trim();
                }
            }
            catch (System.Runtime.InteropServices.ExternalException)
            {
                SetStatus("Couldn't read the clipboard (another program has it open). Paste with Ctrl+V instead.");
            }
        };
        codeHeader.Controls.Add(paste);
        layout.Controls.Add(codeHeader);
        _codeBox.Font = Theme.Mono;
        _codeBox.BorderStyle = BorderStyle.FixedSingle;
        layout.Controls.Add(_codeBox);
        _connectButton.Margin = new Padding(0, 10, 0, 0);
        _connectButton.Click += async (_, _) => await ConnectAsync();
        layout.Controls.Add(_connectButton);
        layout.Controls.Add(Wrapping("LAN only: Cert Generator Pal talks to your server on your local network (or a private overlay such as Tailscale or Zscaler) and nowhere else. " +
            "Keys are created on this PC and never leave it.", SystemColors.GrayText, new Padding(0, 14, 0, 0)));
        _connectPanel.Controls.Add(layout);
    }

    /// <summary>The name this PC will connect as: the admin's allowed DNS names must include it.</summary>
    private async Task ShowPcNameAsync()
    {
        _pcName.Text = "This PC's name: checking…";
        string fqdn = await Task.Run(() => LocalIdentity.Fqdn());
        _pcName.Text = fqdn.Contains('.', StringComparison.Ordinal)
            ? $"This PC connects as {fqdn}. The pairing code must allow it, e.g. *.{fqdn[(fqdn.IndexOf('.', StringComparison.Ordinal) + 1)..]}"
            : $"This PC's name is just {fqdn}, with no DNS suffix. Set the PC's primary DNS suffix (System › About › Rename / domain settings) before connecting.";
    }

    private void BuildMainPanel()
    {
        _mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _mainPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        _mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        foreach (string tile in UseCases.All.Append(TrustTile).Append(CrlTile))
        {
            var button = new TileButton
            {
                Text = tile switch { TrustTile => "TLS inspection", CrlTile => "Endpoint-hosted CRL", _ => UseCases.Label(tile) },
                Subtitle = TileSubtitles[tile],
            };
            button.Click += async (_, _) =>
            {
                if (tile == TrustTile)
                {
                    await TrustAsync();
                }
                else if (tile == CrlTile)
                {
                    await LocalCrlAsync();
                }
                else
                {
                    await RequestAsync(tile);
                }
            };
            _tileButtons[tile] = button;
            _tiles.Controls.Add(button);
        }
        // Every control gets an explicit row: a hidden control gives up its cell otherwise, and the
        // rows below shift into the wrong sizing (the list stuck small, the buttons stretched).
        _mainPanel.RowCount = 5;
        _mainPanel.Controls.Add(_tiles, 0, 0);

        var checkAgain = new Button { Text = "Check again", AutoSize = true, Tag = Theme.ButtonKind.Primary };
        checkAgain.Click += async (_, _) => await CollectAsync();
        _pendingBar.Controls.Add(_pendingLabel);
        _pendingBar.Controls.Add(checkAgain);
        _mainPanel.Controls.Add(_pendingBar, 0, 1);

        _mainPanel.Controls.Add(_listTitle, 0, 2);
        foreach (var (title, width) in ListColumns)
        {
            _list.Columns.Add(title, width);
        }
        _list.Columns.Add("Notes", NotesMinWidth);
        _list.SelectedIndexChanged += (_, _) => UpdateActions();
        _list.Resize += (_, _) => FitColumnsSoon();
        _list.ColumnWidthChanged += (_, e) => ColumnDragged(e.ColumnIndex);
        _list.ColumnClick += (_, e) => SortBy(e.Column);
        _list.DrawColumnHeader += DrawHeader;
        _list.DrawItem += (_, e) => e.DrawDefault = false;
        _list.DrawSubItem += DrawCell;
        _list.DoubleClick += (_, _) => ShowDetails();
        _mainPanel.Controls.Add(_list, 0, 3);

        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
        _renew.Click += async (_, _) => await RenewAsync();
        _remove.Click += async (_, _) => await RemoveAsync(revokeOnly: false);
        _revoke.Click += async (_, _) => await RemoveAsync(revokeOnly: true);
        _details.Click += (_, _) => ShowDetails();
        _bind.Click += async (_, _) => await BindAsync();
        _refresh.Click += async (_, _) => await RefreshAsync();
        actions.Controls.AddRange([_renew, _bind, _revoke, _remove, _details, _refresh]);
        _mainPanel.Controls.Add(actions, 0, 4);
    }

    /// <summary>
    /// The columns always add up to the list's width: Notes takes what is left, and in a narrow
    /// window the others shrink in proportion. The list therefore never scrolls sideways, which
    /// also keeps Windows from leaving its contents shifted after the window or a column is resized.
    /// </summary>
    private void FitColumns()
    {
        if (_fitting || _list.Columns.Count != _columnWidths.Length + 1 || _list.ClientSize.Width <= 0)
        {
            return;
        }
        _fitting = true;
        try
        {
            int room = _list.ClientSize.Width - SystemInformation.VerticalScrollBarWidth;
            int rigid = _columnWidths.Skip(ElasticColumns).Sum(w => LogicalToDeviceUnits(w));
            int elastic = _columnWidths.Take(ElasticColumns).Sum(w => LogicalToDeviceUnits(w));
            double scale = Math.Min(1.0, (double)Math.Max(0, room - LogicalToDeviceUnits(NotesMinWidth) - rigid) / Math.Max(1, elastic));
            int used = 0;
            _list.BeginUpdate();
            for (int i = 0; i < _columnWidths.Length; i++)
            {
                int width = Math.Max(LogicalToDeviceUnits(24), (int)(LogicalToDeviceUnits(_columnWidths[i]) * (i < ElasticColumns ? scale : 1.0)));
                _list.Columns[i].Width = width;
                used += width;
            }
            _list.Columns[^1].Width = Math.Max(LogicalToDeviceUnits(24), room - used);
            _list.EndUpdate();
        }
        finally
        {
            _fitting = false;
        }
    }

    /// <summary>Refit once the list has finished resizing: changing a column's width while Windows is still sizing the list can leave it shifted.</summary>
    private void FitColumnsSoon()
    {
        if (IsHandleCreated && !_fitPending)
        {
            _fitPending = true;
            BeginInvoke(() =>
            {
                _fitPending = false;
                FitColumns();
            });
        }
    }

    /// <summary>The user dragged a column's edge: keep that width (at 96 DPI) and give Notes what is left.</summary>
    private void ColumnDragged(int column)
    {
        if (_fitting || column < 0 || column >= _columnWidths.Length)
        {
            return;
        }
        _columnWidths[column] = Math.Max(24, _list.Columns[column].Width * 96 / Math.Max(96, DeviceDpi));
        FitColumnsSoon();
    }

    private TableLayoutPanel BuildFooter()
    {
        var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true, Margin = new Padding(0, 8, 0, 0) };
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var links = new LinkLabel { AutoSize = true, Text = $"v{Version}  ·  Help  ·  Troubleshooting  ·  GitHub  ·  Release notes" };
        links.Links.Clear();
        foreach (var (word, url) in new[] { ("Help", HelpUrl), ("Troubleshooting", TroubleshootingUrl), ("GitHub", RepoUrl), ("Release notes", ReleaseNotesUrl) })
        {
            links.Links.Add(links.Text.IndexOf(word, StringComparison.Ordinal), word.Length, url);
        }
        links.LinkClicked += (_, e) => OpenUrl((string)e.Link!.LinkData!);
        footer.Controls.Add(links);
        _disconnect.LinkClicked += async (_, _) => await DisconnectAsync();
        footer.Controls.Add(_disconnect);
        return footer;
    }

    /// <summary>Opens https links only, via explorer.exe so a browser never inherits elevation.</summary>
    internal static void OpenUrl(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps && uri.Host == "github.com")
        {
            string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            Process.Start(new ProcessStartInfo(explorer, "\"" + uri.AbsoluteUri + "\"") { UseShellExecute = false })?.Dispose();
        }
    }

    /// <summary>The Pal ships with the server and carries its version: a different one may not match its features.</summary>
    private void UpdateDrift()
    {
        string server = _device?.ServerVersion ?? "";
        _drift.Visible = _state is not null && server.Length > 0 && server != Version;
        if (!_drift.Visible)
        {
            return;
        }
        const string link = "Download the matching Pal";
        _drift.Text = $"⚠ This Pal is v{Version}; your server is v{server}, so features may not match. {link}";
        _drift.ForeColor = Theme.Warning;
        _drift.LinkColor = _drift.ActiveLinkColor = _drift.VisitedLinkColor = Theme.AccentText;
        _drift.Links.Clear();
        _drift.Links.Add(_drift.Text.Length - link.Length, link.Length);
    }

    /// <summary>The Pal that shipped with the paired server, from that server only.</summary>
    private void OpenServerDownload()
    {
        if (_state is null || !Uri.TryCreate(_state.ServerUri, "/pal/CertGeneratorPal.exe", out var uri)
            || uri.Host != _state.ServerUri.Host || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return;
        }
        string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        Process.Start(new ProcessStartInfo(explorer, "\"" + uri.AbsoluteUri + "\"") { UseShellExecute = false })?.Dispose();
    }

    // ── State ───────────────────────────────────────────────────────

    private async Task LoadStateAsync()
    {
        _state = DeviceState.Load();
        FillProfiles();
        if (_state is null)
        {
            ShowConnect();
            _subtitle.Text = _profileBox.Items.Count > 0 ? "No active CRL profile: pick one above" : "Not connected";
            _seal.SetCa(null, null);
            await ShowPcNameAsync();
            return;
        }
        _connectPanel.Visible = false;
        _mainPanel.Visible = true;
        _disconnect.Visible = true;
        _subtitle.Text = $"Connected to {_state.ServerUri.Host} · {_state.CaName} · this PC: {_state.Fqdn}";
        _seal.SetCa(_state.CaName, SealControl.DomainOf(_state.Fqdn));
        _listRoomChecked = false;  // another profile can mean more connectivity rows and tiles
        _listTitle.Text = $"Certificates from {_state.CaName} on this PC";
        await RefreshAsync();
    }

    private void ShowConnect()
    {
        _connectPanel.Visible = true;
        _mainPanel.Visible = false;
        _disconnect.Visible = false;
        _crlPanel.Visible = false;
        _drift.Visible = false;
        SetStatus("Paste a pairing code to connect this PC.");
        _codeBox.Focus();
    }

    /// <summary>Every (pairing, allowed revocation type), the active one selected.</summary>
    private void FillProfiles()
    {
        _fillingProfiles = true;
        _profileBox.Items.Clear();
        if (_state is { CrlDp.Length: 0 })
        {
            var none = new ProfileChoice(_state, "");
            _profileBox.Items.Add(none);
            _profileBox.SelectedItem = none;
        }
        foreach (var pairing in DeviceState.LoadAll())
        {
            var allowed = pairing.CrlDps.Count > 0 ? pairing.CrlDps : [pairing.CrlDp.Length > 0 ? pairing.CrlDp : "server"];
            if (_state is { CrlDp.Length: > 0 } && pairing.DeviceId == _state.DeviceId && !allowed.Contains(_state.CrlDp))
            {
                allowed = [.. allowed, _state.CrlDp];  // in use, though the admin no longer allows it: still shown
            }
            foreach (string crl in allowed)
            {
                var choice = new ProfileChoice(pairing, crl);
                _profileBox.Items.Add(choice);
                if (_state is not null && pairing.DeviceId == _state.DeviceId && crl == _state.CrlDp)
                {
                    _profileBox.SelectedItem = choice;
                }
            }
        }
        _profileRow.Visible = _profileBox.Items.Count > 0;
        _fillingProfiles = false;
    }

    private async Task ProfileChosenAsync()
    {
        if (_fillingProfiles || _profileBox.SelectedItem is not ProfileChoice choice || choice.CrlDp.Length == 0
            || (_state is not null && choice.Pairing.DeviceId == _state.DeviceId && choice.CrlDp == _state.CrlDp))
        {
            return;
        }
        var lines = _items.Where(i => i.FromPal is not null && !i.IsCa).Select(i => $"• {i.Names}  ({i.UseLabel}, {i.StoreLabel})"
            + (i.UsedBy.Count > 0 ? $" ⚠ used by {string.Join(", ", i.UsedBy)}: request and bind a new one afterwards" : "")).ToList();
        if (_state?.CrlDp == "placeholder")
        {
            lines.Add("• the endpoint-hosted CRL listener");
        }
        bool first = _state is null || _state.CrlDp.Length == 0;  // nothing picked yet: nothing to back out
        string backOut = first ? "" : lines.Count == 0
            ? "\n\nNothing from the current CRL profile is installed, so nothing is removed."
            : $"\n\nThe current CRL profile is backed out. Removed from this PC:\n{string.Join("\n", lines.Take(12))}"
              + (lines.Count > 12 ? $"\n• …and {lines.Count - 12} more" : "") + "\n\nThe root CA stays trusted.";
        string extra = choice.CrlDp == "placeholder" ? "\n\nThe endpoint-hosted CRL listener is set up for the new CRL profile." : "";
        if (MessageBox.Show(this, (first ? $"Use {choice}?\n\nThis PC's certificates will check revocation there." : $"Switch to {choice}?")
                + $"{backOut}{extra}", first ? "Pick CRL profile" : "Switch CRL profile", MessageBoxButtons.OKCancel,
                MessageBoxIcon.Question) != DialogResult.OK || !BeginBusy("Switching CRL profile… approve the Windows prompt."))
        {
            FillProfiles();  // put the selection back
            return;
        }
        try
        {
            Report(await Elevation.RunAsync(new HelperOp { Op = "switch", DeviceId = choice.Pairing.DeviceId, CrlDp = choice.CrlDp }));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await LoadStateAsync();
    }

    /// <summary>Check the CRL profile in use: does its CRL address answer?</summary>
    private async Task CheckCrlsAsync()
    {
        _crlResults = [];
        if (_device is null || _state is null || !_device.CrlUrls.TryGetValue(_state.CrlDp, out string? url))
        {
            return;
        }
        _crlResults[_state.CrlDp] = await CrlCheck.TestAsync(url, _state.CrlDp == "placeholder");
    }

    /// <summary>Switching CRL profile talks to the server (and backs certificates out): locked while it can't be reached.</summary>
    private void UpdateProfileLock()
    {
        bool reachable = _state is null || ServerReachable;  // no active pairing: nothing to check yet
        _profileBox.Enabled = reachable && !_busy;
        _crlTip.SetToolTip(_profileBox, reachable ? "" : "Locked: the cert server can't be reached. Check Connectivity below, then Refresh.");
    }

    /// <summary>
    /// Connectivity: the cert server, then the CRL profile in use (none until one is picked). Each row has a
    /// status dot, what the last check found, and a Test link.
    /// </summary>
    private void FillCrlPanel()
    {
        _crlPanel.SuspendLayout();
        foreach (Control c in _crlPanel.Controls.Cast<Control>().ToList())
        {
            c.Dispose();
        }
        _crlPanel.Controls.Clear();
        _crlPanel.RowStyles.Clear();
        _crlPanel.RowCount = 0;
        if (_state is null)
        {
            _crlPanel.Visible = false;
            _crlPanel.ResumeLayout();
            return;
        }
        var heading = Theme.Eyebrow("Connectivity");
        heading.Margin = new Padding(0, 2, 16, 4);
        _crlPanel.Controls.Add(heading, 0, 0);
        var tools = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        tools.Controls.Add(PanelLink("Refresh", "Check the cert server and CRL again", async () => await RecheckAsync()));
        if (_state.Relay is not null)
        {
            bool forced = Connectivity.Route == PalRoute.Relay;
            tools.Controls.Add(PanelLink(forced ? "Use direct first" : "Connect to remote",
                forced ? "Go back to the direct connection first, the relay only when it can't be reached"
                       : "Use only the remote relay for now (to test it, or when the LAN shouldn't be used)",
                async () =>
                {
                    Connectivity.Route = forced ? PalRoute.Auto : PalRoute.Relay;
                    AppLog.Info("Route: " + Connectivity.Route);
                    await RecheckAsync();
                }));
        }
        if (_device is not null && (_device.CrlUrls.ContainsKey("server") || _device.CrlUrls.ContainsKey("cloudflare")))
        {
            tools.Controls.Add(PanelLink("Publish CRL now", "Have the server sign its CRL again and publish it now (here and to its Cloudflare Worker)",
                async () => await PublishCrlAsync()));
        }
        tools.Controls.Add(PanelLink("Log", "Show the Pal's log, and turn debug logging on or off", () =>
        {
            using var log = new LogDialog();
            log.ShowDialog(this);
            return Task.CompletedTask;
        }));
        _crlPanel.Controls.Add(tools, 1, 0);
        _crlPanel.SetColumnSpan(tools, 3);

        string serverUrl = _state.ServerUri.GetLeftPart(UriPartial.Authority);
        int row = 1;
        bool remoteOnly = Connectivity.Route == PalRoute.Relay;
        if (remoteOnly)
        {
            AddStatusRow(row++, "Cert server · Direct", serverUrl, new CrlCheck.Result(true, "Not used: connected to remote", ""), null, neutral: true);
        }
        else
        {
            AddStatusRow(row++, "Cert server · Direct", serverUrl, _serverCheck, async () => await TestServerAsync(PalRoute.Lan));
        }
        if (_state.Relay is { } relayInfo)
        {
            AddStatusRow(row++, "Cert server · Remote", relayInfo.Url, _remoteCheck, async () => await TestServerAsync(PalRoute.Relay));
        }
        row = AddCrlRows(row);
        if (_deviceKeyStorage is { } keyStorage)
        {
            bool tpm = keyStorage == "tpm";
            AddStatusRow(row++, "Key storage", null, new CrlCheck.Result(tpm,
                tpm ? "TPM  ·  keys the Pal makes can't be exported or copied off this PC"
                    : "Software key store  ·  this PC has no usable TPM; keys are non-exportable, but an administrator here can extract them", ""),
                null, neutral: !tpm);
        }
        _crlPanel.RowCount = row;
        _crlPanel.Visible = true;
        _crlPanel.ResumeLayout();
        UpdateProfileLock();
    }

    /// <summary>The CRL profile in use, then the CRLs this server and its Cloudflare Worker publish; the next free row.</summary>
    private int AddCrlRows(int row)
    {
        if (_state is null)
        {
            return row;
        }
        if (_state.CrlDp.Length > 0)
        {
            string type = _state.CrlDp;
            string? url = _device?.CrlUrls.GetValueOrDefault(type);
            _crlResults.TryGetValue(type, out var result);
            string label = "CRL · " + CrlTypes.Label(type);
            if (type == "none")
            {
                AddStatusRow(row, label, null, new CrlCheck.Result(true, "No revocation checks", ""), null, neutral: true);
            }
            else
            {
                AddStatusRow(row, label, url, result, url is null ? null : async () => await TestCrlAsync(type, url));
            }
            if (type == "placeholder" && result is { Ok: false })
            {
                var repair = new LinkLabel { Text = "Repair", AutoSize = true, Margin = new Padding(0, 2, 0, 2) };
                repair.LinkColor = repair.ActiveLinkColor = repair.VisitedLinkColor = Theme.AccentText;
                repair.LinkClicked += async (_, _) => await RepairAsync();
                _crlTip.SetToolTip(repair, "Reinstall this PC's CRL listener and refresh its CRLs");
                _crlPanel.Controls.Add(repair, 3, row);
            }
            else if (type != "none" && url is not null)
            {
                AddViewLink(row, type, url);
            }
            row++;
        }
        // The CRLs this server and its Cloudflare Worker publish can be looked at whichever profile is in use.
        foreach (string type in new[] { "server", "cloudflare" })
        {
            if (type != _state.CrlDp && _device?.CrlUrls.GetValueOrDefault(type) is { } url)
            {
                _crlResults.TryGetValue(type, out var result);
                AddStatusRow(row, $"CRL · {CrlTypes.Label(type)} (not in use)", url, result, async () => await TestCrlAsync(type, url));
                AddViewLink(row++, type, url);
            }
        }
        return row;
    }

    private void AddStatusRow(int row, string label, string? url, CrlCheck.Result? result, Func<Task>? test, bool neutral = false)
    {
        (string dot, Color color, string status) = neutral ? ("○", Theme.TextDim, result?.Summary ?? "")
            : result is null ? ("○", Theme.TextDim, url is null ? "No address yet" : "Not checked")
            : result.Ok ? ("●", Theme.Success, result.Summary)
            : ("●", Theme.Danger, result.Summary);
        var name = new Label { Text = $"{dot}  {label}", AutoSize = true, ForeColor = color, Font = Theme.UiBold, Margin = new Padding(0, 2, 16, 2) };
        var state = new Label
        {
            Text = status + (url is null ? "" : "  ·  " + url),
            AutoSize = true, ForeColor = neutral || result is null ? Theme.TextDim : result.Ok ? Theme.Success : Theme.Danger,
            Margin = new Padding(0, 2, 16, 2),
        };
        _crlPanel.Controls.Add(name, 0, row);
        _crlPanel.Controls.Add(state, 1, row);
        if (test is not null && url is not null)
        {
            var link = new LinkLabel { Text = "Test", AutoSize = true, Margin = new Padding(0, 2, 12, 2) };
            link.LinkColor = link.ActiveLinkColor = link.VisitedLinkColor = Theme.AccentText;
            link.LinkClicked += async (_, _) => await test();
            _crlTip.SetToolTip(link, "Check " + url + " now");
            _crlPanel.Controls.Add(link, 2, row);
        }
    }

    private void AddViewLink(int row, string type, string url)
    {
        var view = new LinkLabel { Text = "View", AutoSize = true, Margin = new Padding(0, 2, 0, 2) };
        view.LinkColor = view.ActiveLinkColor = view.VisitedLinkColor = Theme.AccentText;
        view.LinkClicked += async (_, _) => await ViewCrlAsync(type, url);
        _crlTip.SetToolTip(view, "Show the revoked certificates this CRL lists now");
        _crlPanel.Controls.Add(view, 3, row);
    }

    private LinkLabel PanelLink(string text, string tip, Func<Task> action)
    {
        var link = new LinkLabel { Text = text, AutoSize = true, Margin = new Padding(0, 0, 12, 4), Font = Theme.MonoSmall };
        link.LinkColor = link.ActiveLinkColor = link.VisitedLinkColor = Theme.AccentText;
        link.LinkClicked += async (_, _) => await action();
        _crlTip.SetToolTip(link, tip);
        return link;
    }

    /// <summary>Check the LAN and (when this PC has one) the relay; _device comes from whichever answered, the LAN first.</summary>
    private async Task CheckBothAsync(DeviceState state)
    {
        _serverCheck = Connectivity.Route == PalRoute.Relay ? null : await CheckServerAsync(state, PalRoute.Lan);
        var fromLan = _device;
        _remoteCheck = state.Relay is null ? null : await CheckServerAsync(state, PalRoute.Relay);
        if (_serverCheck is { Ok: true } && fromLan is not null)
        {
            _device = fromLan;  // prefer what the LAN said
        }
    }

    private bool ServerReachable => _serverCheck is { Ok: true } || _remoteCheck is { Ok: true };

    /// <summary>Re-run the connectivity checks only (no store audit), for the Refresh link.</summary>
    private async Task RecheckAsync()
    {
        if (_state is null || !BeginBusy("Checking connectivity…"))
        {
            return;
        }
        try
        {
            await CheckBothAsync(_state);
            _crlAnswering = _device is null ? [] : await LocalCrlServer.ProbeAsync(_device.SelfHosted);
            await CheckCrlsAsync();
            FillCrlPanel();
            UpdateDrift();
            SetStatus((_serverCheck is { } lan ? "Direct: " + lan.Summary : "Direct: not used") + (_remoteCheck is { } remote ? " · Remote: " + remote.Summary : "")
                + (_state.CrlDp.Length > 0 && _crlResults.TryGetValue(_state.CrlDp, out var crl) ? " · CRL: " + crl.Summary : ""));
        }
        finally
        {
            EndBusy();
        }
    }

    /// <summary>A signed call to the server over one route, timed: the same path every request and renewal takes.</summary>
    private async Task<CrlCheck.Result> CheckServerAsync(DeviceState state, PalRoute route)
    {
        string url = route == PalRoute.Relay ? state.Relay?.Url ?? "" : state.ServerUri.GetLeftPart(UriPartial.Authority);
        string via = route == PalRoute.Relay ? "through the remote relay" : "over the LAN";
        var watch = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var signer = new DeviceSigner(state);
            using var client = state.Client(route);
            var device = await client.GetDeviceAsync(signer);
            watch.Stop();
            _device = device;
            state.RememberRelay(device);  // only when it came over the LAN
            if (state.RememberCrlDps(device))
            {
                FillProfiles();  // the admin changed which CRL profiles this PC may use
            }
            AppLog.Debug($"Server check {via} {url}: ok in {watch.ElapsedMilliseconds} ms (server v{device.ServerVersion})");
            string ms = watch.ElapsedMilliseconds.ToString(CultureInfo.CurrentCulture);
            return new CrlCheck.Result(true, $"Reachable · {ms} ms",
                $"{url}\n\nAnswered a signed request {via} in {ms} ms.\nServer v{device.ServerVersion} · CA {device.CaName} · this PC {device.Fqdn}");
        }
        catch (Exception e) when (e is PalException or DeviceKeyUnavailableException or HttpRequestException or TaskCanceledException)
        {
            string message = Operations.FriendlyMessage(e);
            AppLog.Debug($"Server check {via} {url}: FAILED after {watch.ElapsedMilliseconds} ms: {e.GetType().Name}: {e.Message}");
            return new CrlCheck.Result(false, message.Split(". ")[0].TrimEnd('.'), $"{url}\n\n{message}");
        }
    }

    private async Task TestServerAsync(PalRoute route)
    {
        if (_busy || _state is null)
        {
            return;
        }
        string name = route == PalRoute.Relay ? "Cert server · Remote" : "Cert server · Direct";
        UseWaitCursor = true;
        SetStatus($"Testing {name}…");
        var result = await CheckServerAsync(_state, route);
        if (route == PalRoute.Relay)
        {
            _remoteCheck = result;
        }
        else
        {
            _serverCheck = result;
        }
        UseWaitCursor = false;
        FillCrlPanel();
        SetStatus($"{name}: {result.Summary}");
        MessageBox.Show(this, result.Detail, $"{name}: {result.Summary}", MessageBoxButtons.OK,
            result.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
    }

    private async Task TestCrlAsync(string type, string url)
    {
        if (_busy)
        {
            return;
        }
        UseWaitCursor = true;
        SetStatus($"Testing {CrlTypes.Label(type)}: {url}");
        var result = await CrlCheck.TestAsync(url, type == "placeholder");
        UseWaitCursor = false;
        _crlResults[type] = result;
        FillCrlPanel();
        SetStatus($"{CrlTypes.Label(type)}: {result.Summary}");
        MessageBox.Show(this, result.Detail, $"{CrlTypes.Label(type)}: {result.Summary}", MessageBoxButtons.OK,
            result.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
    }

    /// <summary>Ask the server to sign and publish the CA's CRL now, then check the addresses again.</summary>
    private async Task PublishCrlAsync()
    {
        if (_state is null || !BeginBusy("Publishing the CRL…"))
        {
            return;
        }
        try
        {
            using var signer = new DeviceSigner(_state);
            using var client = _state.Client();
            var reply = await client.PublishCrlAsync(signer);
            await CheckCrlsAsync();
            FillCrlPanel();
            bool pushFailed = reply.Cloudflare is { Pushed: false };
            string worker = reply.Cloudflare is null ? ""
                : pushFailed ? $"\n\nPublishing to the Cloudflare Worker failed: {reply.Cloudflare.Error ?? "unknown error"}. The server retries every hour."
                : "\n\nThe Cloudflare Worker has it too.";
            AppLog.Info($"CRL published now: {reply.Revoked} revoked{(pushFailed ? "; Cloudflare push failed" : "")}");
            SetStatus(pushFailed ? "CRL published; the Cloudflare Worker didn't take it" : "CRL published");
            MessageBox.Show(this, $"The server signed a new CRL listing {reply.Revoked.ToString(CultureInfo.CurrentCulture)} revoked certificate{(reply.Revoked == 1 ? "" : "s")}."
                + worker + "\n\nA PC that already fetched the CRL keeps its copy until that copy's next update.",
                "Publish CRL now", MessageBoxButtons.OK, pushFailed ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }
        catch (Exception e) when (e is PalException or DeviceKeyUnavailableException or HttpRequestException or TaskCanceledException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
    }

    /// <summary>Download the CRL an address serves now and list what it revokes.</summary>
    private async Task ViewCrlAsync(string type, string url)
    {
        if (_busy)
        {
            return;
        }
        UseWaitCursor = true;
        SetStatus($"Getting the CRL: {url}");
        try
        {
            if (CrlList.Parse(await CrlCheck.DownloadAsync(url, type == "placeholder")) is not { } crl)
            {
                SetStatus($"{CrlTypes.Label(type)}: answers, but not with a CRL");
                MessageBox.Show(this, $"{url}\n\nThe reply isn't a CRL Windows can read.", "CRL · " + CrlTypes.Label(type), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            var onThisPc = _items.Where(i => !i.IsCa).GroupBy(i => StoreAudit.NormalizeSerial(i.Serial)).ToDictionary(g => g.Key, g => g.First().Names);
            SetStatus($"{CrlTypes.Label(type)}: {crl.Revoked.Count.ToString(CultureInfo.CurrentCulture)} revoked");
            UseWaitCursor = false;
            using var dialog = new CrlDialog(CrlTypes.Label(type), url, crl, onThisPc);
            dialog.ShowDialog(this);
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            string why = e is TaskCanceledException ? "No answer within 10 seconds." : e.Message;
            SetStatus($"{CrlTypes.Label(type)}: couldn't get the CRL");
            MessageBox.Show(this, $"{url}\n\n{why}", "CRL · " + CrlTypes.Label(type), MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        finally
        {
            UseWaitCursor = false;
        }
    }

    private async Task RepairAsync()
    {
        if (!BeginBusy("Repairing the endpoint-hosted CRL… approve the Windows prompt."))
        {
            return;
        }
        try
        {
            Report(await Elevation.RunAsync(new HelperOp { Op = "crl-install" }));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        if (_state is null || !BeginBusy("Checking with the server and auditing this PC's certificate stores…"))
        {
            return;
        }
        List<AuditItem> revokedByServer = [];
        try
        {
            var state = _state;
            string? serverProblem = null;
            Dictionary<string, string> status = [];
            revokedByServer = [];
            try
            {
                _device = null;
                await CheckBothAsync(state);  // sets _device from whichever route answered
                if (!ServerReachable || _device is null)
                {
                    throw new PalException((_serverCheck ?? _remoteCheck)?.Summary + ".");
                }
                using var signer = new DeviceSigner(state);
                // The LAN just failed: go straight to the relay rather than waiting for it again.
                using var client = state.Client(_serverCheck is { Ok: true } ? null : PalRoute.Relay);
                if (ChainCheck.RootMatches(_device.Chain, state.RootSha256))
                {
                    state.Chain = _device.Chain;  // picks up a new intermediate; saved by the next elevated step
                }
                await PendingRevokes.FlushAsync(client, signer, state.DeviceId);  // removals made while the server was out of reach
                _items = await Task.Run(() => StoreAudit.Run(state));
                // Where each key lives goes along, so the admin sees which are in the TPM.
                var keys = new Dictionary<string, string>();
                var reported = _device.Certs.Where(c => c.KeyStorage is not null)
                    .GroupBy(c => StoreAudit.NormalizeSerial(c.Serial)).ToDictionary(g => g.Key, g => g.First().KeyStorage!);
                foreach (var item in _items.Where(i => !i.IsCa))
                {
                    if (Keys.Storage(item.Cert) is { } storage)
                    {
                        keys[item.Serial] = storage;
                        item.KeyStorage = storage;
                    }
                    else
                    {
                        item.KeyStorage = reported.GetValueOrDefault(StoreAudit.NormalizeSerial(item.Serial), "");
                    }
                }
                _deviceKeyStorage = signer.KeyStorage;
                var uses = _items.Where(i => i.UsedBy.Count > 0).GroupBy(i => i.Serial)
                    .ToDictionary(g => g.Key, g => g.SelectMany(i => i.UsedBy).Distinct().ToList());
                status = await client.StatusAsync(signer, _items.Select(i => i.Serial).Distinct().ToList(), _deviceKeyStorage, keys, LocalIdentity.AccountName, uses);
                _crlAnswering = await LocalCrlServer.ProbeAsync(_device.SelfHosted);
                await CheckCrlsAsync();
            }
            catch (Exception e) when (e is PalException or DeviceKeyUnavailableException or HttpRequestException)
            {
                serverProblem = Operations.FriendlyMessage(e);
                _items = await Task.Run(() => StoreAudit.Run(state));
            }
            StoreAudit.ApplyServer(_items, status, _device);
            if (serverProblem is null && status.Count > 0)
            {
                var changed = SeenStatus.Update(state.DeviceId, status);
                revokedByServer = _items.Where(i => !i.IsCa && changed.Contains(i.Serial)).ToList();
            }
            FillCrlPanel();
            UpdateDrift();
            UpdateTiles();
            FillList();
            UpdatePending();
            int problems = _items.Count(i => i.Flags.Count > 0);
            SetStatus(serverProblem is not null
                ? "Server: " + serverProblem
                : $"{_items.Count} certificates from {state.CaName}" + (problems > 0 ? $", {problems} need a look." : ". All good.")
                  + (_serverCheck is { Ok: true } ? "" : " (through the remote relay)"));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        if (revokedByServer.Count > 0)
        {
            // Something the server did since this PC last looked: say so, once.
            string it = revokedByServer.Count == 1 ? "it" : "them";
            MessageBox.Show(this,
                (revokedByServer.Count == 1 ? "Your admin revoked a certificate on this PC:" : $"Your admin revoked {revokedByServer.Count} certificates on this PC:") +
                "\n\n" + string.Join("\n", revokedByServer.Take(12).Select(i => $"• {i.Names}  ({i.UseLabel})")) +
                $"\n\nNothing that checks revocation trusts {it} any more. Select {it} and choose Remove to take {it} off this PC, " +
                "then request a new certificate if you still need one.",
                Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void UpdateTiles()
    {
        var policy = _device?.Policy;
        foreach (var (tile, button) in _tileButtons)
        {
            if (tile == CrlTile)
            {
                button.Visible = _state?.CrlDp == "placeholder";
                bool answering = _crlAnswering.Count > 0 && _crlAnswering.Values.All(v => v);
                (string crlText, Color crlColor) = answering ? ("Running", Theme.Success)
                    : _device?.CrlDp == "placeholder" ? ("Recommended: install", Theme.Warning)
                    : ("Not installed", Theme.TextDim);
                button.SetStatus(crlText, crlColor);
                button.Enabled = _device is not null && _device.SelfHosted.Count > 0 && !_busy;
                continue;
            }
            if (tile == TrustTile)
            {
                bool trusted = _state is not null && Operations.IsTrusted(_state);
                button.SetStatus(trusted ? "Already in Trusted Root" : "Install root CA", trusted ? Theme.Success : Theme.AccentText);
                button.Enabled = !trusted && !_busy;
                continue;
            }
            string mode = policy?.Mode(tile) ?? "off";
            button.Visible = policy is null || mode != "off";  // not allowed: not shown
            // A certificate this PC already holds can't be requested again: renew it near expiry instead.
            var installed = _items.FirstOrDefault(i => i.FromPal is { Revoked: 0 } pal && UseCases.FromTemplate(pal.Template) == tile
                && i.ServerStatus != "revoked" && i.Cert.NotAfter > DateTime.Now);
            bool noProfile = _state is { CrlDp.Length: 0 };
            (string note, Color color) = installed is not null ? ("Installed", Theme.Success)
                : policy is null ? ("Server unreachable", Theme.Danger)
                : noProfile && mode != "off" ? ("Pick a CRL profile first", Theme.Warning)
                : mode switch
                {
                    "auto" => ("Get it now", Theme.AccentText),
                    "approve" => ("Your admin approves", Theme.Warning),
                    _ => ("Not allowed", Theme.TextDim),
                };
            button.SetStatus(note, color);
            button.Enabled = mode != "off" && installed is null && !noProfile && !_busy;
        }
    }

    /// <summary>
    /// The list gets whatever height the masthead and the tiles leave, which at the default size can
    /// be next to nothing (a long connectivity block, two rows of tiles). Once per load, grow the
    /// window until about five rows show, as far as the screen allows. Later the size is the user's.
    /// </summary>
    private void EnsureListRoom()
    {
        if (_listRoomChecked || !_mainPanel.Visible || WindowState != FormWindowState.Normal || !IsHandleCreated)
        {
            return;
        }
        _listRoomChecked = true;
        PerformLayout();
        int missing = LogicalToDeviceUnits(ListMinHeight) - _list.Height;
        if (missing > 0)
        {
            var area = Screen.FromControl(this).WorkingArea;
            Height = Math.Min(area.Height, Height + missing);
            Top = Math.Max(area.Top, Math.Min(Top, area.Bottom - Height));
        }
    }

    private static string UseText(AuditItem item) => item.UseLabel + (item.FromPal is not null ? " (Pal)" : "");

    private static string KeyText(AuditItem item) =>
        item.IsCa ? "" : item.KeyStorage switch { "tpm" => "TPM", "software" => "Software", _ => item.Cert.HasPrivateKey ? "Unknown" : "" };

    /// <summary>What needs a look, then everything that uses the certificate, then binds still waiting for the admin.</summary>
    private string NotesText(AuditItem item) => string.Join("; ", item.Flags
        .Concat(item.UsedBy.Select(u => "Used by " + u))
        .Concat(_waitingBinds[item.Cert.Thumbprint].Select(t => "Waiting for approval: " + BindKeys.Label(t))));

    /// <summary>A click on a column header sorts by it; a second click on the same one reverses the order.</summary>
    private void SortBy(int column)
    {
        _sortDescending = column == _sortColumn && !_sortDescending;
        _sortColumn = column;
        _list.Invalidate();  // the header's arrow moves
        FillList();
    }

    /// <summary>The rows in the chosen order. Dates sort as dates, and what can't be renewed sorts after what can.</summary>
    private IEnumerable<AuditItem> Sorted()
    {
        var text = StringComparer.CurrentCultureIgnoreCase;
        IOrderedEnumerable<AuditItem> By<T>(Func<AuditItem, T> key, IComparer<T>? comparer = null) =>
            _sortDescending ? _items.OrderByDescending(key, comparer) : _items.OrderBy(key, comparer);
        var sorted = _sortColumn switch
        {
            0 => By(i => i.Names, text),
            1 => By(UseText, text),
            2 => By(i => i.StoreLabel, text),
            3 => By(KeyText, text),
            4 => By(i => i.Cert.NotAfter),
            5 => By(i => i.FromPal?.RenewFromTime ?? DateTimeOffset.MaxValue),
            6 => By(i => i.ServerStatus, text),
            7 => By(NotesText, text),
            _ => _items.OrderBy(i => i.IsCa).ThenBy(i => i.Location),
        };
        return sorted.ThenBy(i => i.Names, text);
    }

    private void FillList()
    {
        var selected = SelectedAll;
        _waitingBinds = _state is null ? Enumerable.Empty<string>().ToLookup(t => t) : Operations.WaitingBinds(_state.DeviceId);
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var item in Sorted())
        {
            var row = new ListViewItem(item.Names) { Tag = item, Selected = selected.Contains(item) };
            row.SubItems.Add(UseText(item));
            row.SubItems.Add(item.StoreLabel);
            row.SubItems.Add(KeyText(item));
            row.SubItems.Add(item.Cert.NotAfter.ToString("d MMM yyyy", CultureInfo.CurrentCulture));
            row.SubItems.Add(RenewText(item));
            row.SubItems.Add(item.ServerStatus);
            row.SubItems.Add(NotesText(item));
            if (item.ServerStatus == "revoked" || item.Flags.Any(f => f.StartsWith("Expired", StringComparison.Ordinal)))
            {
                row.ForeColor = Theme.Danger;
            }
            else if (item.Flags.Count > 0)
            {
                row.ForeColor = Theme.Warning;
            }
            _list.Items.Add(row);
        }
        _list.EndUpdate();
        FitColumns();
        UpdateActions();
        EnsureListRoom();
    }

    private void UpdatePending()
    {
        int local = Operations.PendingCount();
        int server = _device?.Requests.Count(r => r.Status == "pending") ?? 0;
        int count = Math.Max(local, server);
        int binds = Operations.PendingBindCount();
        _pendingBar.Visible = count + binds > 0;
        string what = string.Join(" and ", new[]
        {
            count == 0 ? null : count == 1 ? "1 request" : $"{count} requests",
            binds == 0 ? null : binds == 1 ? "1 bind" : $"{binds} binds",
        }.OfType<string>());
        _pendingLabel.Text = $"{what} {(count + binds == 1 ? "is" : "are")} waiting for your admin.";
    }

    /// <summary>The root is already trusted where this request installs (machine certs: the computer's store).</summary>
    private bool RootTrustedHere(string useCase) =>
        _items.Any(i => i.IsRoot && i.StoreName == "Root" && (i.Location == StoreLocation.LocalMachine || !UseCases.IsMachine(useCase)));

    private AuditItem? Selected => _list.SelectedItems.Count == 1 ? _list.SelectedItems[0].Tag as AuditItem : null;

    private List<AuditItem> SelectedAll => _list.SelectedItems.Cast<ListViewItem>().Select(r => r.Tag).OfType<AuditItem>().ToList();

    private void UpdateActions()
    {
        var item = Selected;
        var renewFrom = item?.FromPal?.RenewFromTime;
        _renew.Enabled = !_busy && item?.FromPal is { Revoked: 0 } && item.StoreName == "My" && renewFrom is { } from && from <= DateTimeOffset.UtcNow;
        bool waiting = item?.FromPal is { Revoked: 0 } && renewFrom is { } opens && opens > DateTimeOffset.UtcNow;
        _renew.Text = waiting ? "RENEW " + RenewText(item!).ToUpperInvariant() : "RENEW";
        _crlTip.SetToolTip(_renew, waiting
            ? "Renewal opens " + renewFrom!.Value.ToLocalTime().ToString("d MMM yyyy HH:mm", CultureInfo.CurrentCulture) + ", near the end of the certificate's life."
            : "");
        int count = _list.SelectedItems.Count;
        _remove.Enabled = !_busy && count > 0;
        _remove.Text = count > 1 ? $"REMOVE {count}" : "REMOVE";
        int revocable = _list.SelectedItems.Cast<ListViewItem>().Count(r => r.Tag is AuditItem { IsCa: false, HasCrl: true, FromPal.Revoked: 0 });
        _revoke.Enabled = !_busy && revocable > 0;
        _revoke.Text = revocable > 1 ? $"REVOKE {revocable}" : "REVOKE";
        _crlTip.SetToolTip(_revoke, "Have the server revoke a certificate this PC was issued. It stays on this PC, marked revoked, until you remove it. A certificate that names no CRL can't be revoked.");
        _crlTip.SetToolTip(_remove, "Remove from this PC. A certificate this PC was issued is revoked on the server in the same step, unless it names no CRL.");
        _details.Enabled = item is not null;
        _bind.Enabled = !_busy && item is { CanBind: true };
        _crlTip.SetToolTip(_bind, "Choose what uses this certificate, or take it out of use: Remote Desktop, WinRM, an IIS site or a Remote Desktop Services role. Your admin decides which are allowed. Renewing it moves them to the new certificate.");
    }

    /// <summary>When a certificate this PC was issued can be renewed: "now", "in 245 days", or "" for others.</summary>
    internal static string RenewText(AuditItem item)
    {
        if (item.FromPal is not { Revoked: 0 } pal || item.IsCa || pal.RenewFromTime is not { } opens)
        {
            return "";
        }
        return opens <= DateTimeOffset.UtcNow ? "now" : "in " + Remaining(opens - DateTimeOffset.UtcNow);
    }

    internal static string Remaining(TimeSpan left) => left.TotalDays >= 2 ? $"{(int)Math.Ceiling(left.TotalDays)} days"
        : left.TotalHours >= 2 ? $"{(int)Math.Ceiling(left.TotalHours)} hours"
        : $"{Math.Max(1, (int)Math.Ceiling(left.TotalMinutes))} minutes";

    // ── Actions ─────────────────────────────────────────────────────

    private async Task ConnectAsync()
    {
        string text = _codeBox.Text.Trim();
        try
        {
            PairingCode.Parse(text);  // a typo is reported before asking for administrator approval
        }
        catch (PalException e)
        {
            MessageBox.Show(this, e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        if (!BeginBusy("Connecting… approve the Windows prompt to trust your CA."))
        {
            return;
        }
        try
        {
            var result = await Elevation.RunAsync(new HelperOp { Op = "connect", Code = text });
            Report(result);
            if (result.Ok)
            {
                _codeBox.Clear();
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await LoadStateAsync();
    }

    private async Task RequestAsync(string useCase)
    {
        if (_state is null || _device is null)
        {
            return;
        }
        using var dialog = new RequestDialog(useCase, _state, _device.Policy, RootTrustedHere(useCase));
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }
        await RunRequestAsync(useCase, dialog.Names, dialog.LifetimeDays, renewOf: null, replace: null, dialog.Note);
    }

    private async Task RenewAsync()
    {
        if (_state is null || Selected is not { FromPal: { } pal } item || UseCases.FromTemplate(pal.Template) is not { } useCase)
        {
            return;
        }
        if (MessageBox.Show(this, $"Renew {item.Names}?\n\nA new key and certificate replace this one.", Text,
                MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
        {
            return;
        }
        Dictionary<string, object> names = useCase switch
        {
            UseCases.WebServer => new() { ["dns"] = pal.SanDomains.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList() },
            UseCases.Computer => [],
            UseCases.User => new() { ["upn"] = pal.CommonName },
            _ => new() { ["cn"] = pal.CommonName },
        };
        await RunRequestAsync(useCase, names, lifetime: null, renewOf: pal.Id, replace: item.Cert.Thumbprint);
    }

    private async Task RunRequestAsync(string useCase, Dictionary<string, object> names, int? lifetime, int? renewOf, string? replace,
        string? note = null)
    {
        if (_state is null || !BeginBusy($"Requesting {UseCases.Label(useCase)}…"))
        {
            return;
        }
        string? bindNext = null;  // the kind of certificate to open Bind… on once the list is fresh
        try
        {
            var op = new HelperOp { Op = "request", UseCase = useCase, Names = names, LifetimeDays = lifetime, RenewOf = renewOf, ReplaceThumbprint = replace, Note = note };
            OpResult result;
            if (UseCases.IsMachine(useCase))
            {
                result = await Elevation.RunAsync(op);
            }
            else
            {
                try
                {
                    result = await Operations.RequestAsync(_state, useCase, names, lifetime, renewOf, replace, note: note);
                }
                catch (DeviceKeyUnavailableException)
                {
                    result = await Elevation.RunAsync(op);  // this PC's key can't be shared with users: do it elevated
                }
            }
            bindNext = ReportAndOfferBind(result, useCase, renewOf is not null);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await RefreshAsync();
        if (bindNext is not null && _items.Where(i => i.CanBind && i.FromPal is { Revoked: 0 } pal && UseCases.FromTemplate(pal.Template) == bindNext)
                .OrderByDescending(i => i.Cert.NotBefore).FirstOrDefault() is { } installed)
        {
            await BindAsync(installed);
        }
    }

    /// <summary>
    /// Say how a request went. A new machine certificate also says what it already does and what
    /// needs a bind, and offers Bind…; a web server request the This computer certificate already
    /// covers offers Bind… on that one. Returns the kind of certificate to bind next, or null.
    /// </summary>
    private string? ReportAndOfferBind(OpResult result, string useCase, bool renewal)
    {
        const string covered = "Already covered. ";
        if (!result.Ok && result.Message.StartsWith(covered, StringComparison.Ordinal))
        {
            SetStatus(result.Message);
            return MessageBox.Show(this, result.Message[covered.Length..] + "\n\nOpen Bind… for that certificate now?", "Already covered",
                MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes ? UseCases.Computer : null;
        }
        if (!result.Ok || result.Status != "issued" || renewal || !UseCases.IsMachine(useCase))
        {
            Report(result);  // a renewal keeps the old certificate's binds, so there is nothing to offer
            return null;
        }
        var policy = _device?.Policy ?? new Policy();
        var roles = BindKeys.All.Where(k => policy.BindMode(k) != "off").Select(BindKeys.Label).ToList();
        string ready = useCase == UseCases.Computer
            ? "Works now, with no bind: Wi-Fi, VPN and 802.1X sign-in, and identifying this computer (for example device posture checks)."
            : "A web server certificate does nothing until it is bound.";
        SetStatus(result.Message);
        if (roles.Count == 0)
        {
            MessageBox.Show(this, $"{result.Message}\n\n{ready}\n\nYour admin hasn't allowed binding it to anything on this PC.", Text,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return null;
        }
        return MessageBox.Show(this, $"{result.Message}\n\n{ready}\nNeeds a bind first: {string.Join(", ", roles)}.\n\nBind it to one of those now?", Text,
            MessageBoxButtons.YesNo, MessageBoxIcon.Information, MessageBoxDefaultButton.Button2) == DialogResult.Yes ? useCase : null;
    }

    private async Task CollectAsync()
    {
        if (_state is null || !BeginBusy("Checking your requests…"))
        {
            return;
        }
        try
        {
            var messages = new List<string>();
            if (PendingStore.Open(machine: true).Items.Count > 0)
            {
                messages.Add((await Elevation.RunAsync(new HelperOp { Op = "collect", Machine = true })).Message);
            }
            if (PendingStore.Open(machine: false).Items.Count > 0)
            {
                try
                {
                    messages.Add((await Operations.CollectAsync(_state, machine: false)).Message);
                }
                catch (DeviceKeyUnavailableException)
                {
                    messages.Add((await Elevation.RunAsync(new HelperOp { Op = "collect", Machine = false })).Message);
                }
            }
            if (Operations.PendingBindCount() > 0)
            {
                messages.Add((await Elevation.RunAsync(new HelperOp { Op = "collect-binds" })).Message);
            }
            if (messages.Count == 0)
            {
                messages.Add("Nothing waiting on this PC.");
            }
            MessageBox.Show(this, string.Join(Environment.NewLine, messages), Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await RefreshAsync();
    }

    /// <summary>Remove every selected certificate: the computer's in one elevated pass (one UAC prompt), the user's directly.</summary>
    /// <summary>
    /// Remove takes the selected certificates off this PC and, in the same pass, has the server revoke
    /// the ones this PC was issued: a removed certificate must not stay valid. Revoke
    /// (<paramref name="revokeOnly"/>) has the server revoke them and leaves them here, marked revoked.
    /// </summary>
    /// <summary>The confirmation for Remove or Revoke: what goes, what still uses it, and what the server revokes (or can't).</summary>
    private static string RemoveQuestion(List<AuditItem> items, List<AuditItem> revocable, int noCrl, bool revokeOnly)
    {
        var lines = items.Take(12).Select(i => $"• {i.Names}  ({i.StoreLabel})").ToList();
        if (items.Count > 12)
        {
            lines.Add($"• …and {items.Count - 12} more");
        }
        string one = items.Count == 1 ? "it" : "them";
        string question;
        string warning = "";
        if (revokeOnly)
        {
            question = items.Count == 1 ? "Revoke this certificate?" : $"Revoke these {items.Count} certificates?";
            warning = $"\n\nThe server revokes {one}, and nothing that checks revocation trusts {one} again. " +
                      (items.Count == 1 ? "It stays" : "They stay") + $" on this PC, marked revoked, until you remove {one}. This can't be undone.";
        }
        else
        {
            question = items.Count == 1 ? "Remove this certificate?" : $"Remove these {items.Count} certificates?";
            if (items.Any(i => i.IsRoot))
            {
                warning += "\n\nThis includes the root CA: this PC will stop trusting every certificate from it.";
            }
            var inUse = items.Where(i => i.UsedBy.Count > 0).ToList();
            if (inUse.Count > 0)
            {
                warning += "\n\nIn use: " + string.Join("; ", inUse.Select(i => $"{i.Names} by {string.Join(", ", i.UsedBy)}")) +
                    ". Without it, whatever uses it has no certificate, and Remote Desktop goes back to its own.";
            }
            if (revocable.Count > 0)
            {
                warning += "\n\nALSO REVOKED: " + (revocable.Count == items.Count
                        ? (items.Count == 1 ? "this PC was issued this certificate, so it is" : "this PC was issued these certificates, so they are")
                        : $"{revocable.Count} of them were issued to this PC and are") +
                    " revoked on the server in the same step. This can't be undone: request a new one if you need it again.";
            }
            if (noCrl > 0)
            {
                warning += "\n\nNOT REVOKED: " + (noCrl == items.Count
                        ? (items.Count == 1 ? "this certificate names" : "these certificates name")
                        : $"{noCrl} of them name") +
                    " no CRL, so the server can't revoke " + (noCrl == 1 ? "it" : "them") + ". A copy made elsewhere stays trusted until it expires.";
            }
        }
        return question + "\n\n" + string.Join("\n", lines) + warning;
    }

    private async Task RemoveAsync(bool revokeOnly)
    {
        var items = revokeOnly ? SelectedAll.Where(i => !i.IsCa && i.HasCrl && i.FromPal is { Revoked: 0 }).ToList() : SelectedAll;
        if (items.Count == 0)
        {
            return;
        }
        var issuedHere = items.Where(i => !i.IsCa && i.FromPal is { Revoked: 0 }).ToList();
        var revocable = issuedHere.Where(i => i.HasCrl).ToList();  // one that names no CRL is only reported as removed
        int noCrl = issuedHere.Count - revocable.Count;
        if (MessageBox.Show(this, RemoveQuestion(items, revocable, noCrl, revokeOnly), Text, MessageBoxButtons.OKCancel,
                MessageBoxIcon.Warning) != DialogResult.OK || !BeginBusy(revokeOnly ? "Revoking…" : "Removing…"))
        {
            return;
        }
        try
        {
            var problems = new List<string>();
            if (!revokeOnly)
            {
                var machine = items.Where(i => i.Location == StoreLocation.LocalMachine).ToList();
                if (machine.Count > 0)
                {
                    var result = await Elevation.RunAsync(new HelperOp
                    {
                        Op = "remove",
                        Targets = machine.Select(i => new RemoveTarget { Store = i.StoreName, Thumbprint = i.Cert.Thumbprint }).ToList(),
                    });
                    if (!result.Ok)
                    {
                        problems.Add(result.Message);
                    }
                }
                foreach (var item in items.Where(i => i.Location == StoreLocation.CurrentUser))
                {
                    try
                    {
                        Operations.Remove(StoreLocation.CurrentUser, item.StoreName, item.Cert.Thumbprint);
                    }
                    catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
                    {
                        problems.Add($"{item.Names}: {Operations.FriendlyMessage(e)}");
                    }
                }
            }
            string did = revokeOnly ? "" : items.Count == 1 ? "Removed from this PC." : $"Removed {items.Count} certificates from this PC.";
            string revoked = "";
            string? waiting = null;
            string saved = revocable.Count > 0 ? "revocation" : "removal";
            if (problems.Count == 0 && issuedHere.Count > 0 && _state is not null)
            {
                // Saved first, so one made while the server can't be reached is still revoked later.
                PendingRevokes.Add(_state.DeviceId, issuedHere.Select(i => i.Serial));
                SeenStatus.MarkRevoked(_state.DeviceId, revocable.Select(i => i.Serial));  // our own doing: no notice about it later
                try
                {
                    using var signer = new DeviceSigner(_state);
                    using var client = _state.Client();  // the LAN first, then the relay if this PC has one
                    if (await PendingRevokes.FlushAsync(client, signer, _state.DeviceId))
                    {
                        revoked = (revocable.Count == 0 ? "" : revocable.Count == 1 && noCrl == 0 ? " Revoked on the server." : $" {revocable.Count} revoked on the server.")
                            + (noCrl == 0 ? "" : issuedHere.Count == 1 ? " Not revoked: it names no CRL." : $" {noCrl} not revoked: no CRL.");
                    }
                    else
                    {
                        waiting = (did + $" The server can't be reached right now, so the {saved} is saved and sent the next time " +
                                   "the Pal reaches it (Refresh, or the next time it opens).").Trim();
                    }
                }
                catch (DeviceKeyUnavailableException e)
                {
                    AppLog.Error("Couldn't sign the revocation", e);
                    waiting = (did + " " + Operations.FriendlyMessage(e) + $" The {saved} is saved and sent at the next check-in.").Trim();
                }
            }
            if (problems.Count > 0)
            {
                Report(OpResult.Failure("Not all removed" + (revocable.Count > 0 ? ", and nothing was revoked on the server. " : ". ") + string.Join("\n", problems)));
            }
            else if (waiting is not null)
            {
                Report(OpResult.Failure(waiting));
            }
            else
            {
                SetStatus((did + revoked).Trim());
            }
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await RefreshAsync();
    }

    /// <summary>Bind… on <paramref name="item"/> (the selected certificate when null): bind it to more roles, or take it out of one.</summary>
    private async Task BindAsync(AuditItem? item = null)
    {
        item ??= Selected;
        if (_state is null || item is not { CanBind: true })
        {
            return;
        }
        // Unreachable server: show every role; the bind itself still asks the server and says so if it can't.
        using var dialog = new BindDialog(item, _device?.Policy ?? new Policy(), _state.Fqdn,
            Operations.WaitingBinds(_state.DeviceId)[item.Cert.Thumbprint].ToList());
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }
        var op = dialog.RemoveTarget is { } target
            ? new HelperOp { Op = "unbind", Thumbprint = item.Cert.Thumbprint, Target = target }
            : new HelperOp { Op = "bind", Thumbprint = item.Cert.Thumbprint, Bind = dialog.Request, Note = dialog.Note };
        if (!BeginBusy(op.Op == "unbind" ? "Removing the bind… approve the Windows prompt." : "Binding… approve the Windows prompt."))
        {
            return;
        }
        try
        {
            Report(await Elevation.RunAsync(op));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await RefreshAsync();
    }

    private void ShowDetails()
    {
        if (Selected is not { } item || _state is null)
        {
            return;
        }
        using var viewer = new CertViewer(item, _state.Chain, RenewText(item));
        viewer.ShowDialog(this);
    }

    private async Task DisconnectAsync()
    {
        if (_state is null)
        {
            return;
        }
        var lines = _items.Where(i => i.FromPal is not null && !i.IsCa).Select(i => $"• {i.Names}  ({i.UseLabel}, {i.StoreLabel})").ToList();
        if (_state.CrlDp == "placeholder")
        {
            lines.Add("• the endpoint-hosted CRL listener");
        }
        string removed = lines.Count == 0 ? "Nothing from it is installed on this PC."
            : "Removed from this PC:\n" + string.Join("\n", lines.Take(12)) + (lines.Count > 12 ? $"\n• …and {lines.Count - 12} more" : "");
        if (MessageBox.Show(this, $"Disconnect this PC from {_state.CaName} ({_state.ServerUri.Host})?\n\n{removed}\n\n" +
                "Every CRL profile of this pairing goes with it; connecting again needs a new pairing code. " +
                "The root CA stays trusted.", "Disconnect", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK
            || !BeginBusy("Disconnecting…"))
        {
            return;
        }
        try
        {
            Report(await Elevation.RunAsync(new HelperOp { Op = "remove-profile", DeviceId = _state.DeviceId }));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await LoadStateAsync();
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private bool BeginBusy(string message)
    {
        if (_busy)
        {
            return false;
        }
        _busy = true;
        UseWaitCursor = true;
        _profileBox.Enabled = false;
        foreach (Control control in _tileButtons.Values.Cast<Control>().Append(_connectButton).Append(_refresh))
        {
            control.Enabled = false;
        }
        UpdateActions();
        SetStatus(message);
        return true;
    }

    private void EndBusy()
    {
        _busy = false;
        UseWaitCursor = false;
        UpdateProfileLock();
        _connectButton.Enabled = _refresh.Enabled = true;
        UpdateTiles();
        UpdateActions();
    }

    private void SetStatus(string message) => _status.Text = message.ReplaceLineEndings(" ");

    /// <summary>Messages lead with a short headline ("Wrong domain. …"): it becomes the dialog's title.</summary>
    private void Report(OpResult result)
    {
        SetStatus(result.Message);
        string caption = Text;
        string body = result.Message;
        int stop = body.IndexOf(". ", StringComparison.Ordinal);
        if (!result.Ok && stop is > 0 and <= 32)
        {
            caption = body[..stop];
            body = body[(stop + 2)..];
        }
        MessageBox.Show(this, body, caption, MessageBoxButtons.OK, result.Ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
    }

    private async Task LocalCrlAsync()
    {
        if (_device is null)
        {
            return;
        }
        using var dialog = new LocalCrlDialog(_device, _crlAnswering, _device.CrlDp == "placeholder");
        if (dialog.ShowDialog(this) != DialogResult.OK || dialog.Choice is null
            || !BeginBusy(dialog.Choice == "crl-install" ? "Installing the endpoint-hosted CRL… approve the Windows prompt." : "Removing the endpoint-hosted CRL…"))
        {
            return;
        }
        try
        {
            Report(await Elevation.RunAsync(new HelperOp { Op = dialog.Choice }));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await RefreshAsync();
    }

    private async Task TrustAsync()
    {
        if (_state is null || !BeginBusy("Adding your CA to the Trusted Root store… approve the Windows prompt."))
        {
            return;
        }
        try
        {
            Report(await Elevation.RunAsync(new HelperOp { Op = "trust" }));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
        await RefreshAsync();
    }

    // ── List drawing, in the app's table style ──────────────────────

    private void DrawHeader(object? sender, DrawListViewColumnHeaderEventArgs e)
    {
        using var back = new SolidBrush(Theme.Surface);
        e.Graphics.FillRectangle(back, e.Bounds);
        using var rule = new Pen(Theme.Rule);
        e.Graphics.DrawLine(rule, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
        var text = Rectangle.Inflate(e.Bounds, -LogicalToDeviceUnits(6), 0);
        string arrow = e.ColumnIndex == _sortColumn ? (_sortDescending ? " \u25BC" : " \u25B2") : "";
        TextRenderer.DrawText(e.Graphics, e.Header?.Text.ToUpperInvariant() + arrow, Theme.MonoSmall, text, Theme.TextDim,
            TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
    }

    private void DrawCell(object? sender, DrawListViewSubItemEventArgs e)
    {
        if (e.Item is null || e.SubItem is null)
        {
            return;
        }
        bool selected = e.Item.Selected;
        using (var back = new SolidBrush(selected ? Theme.Selection : Theme.Surface))
        {
            e.Graphics.FillRectangle(back, e.Bounds);
        }
        using (var line = new Pen(Theme.Border))
        {
            e.Graphics.DrawLine(line, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
        }
        Color color = e.ColumnIndex switch
        {
            3 => e.SubItem.Text switch { "TPM" => Theme.Success, "Software" => Theme.Warning, _ => Theme.TextDim },
            5 => e.SubItem.Text == "now" ? Theme.Success : Theme.TextDim,
            6 => e.SubItem.Text switch
            {
                "valid" => Theme.Success,
                "revoked" or "expired" => Theme.Danger,
                _ => Theme.TextDim,
            },
            7 => e.Item.ForeColor == Theme.Danger ? Theme.Danger : Theme.Warning,
            0 => e.Item.ForeColor == SystemColors.WindowText || e.Item.ForeColor == Theme.Text ? Theme.Text : e.Item.ForeColor,
            _ => Theme.Text,
        };
        bool label = e.ColumnIndex is 3 or 6;  // Key and Status read as labels
        var font = label ? Theme.MonoSmall : e.ColumnIndex == 0 ? Theme.Serif : Theme.Ui;
        string text = label ? e.SubItem.Text.ToUpperInvariant() : e.SubItem.Text;
        var bounds = Rectangle.Inflate(e.Bounds, -LogicalToDeviceUnits(6), 0);
        TextRenderer.DrawText(e.Graphics, text, font, bounds, color, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
    }

    private void Fail(Exception e)
    {
        Operations.Log(e);
        Report(OpResult.Failure(Operations.FriendlyMessage(e)));
    }
}
