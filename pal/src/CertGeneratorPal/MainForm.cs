using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using CertGeneratorPal.Core;

namespace CertGeneratorPal;

internal sealed class MainForm : Form
{
    private const string RepoUrl = "https://github.com/darthrater78/cert-generator";
    private static readonly string Version = typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    private static readonly string ReleaseNotesUrl = RepoUrl + "/releases/tag/v" + Version;

    private const string TrustTile = "trust";
    private const string CrlTile = "crl";
    private static readonly Dictionary<string, string> TileSubtitles = new()
    {
        [UseCases.Computer] = "Wi-Fi, VPN and 802.1X",
        [UseCases.WebServer] = "IIS sites and Remote Desktop",
        [UseCases.User] = "You: sign-in and smart card",
        [UseCases.CodeSigning] = "Scripts and programs",
        [TrustTile] = "Trust the CA for HTTPS inspection",
        [CrlTile] = "Answer revocation checks on this PC",
    };

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
        OwnerDraw = true, BorderStyle = BorderStyle.FixedSingle, HeaderStyle = ColumnHeaderStyle.Nonclickable,
    };
    private readonly Button _renew = new() { Text = "Renew", AutoSize = true, Enabled = false };
    private readonly Button _remove = new() { Text = "Remove", AutoSize = true, Enabled = false, Tag = Theme.ButtonKind.Danger };
    private readonly Button _details = new() { Text = "Details", AutoSize = true, Enabled = false };
    private readonly Button _refresh = new() { Text = "Refresh", AutoSize = true };
    private readonly Label _status = new()
    {
        Dock = DockStyle.Bottom, AutoSize = false, Height = 26, TextAlign = ContentAlignment.MiddleLeft,
        Padding = new Padding(16, 0, 16, 0), BackColor = Theme.Surface, ForeColor = Theme.TextDim, Font = Theme.Mono,
        AutoEllipsis = true,
    };
    private readonly LinkLabel _disconnect = new() { Text = "Remove this profile", AutoSize = true, Visible = false };
    private readonly ComboBox _profileBox = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 460, FlatStyle = FlatStyle.Flat, Margin = new Padding(0, 0, 8, 0) };
    private readonly Button _addProfile = new() { Text = "Add profile", AutoSize = true };
    private readonly FlowLayoutPanel _profileRow = new() { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 6), Visible = false };
    private readonly FlowLayoutPanel _healthRow = new() { AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 8), Visible = false };
    private readonly Label _health = new() { AutoSize = true, Margin = new Padding(0, 6, 8, 0), Font = Theme.Mono };
    private readonly Button _repair = new() { Text = "Repair", AutoSize = true, Tag = Theme.ButtonKind.Primary, Visible = false };
    private readonly Button _cancelAdd = new() { Text = "Cancel", AutoSize = true, Visible = false };
    private bool _fillingProfiles;
    private readonly ToolTip _healthTip = new();

    /// <summary>One profile: a pairing with one of the revocation types its code allowed.</summary>
    private sealed record ProfileChoice(DeviceState Pairing, string CrlDp)
    {
        public override string ToString() => $"{Pairing.CaName}  ·  {CrlTypes.Label(CrlDp)}  ·  {Pairing.ServerUri.Host}";
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
        ClientSize = new Size(900, 620);
        MinimumSize = new Size(720, 520);
        StartPosition = FormStartPosition.CenterScreen;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(16, 12, 16, 8) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        // The app's masthead: mono eyebrow, serif title, italic subtitle, strong rule.
        var header = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Fill };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.Controls.Add(Theme.Eyebrow("Certificate authority · Windows companion"));
        header.Controls.Add(new Label { Text = "Cert Generator Pal", AutoSize = true, Font = Theme.Display, Margin = new Padding(0) });
        header.Controls.Add(_subtitle);
        var profileLabel = Theme.Eyebrow("Profile");
        profileLabel.Margin = new Padding(0, 8, 8, 0);
        _profileRow.Controls.AddRange([profileLabel, _profileBox, _addProfile]);
        _profileBox.SelectedIndexChanged += async (_, _) => await ProfileChosenAsync();
        _addProfile.Click += (_, _) => ShowConnect(adding: true);
        header.Controls.Add(_profileRow);
        _healthRow.Controls.AddRange([_health, _repair]);
        _repair.Click += async (_, _) => await RepairAsync();
        header.Controls.Add(_healthRow);
        var rule = Theme.RuleLine();
        rule.Dock = DockStyle.None;
        rule.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        header.Controls.Add(rule);
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
            if (Clipboard.ContainsText())
            {
                _codeBox.Text = Clipboard.GetText().Trim();
            }
        };
        codeHeader.Controls.Add(paste);
        layout.Controls.Add(codeHeader);
        _codeBox.Font = Theme.Mono;
        _codeBox.BorderStyle = BorderStyle.FixedSingle;
        layout.Controls.Add(_codeBox);
        _connectButton.Margin = new Padding(0, 10, 0, 0);
        _connectButton.Click += async (_, _) => await ConnectAsync();
        var connectRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 10, 0, 0) };
        _connectButton.Margin = new Padding(0, 0, 8, 0);
        _cancelAdd.Click += async (_, _) => await LoadStateAsync();
        connectRow.Controls.AddRange([_connectButton, _cancelAdd]);
        layout.Controls.Add(connectRow);
        layout.Controls.Add(Wrapping("LAN only: Cert Generator Pal talks to your server on your local network and nowhere else. " +
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
                Text = tile switch { TrustTile => "TLS inspection", CrlTile => "Self-hosted CRL", _ => UseCases.Label(tile) },
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
        _list.Columns.Add("Certificate", 230);
        _list.Columns.Add("Use", 120);
        _list.Columns.Add("Store", 150);
        _list.Columns.Add("Expires", 95);
        _list.Columns.Add("Status", 80);
        _list.Columns.Add("Notes", 260);
        _list.SelectedIndexChanged += (_, _) => UpdateActions();
        _list.Resize += (_, _) => FitColumns();
        _list.DrawColumnHeader += DrawHeader;
        _list.DrawItem += (_, e) => e.DrawDefault = false;
        _list.DrawSubItem += DrawCell;
        _list.DoubleClick += (_, _) => ShowDetails();
        _mainPanel.Controls.Add(_list, 0, 3);

        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
        _renew.Click += async (_, _) => await RenewAsync();
        _remove.Click += async (_, _) => await RemoveAsync();
        _details.Click += (_, _) => ShowDetails();
        _refresh.Click += async (_, _) => await RefreshAsync();
        actions.Controls.AddRange([_renew, _remove, _details, _refresh]);
        _mainPanel.Controls.Add(actions, 0, 4);
    }

    /// <summary>The Notes column takes whatever width is left, so the list never scrolls sideways.</summary>
    private void FitColumns()
    {
        if (_list.Columns.Count == 0)
        {
            return;
        }
        int used = 0;
        for (int i = 0; i < _list.Columns.Count - 1; i++)
        {
            used += _list.Columns[i].Width;
        }
        _list.Columns[^1].Width = Math.Max(LogicalToDeviceUnits(120), _list.ClientSize.Width - used - SystemInformation.VerticalScrollBarWidth);
    }

    private TableLayoutPanel BuildFooter()
    {
        var footer = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, AutoSize = true, Margin = new Padding(0, 8, 0, 0) };
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var links = new LinkLabel { AutoSize = true, Text = $"v{Version}  ·  GitHub  ·  Release notes" };
        int github = links.Text.IndexOf("GitHub", StringComparison.Ordinal);
        int notes = links.Text.IndexOf("Release notes", StringComparison.Ordinal);
        links.Links.Clear();
        links.Links.Add(github, "GitHub".Length, RepoUrl);
        links.Links.Add(notes, "Release notes".Length, ReleaseNotesUrl);
        links.LinkClicked += (_, e) => OpenUrl((string)e.Link!.LinkData!);
        footer.Controls.Add(links);
        _disconnect.LinkClicked += async (_, _) => await DisconnectAsync();
        footer.Controls.Add(_disconnect);
        return footer;
    }

    /// <summary>Opens https links only, via explorer.exe so a browser never inherits elevation.</summary>
    private static void OpenUrl(string url)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps && uri.Host == "github.com")
        {
            string explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
            Process.Start(new ProcessStartInfo(explorer, "\"" + uri.AbsoluteUri + "\"") { UseShellExecute = false })?.Dispose();
        }
    }

    // ── State ───────────────────────────────────────────────────────

    private async Task LoadStateAsync()
    {
        _state = DeviceState.Load();
        FillProfiles();
        if (_state is null)
        {
            ShowConnect(adding: false);
            _subtitle.Text = _profileBox.Items.Count > 0 ? "No active profile: pick one above, or add one" : "Not connected";
            await ShowPcNameAsync();
            return;
        }
        _connectPanel.Visible = false;
        _mainPanel.Visible = true;
        _disconnect.Visible = true;
        _subtitle.Text = $"Connected to {_state.ServerUri.Host} · {_state.CaName} · this PC: {_state.Fqdn}";
        _listTitle.Text = $"Certificates from {_state.CaName} on this PC";
        await RefreshAsync();
    }

    private void ShowConnect(bool adding)
    {
        _connectPanel.Visible = true;
        _mainPanel.Visible = false;
        _disconnect.Visible = false;
        _healthRow.Visible = false;
        _cancelAdd.Visible = adding && _state is not null;
        SetStatus(adding ? "Paste another pairing code: it becomes a new profile." : "Paste a pairing code to connect this PC.");
        _codeBox.Focus();
    }

    /// <summary>Every (pairing, allowed revocation type), the active one selected.</summary>
    private void FillProfiles()
    {
        _fillingProfiles = true;
        _profileBox.Items.Clear();
        foreach (var pairing in DeviceState.LoadAll())
        {
            foreach (string crl in pairing.CrlDps.Count > 0 ? pairing.CrlDps : [pairing.CrlDp.Length > 0 ? pairing.CrlDp : "server"])
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
        if (_fillingProfiles || _profileBox.SelectedItem is not ProfileChoice choice
            || (_state is not null && choice.Pairing.DeviceId == _state.DeviceId && choice.CrlDp == _state.CrlDp))
        {
            return;
        }
        var lines = _items.Where(i => i.FromPal is not null && !i.IsCa).Select(i => $"• {i.Names}  ({i.UseLabel}, {i.StoreLabel})").ToList();
        if (_state?.CrlDp == "placeholder")
        {
            lines.Add("• the self-hosted CRL listener");
        }
        string backOut = _state is null ? "" : lines.Count == 0
            ? "\n\nNothing from the current profile is installed, so nothing is removed."
            : $"\n\nThe current profile is backed out. Removed from this PC:\n{string.Join("\n", lines.Take(12))}"
              + (lines.Count > 12 ? $"\n• …and {lines.Count - 12} more" : "") + "\n\nThe root CA stays trusted.";
        string extra = choice.CrlDp == "placeholder" ? "\n\nThe self-hosted CRL listener is set up for the new profile." : "";
        if (MessageBox.Show(this, $"Switch to {choice}?{backOut}{extra}", "Switch profile", MessageBoxButtons.OKCancel,
                MessageBoxIcon.Question) != DialogResult.OK || !BeginBusy("Switching profile… approve the Windows prompt."))
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

    /// <summary>Can this PC reach the revocation addresses its certificates name (and its own listener)?</summary>
    private async Task UpdateHealthAsync()
    {
        if (_state is null || _device is null)
        {
            _healthRow.Visible = false;
            return;
        }
        var urls = _items.Where(i => i.FromPal is not null && !i.IsCa).SelectMany(i => StoreAudit.CrlUrls(i.Cert)).ToHashSet();
        bool selfHosted = _state.CrlDp == "placeholder";
        if (selfHosted)
        {
            urls.UnionWith(_device.SelfHosted.Select(a => a.Url));
        }
        _healthRow.Visible = true;
        if (urls.Count == 0)
        {
            _health.Text = _state.CrlDp == "none" ? "REVOCATION: NOT CHECKED (THIS PROFILE HAS NONE)" : "REVOCATION: NO CERTIFICATES TO CHECK YET";
            _health.ForeColor = Theme.TextDim;
            _repair.Visible = false;
            return;
        }
        var selfUrls = _device.SelfHosted.Select(a => a.Url).ToHashSet();
        var failed = new List<string>();
        foreach (string url in urls)
        {
            bool ok = selfUrls.Contains(url) ? _crlAnswering.GetValueOrDefault(url) : await StoreAudit.ReachableAsync(url);
            if (!ok)
            {
                failed.Add(url);
            }
        }
        _health.Text = failed.Count == 0
            ? $"REVOCATION: ✓ REACHABLE ({urls.Count} ADDRESS{(urls.Count == 1 ? "" : "ES")})"
            : $"REVOCATION: ✗ NOT REACHABLE: {string.Join(", ", failed.Select(u => new Uri(u).Host).Distinct())}";
        _health.ForeColor = failed.Count == 0 ? Theme.Success : Theme.Danger;
        _repair.Visible = failed.Count > 0 && selfHosted;
        _healthTip.SetToolTip(_health, failed.Count == 0 ? string.Join("\n", urls) :
            selfHosted ? "Repair reinstalls this PC's CRL listener and refreshes its CRLs." : "Check that this PC can reach " + string.Join(", ", failed));
    }

    private async Task RepairAsync()
    {
        if (!BeginBusy("Repairing the self-hosted CRL… approve the Windows prompt."))
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
        try
        {
            var state = _state;
            string? serverProblem = null;
            Dictionary<string, string> status = [];
            try
            {
                using var signer = new DeviceSigner(state);
                using var client = new PalClient(state.ServerUri, state.RootSha256);
                _device = await client.GetDeviceAsync(signer);
                if (ChainCheck.RootMatches(_device.Chain, state.RootSha256))
                {
                    state.Chain = _device.Chain;  // picks up a new intermediate; saved by the next elevated step
                }
                _items = await Task.Run(() => StoreAudit.Run(state));
                status = await client.StatusAsync(signer, _items.Select(i => i.Serial).Distinct().ToList());
                _crlAnswering = await LocalCrlServer.ProbeAsync(_device.SelfHosted);
                await UpdateHealthAsync();
            }
            catch (Exception e) when (e is PalException or DeviceKeyUnavailableException or HttpRequestException)
            {
                serverProblem = Operations.FriendlyMessage(e);
                _items = await Task.Run(() => StoreAudit.Run(state));
            }
            StoreAudit.ApplyServer(_items, status, _device);
            UpdateTiles();
            FillList();
            UpdatePending();
            int problems = _items.Count(i => i.Flags.Count > 0);
            SetStatus(serverProblem is not null
                ? "Server: " + serverProblem
                : $"{_items.Count} certificates from {state.CaName}" + (problems > 0 ? $", {problems} need a look." : ". All good."));
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Fail(e);
        }
        finally
        {
            EndBusy();
        }
    }

    private void UpdateTiles()
    {
        var policy = _device?.Policy;
        foreach (var (tile, button) in _tileButtons)
        {
            if (tile == CrlTile)
            {
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
            // A certificate this PC already holds can't be requested again: renew it near expiry instead.
            var installed = _items.FirstOrDefault(i => i.FromPal is { Revoked: 0 } pal && UseCases.FromTemplate(pal.Template) == tile
                && i.ServerStatus != "revoked" && i.Cert.NotAfter > DateTime.Now);
            (string note, Color color) = installed is not null ? ("Installed", Theme.Success)
                : mode switch
                {
                    "auto" => ("Get it now", Theme.AccentText),
                    "approve" => ("Your admin approves", Theme.Warning),
                    _ => (policy is null ? "Server unreachable" : "Not allowed", Theme.TextDim),
                };
            button.SetStatus(note, color);
            button.Enabled = mode != "off" && installed is null && !_busy;
        }
    }

    private void FillList()
    {
        _list.BeginUpdate();
        _list.Items.Clear();
        foreach (var item in _items.OrderBy(i => i.IsCa).ThenBy(i => i.Location).ThenBy(i => i.Names, StringComparer.OrdinalIgnoreCase))
        {
            var row = new ListViewItem(item.Names) { Tag = item };
            row.SubItems.Add(item.UseLabel + (item.FromPal is not null ? " (Pal)" : ""));
            row.SubItems.Add(item.StoreLabel);
            row.SubItems.Add(item.Cert.NotAfter.ToString("d MMM yyyy", CultureInfo.CurrentCulture));
            row.SubItems.Add(item.ServerStatus);
            row.SubItems.Add(string.Join("; ", item.Flags));
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
    }

    private void UpdatePending()
    {
        int local = Operations.PendingCount();
        int server = _device?.Requests.Count(r => r.Status == "pending") ?? 0;
        int count = Math.Max(local, server);
        _pendingBar.Visible = count > 0;
        _pendingLabel.Text = count == 1 ? "1 request is waiting for your admin." : $"{count} requests are waiting for your admin.";
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
        _renew.Text = item?.FromPal is { Revoked: 0 } && renewFrom is { } opens && opens > DateTimeOffset.UtcNow
            ? "RENEW FROM " + opens.ToLocalTime().ToString("d MMM yyyy", CultureInfo.CurrentCulture).ToUpperInvariant()
            : "RENEW";
        int count = _list.SelectedItems.Count;
        _remove.Enabled = !_busy && count > 0;
        _remove.Text = count > 1 ? $"REMOVE {count}" : "REMOVE";
        _details.Enabled = item is not null;
    }

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
        if (_state is not null)
        {
            var lines = _items.Where(i => i.FromPal is not null && !i.IsCa).Select(i => $"• {i.Names}  ({i.UseLabel})").ToList();
            if (_state.CrlDp == "placeholder")
            {
                lines.Add("• the self-hosted CRL listener");
            }
            string backOut = lines.Count == 0 ? "Nothing from it is installed, so nothing is removed."
                : "Removed from this PC:\n" + string.Join("\n", lines.Take(12));
            if (MessageBox.Show(this, $"Add this profile and switch to it?\n\nThe current profile ({_state.CaName} · {CrlTypes.Label(_state.CrlDp)}) " +
                    $"stays in the list but is backed out. {backOut}", "Add profile", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
            {
                return;
            }
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
        await RunRequestAsync(useCase, dialog.Names, dialog.LifetimeDays, renewOf: null, replace: null);
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

    private async Task RunRequestAsync(string useCase, Dictionary<string, object> names, int? lifetime, int? renewOf, string? replace)
    {
        if (_state is null || !BeginBusy($"Requesting {UseCases.Label(useCase)}…"))
        {
            return;
        }
        try
        {
            var op = new HelperOp { Op = "request", UseCase = useCase, Names = names, LifetimeDays = lifetime, RenewOf = renewOf, ReplaceThumbprint = replace };
            OpResult result;
            if (UseCases.IsMachine(useCase))
            {
                result = await Elevation.RunAsync(op);
            }
            else
            {
                try
                {
                    result = await Operations.RequestAsync(_state, useCase, names, lifetime, renewOf, replace);
                }
                catch (DeviceKeyUnavailableException)
                {
                    result = await Elevation.RunAsync(op);  // this PC's key can't be shared with users: do it elevated
                }
            }
            Report(result);
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
    private async Task RemoveAsync()
    {
        var items = SelectedAll;
        if (items.Count == 0)
        {
            return;
        }
        var lines = items.Take(12).Select(i => $"• {i.Names}  ({i.StoreLabel})").ToList();
        if (items.Count > 12)
        {
            lines.Add($"• …and {items.Count - 12} more");
        }
        string warning = items.Any(i => i.IsRoot)
            ? "\n\nThis includes the root CA: this PC will stop trusting every certificate from it." : "";
        string question = items.Count == 1 ? "Remove this certificate?" : $"Remove these {items.Count} certificates?";
        if (MessageBox.Show(this, question + "\n\n" + string.Join("\n", lines) + warning, Text, MessageBoxButtons.OKCancel,
                MessageBoxIcon.Warning) != DialogResult.OK || !BeginBusy("Removing…"))
        {
            return;
        }
        try
        {
            var problems = new List<string>();
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
            if (problems.Count > 0)
            {
                Report(OpResult.Failure("Not all removed. " + string.Join("\n", problems)));
            }
            else
            {
                SetStatus(items.Count == 1 ? "Removed." : $"Removed {items.Count} certificates.");
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

    private void ShowDetails()
    {
        if (Selected is not { } item || _state is null)
        {
            return;
        }
        using var viewer = new CertViewer(item, _state.Chain);
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
            lines.Add("• the self-hosted CRL listener");
        }
        string removed = lines.Count == 0 ? "Nothing from it is installed on this PC."
            : "Removed from this PC:\n" + string.Join("\n", lines.Take(12)) + (lines.Count > 12 ? $"\n• …and {lines.Count - 12} more" : "");
        if (MessageBox.Show(this, $"Remove the profile {_state.CaName} · {CrlTypes.Label(_state.CrlDp)}?\n\n{removed}\n\n" +
                $"This removes the whole {_state.CaName} pairing (all its revocation types); using it again needs a new pairing code. " +
                "The root CA stays trusted.", "Remove profile", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK
            || !BeginBusy("Removing the profile…"))
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
            || !BeginBusy(dialog.Choice == "crl-install" ? "Installing the local CRL server… approve the Windows prompt." : "Removing the local CRL server…"))
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
        TextRenderer.DrawText(e.Graphics, e.Header?.Text.ToUpperInvariant(), Theme.MonoSmall, text, Theme.TextDim,
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
            4 => e.SubItem.Text switch
            {
                "valid" => Theme.Success,
                "revoked" or "expired" => Theme.Danger,
                _ => Theme.TextDim,
            },
            5 => e.Item.ForeColor == Theme.Danger ? Theme.Danger : Theme.Warning,
            0 => e.Item.ForeColor == SystemColors.WindowText || e.Item.ForeColor == Theme.Text ? Theme.Text : e.Item.ForeColor,
            _ => Theme.Text,
        };
        var font = e.ColumnIndex == 4 ? Theme.MonoSmall : e.ColumnIndex == 0 ? Theme.Serif : Theme.Ui;
        string text = e.ColumnIndex == 4 ? e.SubItem.Text.ToUpperInvariant() : e.SubItem.Text;
        var bounds = Rectangle.Inflate(e.Bounds, -LogicalToDeviceUnits(6), 0);
        TextRenderer.DrawText(e.Graphics, text, font, bounds, color, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
    }

    private void Fail(Exception e)
    {
        Operations.Log(e);
        Report(OpResult.Failure(Operations.FriendlyMessage(e)));
    }
}
