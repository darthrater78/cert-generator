using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace CertGeneratorPal;

/// <summary>
/// A readable certificate view: what it is, whether it's good, what it's for, who issued it and
/// where its key lives, in plain words. Windows' own dialog stays one click away for the details.
/// </summary>
internal sealed partial class CertViewer : Form
{
    private static readonly Dictionary<string, string> Purposes = new()
    {
        ["1.3.6.1.5.5.7.3.1"] = "Web server (TLS server authentication)",
        ["1.3.6.1.5.5.7.3.2"] = "Client sign-in (TLS client authentication)",
        ["1.3.6.1.5.5.7.3.3"] = "Code signing",
        ["1.3.6.1.5.5.7.3.4"] = "Email protection (S/MIME)",
        ["1.3.6.1.4.1.311.20.2.2"] = "Smart card logon",
        ["1.3.6.1.5.5.7.3.8"] = "Time stamping",
        ["1.3.6.1.5.5.7.3.9"] = "OCSP signing",
    };

    private readonly AuditItem _item;
    private readonly TableLayoutPanel _grid = new() { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Top, Padding = new Padding(0, 4, 0, 0) };

    public CertViewer(AuditItem item, IReadOnlyList<string> chainRootFirst, string renew = "")
    {
        _item = item;
        var cert = item.Cert;
        SuspendLayout();
        AutoScaleDimensions = new SizeF(96F, 96F);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Certificate: " + item.Names;
        ClientSize = new Size(700, 640);
        MinimumSize = new Size(560, 420);
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        MinimizeBox = false;

        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(20, 16, 20, 8) };
        _grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        // Header: name, status, validity.
        var (statusText, statusColor) = Status(item);
        var header = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Dock = DockStyle.Top };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.Controls.Add(new Label
        {
            Text = item.Names,
            AutoSize = true,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Font = Theme.Display,
        });
        header.Controls.Add(new Label
        {
            Text = statusText,
            AutoSize = true,
            ForeColor = statusColor == Theme.Success || statusColor == Theme.Danger ? Theme.Bg : Theme.OnAccent,
            BackColor = statusColor,
            Padding = new Padding(8, 3, 8, 3),
            Margin = new Padding(0, 6, 0, 4),
            Font = Theme.MonoSmall,
        });
        header.Controls.Add(new Label { Text = Validity(cert), AutoSize = true, Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(0, 0, 0, 6) });
        if (item.Flags.Count > 0)
        {
            header.Controls.Add(new Label
            {
                Text = "⚠ " + string.Join("\n⚠ ", item.Flags),
                AutoSize = true,
                Anchor = AnchorStyles.Left | AnchorStyles.Right,
                ForeColor = Theme.Warning,
                Margin = new Padding(0, 0, 0, 6),
            });
        }

        Section("Names");
        Row("Issued to", cert.GetNameInfo(X509NameType.SimpleName, false));
        foreach (var (label, value) in SubjectAltNames(cert))
        {
            Row(label, value);
        }

        Section("What it's for");
        Row("Type", item.IsRoot ? "Root certificate authority" : item.IsCa ? "Intermediate certificate authority" : item.UseLabel
            + (item.FromPal is not null ? " (requested by Cert Generator Pal)" : ""));
        if (Uses(cert) is { Length: > 0 } uses)
        {
            Row("Used for", uses);
        }

        Section("Issued by");
        Row("Chain", ChainText(cert, chainRootFirst));
        if (CrlUrls(cert) is { Count: > 0 } crls)
        {
            Row("Revocation check", string.Join("\n", crls));
        }

        Section("Key");
        Row("Public key", KeyText(cert));
        if (!item.IsCa || cert.HasPrivateKey)
        {
            Row("Private key", PrivateKeyText(cert));
        }

        Section("Validity");
        Row("Valid from", cert.NotBefore.ToString("dddd d MMMM yyyy, HH:mm:ss", CultureInfo.CurrentCulture));
        Row("Valid to", cert.NotAfter.ToString("dddd d MMMM yyyy, HH:mm:ss", CultureInfo.CurrentCulture));
        Row("Time left", TimeLeft(cert));
        if (renew.Length > 0 && item.FromPal?.RenewFromTime is { } opens)
        {
            Row("Renewal", renew == "now"
                ? "Open now: choose Renew for a new key and certificate"
                : $"Opens {opens.ToLocalTime().ToString("d MMM yyyy, HH:mm", CultureInfo.CurrentCulture)} ({renew})");
        }

        Section("On this PC");
        Row("Installed in", (item.Location == StoreLocation.LocalMachine ? "Computer" : "Current user") + " › " + StoreLabel(item.StoreName));
        Row("Server says", item.ServerStatus switch
        {
            "valid" => "Valid: issued by your Cert Generator and not revoked",
            "revoked" => "REVOKED by your admin: remove it",
            "expired" => "Expired",
            _ => "Not known to the server (installed some other way, or the server is unreachable)",
        });

        Section("Identifiers");
        Row("Serial number", Spaced(cert.SerialNumber), mono: true);
        Row("SHA-256 fingerprint", Spaced(Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256))), mono: true);
        Row("SHA-1 thumbprint", Spaced(cert.Thumbprint), mono: true);

        // Everything else in the certificate, as Windows' own Details tab lists it.
        Section("All details");
        Row("Version", "V" + cert.Version.ToString(CultureInfo.InvariantCulture));
        Row("Subject", cert.SubjectName.Format(true).TrimEnd());
        Row("Issuer", cert.IssuerName.Format(true).TrimEnd());
        Row("Signature algorithm", cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "");
        Row("Public key parameters", PublicKeyDetail(cert), mono: true);
        foreach (var ext in cert.Extensions)
        {
            string name = (ext.Oid?.FriendlyName is { Length: > 0 } friendly ? friendly : ext.Oid?.Value ?? "Extension") + (ext.Critical ? " (critical)" : "");
            string value = ext.Format(true).Trim();
            Row(name, value.Length > 0 ? value : Convert.ToHexString(ext.RawData), mono: value.Length == 0);
        }

        scroll.Controls.Add(_grid);
        scroll.Controls.Add(header);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(12, 8, 12, 12) };
        var close = new Button { Text = "Close", AutoSize = true, DialogResult = DialogResult.Cancel };
        var windows = new Button { Text = "Open in Windows", AutoSize = true };
        var save = new Button { Text = "Save…", AutoSize = true };
        var copy = new Button { Text = "Copy PEM", AutoSize = true };
        windows.Click += (_, _) => OpenInWindows();
        save.Click += (_, _) => Save();
        copy.Click += (_, _) =>
        {
            Clipboard.SetText(cert.ExportCertificatePem());
            copy.Text = "Copied ✓";
        };
        buttons.Controls.AddRange([close, windows, save, copy]);
        Controls.Add(scroll);
        Controls.Add(buttons);
        CancelButton = close;
        Theme.Apply(this);
        ResumeLayout(false);
        PerformLayout();
    }

    // ── Layout helpers ──────────────────────────────────────────────

    private void Section(string title)
    {
        var label = new Label
        {
            Text = title,
            AutoSize = true,
            Font = Theme.Heading,
            Margin = new Padding(0, 14, 0, 4),
        };
        _grid.Controls.Add(label);
        _grid.SetColumnSpan(label, 2);
    }

    private void Row(string label, string value, bool mono = false)
    {
        _grid.Controls.Add(new Label
        {
            Text = label,
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Margin = new Padding(0, 3, 16, 3),
        });
        // A borderless read-only box: looks like text, but can be selected and copied.
        int lines = value.Split('\n').Length;
        var box = new TextBox
        {
            Text = value.ReplaceLineEndings(Environment.NewLine),
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            BackColor = SystemColors.Control,
            Multiline = lines > 1 || value.Length > 60,
            WordWrap = true,
            Anchor = AnchorStyles.Left | AnchorStyles.Right,
            Margin = new Padding(0, 3, 0, 3),
            TabStop = false,
            Font = mono ? Theme.Mono : Theme.Ui,
        };
        if (box.Multiline)
        {
            int estimated = Math.Max(lines, (value.Length / 60) + 1);
            box.Height = (box.Font.Height * estimated) + 4;
        }
        _grid.Controls.Add(box);
    }

    // ── Content ─────────────────────────────────────────────────────

    private static (string Text, Color Color) Status(AuditItem item)
    {
        var cert = item.Cert;
        if (item.ServerStatus == "revoked")
        {
            return ("REVOKED", Theme.Danger);
        }
        if (cert.NotAfter < DateTime.Now)
        {
            return ("EXPIRED", Theme.Danger);
        }
        if (cert.NotBefore > DateTime.Now)
        {
            return ("NOT VALID YET", Theme.Warning);
        }
        if (cert.NotAfter < DateTime.Now.AddDays(30))
        {
            return ("EXPIRES SOON", Theme.Warning);
        }
        return ("VALID", Theme.Success);
    }

    private static string Validity(X509Certificate2 cert)
    {
        int days = (int)Math.Floor((cert.NotAfter - DateTime.Now).TotalDays);
        string range = $"Valid {cert.NotBefore.ToString("d MMM yyyy", CultureInfo.CurrentCulture)} to {cert.NotAfter.ToString("d MMM yyyy", CultureInfo.CurrentCulture)}";
        return days >= 0
            ? range + $" · {days.ToString("N0", CultureInfo.CurrentCulture)} days left"
            : range + $" · expired {(-days).ToString("N0", CultureInfo.CurrentCulture)} days ago";
    }

    private static string TimeLeft(X509Certificate2 cert)
    {
        var left = cert.NotAfter - DateTime.Now;
        if (left <= TimeSpan.Zero)
        {
            return "Expired";
        }
        int days = (int)left.TotalDays;
        return days >= 1 ? $"{days.ToString("N0", CultureInfo.CurrentCulture)} days, {left.Hours} hours" : $"{left.Hours} hours, {left.Minutes} minutes";
    }

    private static string PublicKeyDetail(X509Certificate2 cert)
    {
        string oid = cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "";
        byte[] key = cert.PublicKey.EncodedKeyValue.RawData;
        return $"{oid}, {key.Length} bytes\n{Spaced(Convert.ToHexString(key))}";
    }

    private static List<(string, string)> SubjectAltNames(X509Certificate2 cert)
    {
        var rows = new List<(string, string)>();
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san is null)
        {
            return rows;
        }
        var dns = san.EnumerateDnsNames().ToList();
        var ips = san.EnumerateIPAddresses().Select(ip => ip.ToString()).ToList();
        if (dns.Count > 0)
        {
            rows.Add(("DNS names", string.Join("\n", dns)));
        }
        if (ips.Count > 0)
        {
            rows.Add(("IP addresses", string.Join("\n", ips)));
        }
        // Sign-in name and e-mail: Windows formats these for us.
        foreach (string line in san.Format(true).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (line.StartsWith("RFC822 Name=", StringComparison.OrdinalIgnoreCase))
            {
                rows.Add(("E-mail", line["RFC822 Name=".Length..]));
            }
            else if (line.Contains("Principal Name=", StringComparison.OrdinalIgnoreCase))
            {
                rows.Add(("Sign-in name (UPN)", line[(line.IndexOf("Principal Name=", StringComparison.OrdinalIgnoreCase) + "Principal Name=".Length)..]));
            }
        }
        return rows;
    }

    private static string Uses(X509Certificate2 cert)
    {
        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is null)
        {
            return "";
        }
        return string.Join("\n", eku.EnhancedKeyUsages.Cast<Oid>().Select(o => Purposes.GetValueOrDefault(o.Value ?? "", o.FriendlyName ?? o.Value ?? "")));
    }

    private static string ChainText(X509Certificate2 cert, IReadOnlyList<string> chainRootFirst)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        foreach (string pem in chainRootFirst)
        {
            chain.ChainPolicy.ExtraStore.Add(X509Certificate2.CreateFromPem(pem));
        }
        chain.Build(cert);
        var lines = new List<string>();
        for (int i = chain.ChainElements.Count - 1; i >= 0; i--)
        {
            var element = chain.ChainElements[i];
            string name = element.Certificate.GetNameInfo(X509NameType.SimpleName, false);
            bool ok = element.ChainElementStatus.All(s => s.Status is X509ChainStatusFlags.NoError or X509ChainStatusFlags.NotTimeValid
                or X509ChainStatusFlags.RevocationStatusUnknown or X509ChainStatusFlags.OfflineRevocation);
            string role = i == chain.ChainElements.Count - 1 ? "root" : i == 0 ? "this certificate" : "intermediate";
            lines.Add($"{new string(' ', (chain.ChainElements.Count - 1 - i) * 3)}{(i == chain.ChainElements.Count - 1 ? "" : "└ ")}{name} ({role}){(ok ? " ✓" : " ✗ not trusted on this PC")}");
        }
        return string.Join("\n", lines);
    }

    [GeneratedRegex(@"https?://[^\s,;]+", RegexOptions.IgnoreCase)]
    private static partial Regex UrlPattern();

    private static List<string> CrlUrls(X509Certificate2 cert)
    {
        var ext = cert.Extensions["2.5.29.31"];
        return ext is null ? [] : UrlPattern().Matches(ext.Format(true)).Select(m => m.Value).Distinct().ToList();
    }

    private static string KeyText(X509Certificate2 cert)
    {
        using var ec = cert.GetECDsaPublicKey();
        if (ec is not null)
        {
            return $"ECDSA {ec.KeySize}-bit (P-{ec.KeySize})";
        }
        using var rsa = cert.GetRSAPublicKey();
        return rsa is not null ? $"RSA {rsa.KeySize}-bit" : cert.PublicKey.Oid.FriendlyName ?? "Unknown";
    }

    private static string PrivateKeyText(X509Certificate2 cert)
    {
        if (!cert.HasPrivateKey)
        {
            return "Not on this PC";
        }
        try
        {
            CngKey? key = (cert.GetECDsaPrivateKey() as ECDsaCng)?.Key ?? (cert.GetRSAPrivateKey() as RSACng)?.Key;
            if (key is null)
            {
                return "On this PC";
            }
            string where = key.Provider == CngProvider.MicrosoftPlatformCryptoProvider ? "in the TPM chip"
                : key.Provider == CngProvider.MicrosoftSmartCardKeyStorageProvider ? "on a smart card"
                : "in Windows' software key store";
            string export = key.ExportPolicy == CngExportPolicies.None ? "can't be exported" : "can be exported";
            return $"On this PC, {where}; {export}";
        }
        catch (CryptographicException)
        {
            return "On this PC (details need administrator rights)";
        }
    }

    private static string StoreLabel(string store) => store switch
    {
        "My" => "Personal",
        "Root" => "Trusted Root Certification Authorities",
        "CA" => "Intermediate Certification Authorities",
        "WebHosting" => "Web Hosting",
        "TrustedPeople" => "Trusted People",
        _ => store,
    };

    private static string Spaced(string hex) =>
        string.Join(' ', Enumerable.Range(0, (hex.Length + 1) / 2).Select(i => hex.Substring(i * 2, Math.Min(2, hex.Length - (i * 2)))));

    // ── Actions ─────────────────────────────────────────────────────

    private void Save()
    {
        using var dialog = new SaveFileDialog
        {
            FileName = string.Concat(_item.Names.Split(Path.GetInvalidFileNameChars())).Split(',')[0].Trim() + ".cer",
            Filter = "Certificate (*.cer)|*.cer|PEM (*.pem)|*.pem",
        };
        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }
        if (dialog.FilterIndex == 2)
        {
            File.WriteAllText(dialog.FileName, _item.Cert.ExportCertificatePem());
        }
        else
        {
            File.WriteAllBytes(dialog.FileName, _item.Cert.Export(X509ContentType.Cert));
        }
    }

    private void OpenInWindows()
    {
        string path = Path.Combine(Path.GetTempPath(), "CertGeneratorPal-" + _item.Cert.Thumbprint + ".cer");
        File.WriteAllBytes(path, _item.Cert.Export(X509ContentType.Cert));
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true })?.Dispose();
    }
}
