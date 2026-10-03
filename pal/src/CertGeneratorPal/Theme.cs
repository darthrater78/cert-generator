using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CertGeneratorPal;

/// <summary>
/// Cert Generator's look: its Slate theme (light) or Ink theme (dark), following Windows'
/// app setting, with the brass accent, serif headings and uppercase mono buttons.
/// </summary>
internal static partial class Theme
{
    public static readonly bool Dark = IsWindowsDark();

    public static readonly Color Bg = Dark ? Hex("#121821") : Hex("#e9ebee");
    public static readonly Color Surface = Dark ? Hex("#19202b") : Hex("#f4f5f7");
    public static readonly Color SurfaceHover = Dark ? Hex("#212a37") : Hex("#dfe2e6");
    public static readonly Color Border = Dark ? Hex("#2f3a4a") : Hex("#cdd1d7");
    public static readonly Color Rule = Dark ? Hex("#6f7d91") : Hex("#6b7280");
    public static readonly Color Text = Dark ? Hex("#e8edf3") : Hex("#14171c");
    public static readonly Color TextDim = Dark ? Hex("#9aa6b6") : Hex("#535a66");
    public static readonly Color Accent = Hex("#d4a017");
    public static readonly Color AccentText = Dark ? Hex("#d4a017") : Hex("#785b0d");
    public static readonly Color OnAccent = Hex("#0b0b0f");
    public static readonly Color Success = Dark ? Hex("#4ade80") : Hex("#15803d");
    public static readonly Color Danger = Dark ? Hex("#f87171") : Hex("#b91c1c");
    public static readonly Color Warning = Dark ? Hex("#fbbf24") : Hex("#b45309");
    public static readonly Color Selection = Blend(Accent, Surface, Dark ? 0.28 : 0.22);

    public static readonly Font Ui = new("Segoe UI", 9.75f);
    public static readonly Font UiBold = new("Segoe UI", 9.75f, FontStyle.Bold);
    public static readonly Font Display = new("Georgia", 21f);
    public static readonly Font Heading = new("Georgia", 13f);
    public static readonly Font Serif = new("Georgia", 10.5f);
    public static readonly Font SerifItalic = new("Georgia", 10f, FontStyle.Italic);
    public static readonly Font Mono = new(MonoFamily(), 9f);
    public static readonly Font MonoSmall = new(MonoFamily(), 7.75f, FontStyle.Bold);

    public enum ButtonKind { Ghost, Primary, Danger }

    private static Color Hex(string hex) => ColorTranslator.FromHtml(hex);

    public static Color Blend(Color a, Color b, double amountOfA) => Color.FromArgb(
        (int)((a.R * amountOfA) + (b.R * (1 - amountOfA))),
        (int)((a.G * amountOfA) + (b.G * (1 - amountOfA))),
        (int)((a.B * amountOfA) + (b.B * (1 - amountOfA))));

    private static string MonoFamily() =>
        FontFamily.Families.Any(f => f.Name == "Cascadia Mono") ? "Cascadia Mono" : "Consolas";

    private static bool IsWindowsDark()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
    }

    /// <summary>Style a form and everything on it.</summary>
    public static void Apply(Form form)
    {
        form.BackColor = Bg;
        form.ForeColor = Text;
        form.Font = Ui;
        form.HandleCreated += (_, _) => DarkTitleBar(form);
        ApplyChildren(form);
    }

    public static void ApplyChildren(Control parent)
    {
        foreach (Control c in parent.Controls)
        {
            switch (c)
            {
                case Button b:
                    Style(b, b.Tag as ButtonKind? ?? ButtonKind.Ghost);
                    break;
                case LinkLabel link:
                    link.LinkColor = link.ActiveLinkColor = link.VisitedLinkColor = AccentText;
                    link.BackColor = Color.Transparent;
                    break;
                case TextBox t:
                    t.BackColor = t.ReadOnly && t.BorderStyle == BorderStyle.None ? parent.BackColor : Surface;
                    t.ForeColor = Text;
                    break;
                case NumericUpDown n:
                    n.BackColor = Surface;
                    n.ForeColor = Text;
                    break;
                case ListView l:
                    l.BackColor = Surface;
                    l.ForeColor = Text;
                    break;
                case Label label when label.ForeColor == SystemColors.GrayText:
                    label.ForeColor = TextDim;
                    break;
                case Label label when label.ForeColor == SystemColors.ControlText:
                    label.ForeColor = Text;
                    break;
            }
            ApplyChildren(c);
        }
    }

    /// <summary>The app's buttons: square, 1px border, uppercase mono label.</summary>
    public static void Style(Button b, ButtonKind kind)
    {
        b.Tag = kind;
        b.FlatStyle = FlatStyle.Flat;
        b.FlatAppearance.BorderSize = 1;
        b.Font = MonoSmall;
        b.Text = b.Text.ToUpperInvariant();
        b.Padding = new Padding(10, 4, 10, 4);
        b.Cursor = Cursors.Hand;
        b.UseVisualStyleBackColor = false;
        (Color back, Color fore, Color border, Color hover) = kind switch
        {
            ButtonKind.Primary => (Accent, OnAccent, Accent, Blend(Accent, Color.White, 0.85)),
            ButtonKind.Danger => (Color.Transparent, Danger, Danger, Blend(Danger, Bg, 0.15)),
            _ => (Color.Transparent, Text, Rule, SurfaceHover),
        };
        b.BackColor = back;
        b.ForeColor = fore;
        b.FlatAppearance.BorderColor = border;
        b.FlatAppearance.MouseOverBackColor = hover;
        b.FlatAppearance.MouseDownBackColor = hover;
    }

    /// <summary>A small uppercase mono caption, like the app's eyebrows and table headers.</summary>
    public static Label Eyebrow(string text) => new()
    {
        Text = text.ToUpperInvariant(),
        AutoSize = true,
        Font = MonoSmall,
        ForeColor = TextDim,
        Margin = new Padding(0, 0, 0, 2),
    };

    /// <summary>The app's section rule: a heading over a strong line.</summary>
    public static Panel RuleLine() => new() { Height = 2, Dock = DockStyle.Top, BackColor = Rule, Margin = new Padding(0, 0, 0, 8) };

    private static void DarkTitleBar(Form form)
    {
        if (!Dark)
        {
            return;
        }
        int on = 1;
        _ = DwmSetWindowAttribute(form.Handle, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, ref on, sizeof(int));
    }

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
