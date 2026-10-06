using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace CertGeneratorPal;

/// <summary>
/// Cert Generator's look: the web app's six themes, with the brass accent, serif headings and uppercase
/// mono buttons. Until one is chosen it follows Windows' app setting: Slate when light, Ink when dark.
/// The theme is read once, when the Pal starts.
/// </summary>
internal static partial class Theme
{
    /// <summary>One of the web app's themes: the tokens of its block in app/static/theme.css.</summary>
    private sealed record Palette(string Name, bool Dark, string Bg, string Surface, string SurfaceHover, string Border, string Rule,
        string Text, string TextDim, string AccentText);

    private static readonly Palette[] Palettes =
    [
        new("Slate", false, "#e9ebee", "#f4f5f7", "#dfe2e6", "#cdd1d7", "#6b7280", "#14171c", "#535a66", "#785b0d"),
        new("Flashbang", false, "#ffffff", "#f6f6f9", "#ebebf2", "#dcdce3", "#6b6b76", "#0b0b0f", "#5b5b66", "#81610e"),
        new("OLED", true, "#000000", "#0d0d0d", "#1c1c1c", "#2c2c2c", "#6b6b6b", "#f2f2f2", "#999999", "#d4a017"),
        new("Graphite", true, "#1b1c1f", "#232428", "#2c2d32", "#3a3b41", "#7a7b83", "#ececee", "#a2a3ab", "#d4a017"),
        new("Umber", true, "#1c1915", "#24201b", "#2e2922", "#3d372e", "#857a69", "#efe9df", "#aca395", "#d4a017"),
        new("Ink", true, "#121821", "#19202b", "#212a37", "#2f3a4a", "#6f7d91", "#e8edf3", "#9aa6b6", "#d4a017"),
    ];

    public const string MatchWindows = "Match Windows";

    /// <summary>What the theme list offers: following Windows, then each theme by name.</summary>
    public static IReadOnlyList<string> Choices { get; } = [MatchWindows, .. Palettes.Select(p => p.Name)];

    /// <summary>The choice this run started with.</summary>
    public static readonly string Choice = ReadChoice();

    private static readonly Palette Current = Palettes.FirstOrDefault(p => p.Name == Choice)
        ?? Palettes.First(p => p.Name == (IsWindowsDark() ? "Ink" : "Slate"));

    public static readonly bool Dark = Current.Dark;

    public static readonly Color Bg = Hex(Current.Bg);
    public static readonly Color Surface = Hex(Current.Surface);
    public static readonly Color SurfaceHover = Hex(Current.SurfaceHover);
    public static readonly Color Border = Hex(Current.Border);
    public static readonly Color Rule = Hex(Current.Rule);
    public static readonly Color Text = Hex(Current.Text);
    public static readonly Color TextDim = Hex(Current.TextDim);
    public static readonly Color Accent = Hex("#d4a017");
    public static readonly Color AccentText = Hex(Current.AccentText);
    public static readonly Color OnAccent = Hex("#0b0b0f");
    public static readonly Color Success = Dark ? Hex("#8fc29a") : Hex("#2d6a45");
    public static readonly Color Danger = Dark ? Hex("#e8877c") : Hex("#9e2a2b");
    public static readonly Color Warning = Dark ? Hex("#e39a6b") : Hex("#9a4a1a");
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

    private static string ChoiceFile => Path.Combine(Paths.UserDir, "theme.txt");

    /// <summary>The saved theme; following Windows when none was saved, or the file names no theme.</summary>
    private static string ReadChoice()
    {
        try
        {
            string saved = File.Exists(ChoiceFile) ? File.ReadAllText(ChoiceFile).Trim() : "";
            return Palettes.Any(p => p.Name == saved) ? saved : MatchWindows;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return MatchWindows;
        }
    }

    /// <summary>Keep <paramref name="choice"/> (one of <see cref="Choices"/>) for the next start.</summary>
    public static void SaveChoice(string choice) => File.WriteAllText(ChoiceFile, choice);

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
