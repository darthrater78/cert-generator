using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace CertGeneratorPal;

/// <summary>
/// The masthead's notary seal: the connected CA's name around the ring, its initial in the
/// middle and this PC's domain along the bottom. Drawn here, so it needs no image file and
/// follows the theme. Decoration only: everything it says is also in the subtitle beside it.
/// </summary>
internal sealed class SealControl : Control
{
    private const int MaxNameLength = 28;
    private const float MaxArcDegrees = 150f;
    private string? _caName;
    private string? _domain;

    public SealControl()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw, true);
        SetStyle(ControlStyles.Selectable, false);
        Size = new Size(112, 112);
        Margin = new Padding(12, 0, 0, 6);
        TabStop = false;
        AccessibleRole = AccessibleRole.Graphic;
    }

    /// <summary>Show the seal of <paramref name="caName"/>; null for a PC that isn't connected.</summary>
    public void SetCa(string? caName, string? domain)
    {
        _caName = string.IsNullOrWhiteSpace(caName) ? null : caName.Trim();
        _domain = string.IsNullOrWhiteSpace(domain) ? null : domain.Trim();
        AccessibleName = _caName is null ? "Not connected" : "Seal of " + _caName;
        Invalidate();
    }

    /// <summary>The part of a PC's DNS name after its host name (pc01.corp.lan → corp.lan); null when it has none.</summary>
    public static string? DomainOf(string? fqdn)
    {
        int dot = fqdn?.IndexOf('.', StringComparison.Ordinal) ?? -1;
        return dot > 0 && dot < fqdn!.Length - 1 ? fqdn[(dot + 1)..] : null;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.Clear(Parent?.BackColor ?? Theme.Bg);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;

        float size = Math.Min(ClientSize.Width, ClientSize.Height);
        float unit = size / 200f;  // the seal is designed on a 200-unit square
        var centre = new PointF(ClientSize.Width / 2f, ClientSize.Height / 2f);
        Color ink = _caName is null ? Theme.TextDim : Theme.AccentText;
        using var brush = new SolidBrush(ink);

        foreach (var (radius, width) in new[] { (95f, 3f), (89f, 1f), (62f, 1f), (57f, 2.5f) })
        {
            using var pen = new Pen(ink, Math.Max(1f, width * unit));
            float r = radius * unit;
            g.DrawEllipse(pen, centre.X - r, centre.Y - r, r * 2, r * 2);
        }
        foreach (float x in new[] { -76f, 76f })  // a diamond at nine and three o'clock, between the two legends
        {
            float d = 5f * unit, cx = centre.X + (x * unit);
            g.FillPolygon(brush, [new PointF(cx - d, centre.Y), new PointF(cx, centre.Y - d), new PointF(cx + d, centre.Y), new PointF(cx, centre.Y + d)]);
        }

        string top = Shorten((_caName ?? "Cert Generator Pal").ToUpperInvariant());
        string bottom = Shorten((_caName is null ? "Not connected" : _domain ?? "Trusted on this PC").ToUpperInvariant());
        DrawArc(g, brush, top, centre, 67f * unit, 17f * unit, 3f * unit, alongTop: true);
        DrawArc(g, brush, bottom, centre, 85.5f * unit, 13.5f * unit, 2.2f * unit, alongTop: false);

        if (_caName is { Length: > 0 } name)
        {
            using var letter = new Font("Georgia", 62f * unit, FontStyle.Regular, GraphicsUnit.Pixel);
            using var middle = new StringFormat(StringFormat.GenericTypographic) { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString(char.ToUpperInvariant(name[0]).ToString(), letter, brush, new PointF(centre.X, centre.Y - (4f * unit)), middle);
            using var rule = new Pen(ink, Math.Max(1f, unit));
            g.DrawLine(rule, centre.X - (30f * unit), centre.Y + (34f * unit), centre.X + (30f * unit), centre.Y + (34f * unit));
        }
    }

    private static string Shorten(string text) => text.Length <= MaxNameLength ? text : text[..(MaxNameLength - 1)] + "…";

    /// <summary>
    /// Set <paramref name="text"/> around the ring, centred on twelve o'clock (reading clockwise,
    /// letters standing outwards from <paramref name="radius"/>) or on six o'clock (reading left to
    /// right, letters standing inwards). The type shrinks until the legend fits its arc.
    /// </summary>
    private static void DrawArc(Graphics g, Brush brush, string text, PointF centre, float radius, float fontPixels, float tracking, bool alongTop)
    {
        using var format = new StringFormat(StringFormat.GenericTypographic) { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Far };
        format.FormatFlags |= StringFormatFlags.MeasureTrailingSpaces;
        for (float pixels = fontPixels; ; pixels -= 0.5f)
        {
            float scale = pixels / fontPixels;
            using var font = new Font(Theme.MonoSmall.FontFamily, pixels, FontStyle.Bold, GraphicsUnit.Pixel);
            float[] widths = text.Select(ch => g.MeasureString(ch.ToString(), font, PointF.Empty, format).Width + (tracking * scale)).ToArray();
            float degrees = widths.Sum() / radius * (180f / MathF.PI);
            if (degrees > MaxArcDegrees && pixels > fontPixels * 0.5f)
            {
                continue;  // too long for the arc at this size: try smaller
            }
            // Screen angles: 0° is three o'clock and they grow clockwise, so the top is -90° and the bottom +90°.
            float angle = alongTop ? -90f - (degrees / 2f) : 90f + (degrees / 2f);
            for (int i = 0; i < text.Length; i++)
            {
                float step = widths[i] / radius * (180f / MathF.PI);
                float at = alongTop ? angle + (step / 2f) : angle - (step / 2f);
                float radians = at * (MathF.PI / 180f);
                var state = g.Save();
                g.TranslateTransform(centre.X + (radius * MathF.Cos(radians)), centre.Y + (radius * MathF.Sin(radians)));
                g.RotateTransform(alongTop ? at + 90f : at - 90f);
                g.DrawString(text[i].ToString(), font, brush, PointF.Empty, format);
                g.Restore(state);
                angle += alongTop ? step : -step;
            }
            return;
        }
    }
}
