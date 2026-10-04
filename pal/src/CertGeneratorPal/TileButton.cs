namespace CertGeneratorPal;

/// <summary>A request tile in the app's style: flat surface, 1px border, serif title, mono status line.</summary>
internal sealed class TileButton : Control
{
    private static readonly Font SubtitleFont = new("Segoe UI", 8.25f);
    private bool _hover;
    private string _status = "";
    private Color _statusColor = Theme.TextDim;

    public TileButton()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint
            | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
        Cursor = Cursors.Hand;
        TabStop = true;
        Size = new Size(222, 82);
        Margin = new Padding(0, 0, 10, 10);
        AccessibleRole = AccessibleRole.PushButton;
    }

    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public string Subtitle { get; set; } = "";

    public void SetStatus(string text, Color color)
    {
        _status = text.ToUpperInvariant();
        _statusColor = color;
        AccessibleDescription = text;
        Invalidate();
    }

    protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }

    protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }

    protected override void OnEnabledChanged(EventArgs e) { Cursor = Enabled ? Cursors.Hand : Cursors.Default; Invalidate(); base.OnEnabledChanged(e); }

    protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }

    protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode is System.Windows.Forms.Keys.Enter or System.Windows.Forms.Keys.Space)
        {
            OnClick(EventArgs.Empty);
        }
        base.OnKeyDown(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        bool live = Enabled;
        g.Clear(live && _hover ? Theme.SurfaceHover : Theme.Surface);
        var border = Focused ? Theme.Accent : live && _hover ? Theme.Text : Theme.Border;
        using (var pen = new Pen(border, Focused ? 2 : 1))
        {
            g.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
        }
        if (live)
        {
            using var accent = new SolidBrush(Theme.Accent);
            g.FillRectangle(accent, 0, 0, LogicalToDeviceUnits(3), Height);  // the app's brass edge
        }
        int pad = LogicalToDeviceUnits(14);
        var title = new Rectangle(pad, LogicalToDeviceUnits(9), Width - pad - LogicalToDeviceUnits(8), Theme.Heading.Height + 2);
        TextRenderer.DrawText(g, Text, Theme.Heading, title, live ? Theme.Text : Theme.TextDim, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
        var sub = new Rectangle(pad, title.Bottom + LogicalToDeviceUnits(1), title.Width, Theme.Ui.Height);
        TextRenderer.DrawText(g, Subtitle, SubtitleFont, sub, Theme.TextDim, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
        var status = new Rectangle(pad, sub.Bottom + LogicalToDeviceUnits(3), title.Width, Theme.MonoSmall.Height);
        // The status keeps its colour on a disabled tile too: it says why (red unreachable, green installed…).
        TextRenderer.DrawText(g, _status, Theme.MonoSmall, status, _statusColor, TextFormatFlags.EndEllipsis | TextFormatFlags.NoPadding);
    }
}
