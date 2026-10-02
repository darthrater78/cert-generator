"""Generate the app icons: a certificate with a brass rosette and ribbon, on the app's slate.

Writes app/icon.ico + app/icon.png (Cert Generator), app/static/icon.ico (web favicon) and
pal/src/CertGeneratorPal/pal.ico (Cert Generator Pal: the same mark with a PC badge).
Drawn on a 256-unit grid at 4x and scaled down per size, so small sizes stay crisp.
"""
from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
SLATE = (29, 33, 41, 255)
SLATE_EDGE = (42, 48, 59, 255)
BRASS = (212, 160, 23, 255)
BRASS_DARK = (168, 124, 12, 255)
IVORY = (244, 239, 227, 255)
INK_LINE = (185, 178, 162, 255)
INK_LINE_LIGHT = (207, 200, 184, 255)

SUPER = 4                      # supersampling factor
GRID = 256                     # design units
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)


class Canvas:
    """Draws on the 256-unit design grid at ``px`` pixels per side."""

    def __init__(self, px: int) -> None:
        self.k = px / GRID
        self.img = Image.new("RGBA", (px, px), (0, 0, 0, 0))
        self.draw = ImageDraw.Draw(self.img)

    def s(self, v: float) -> float:
        return v * self.k

    def pts(self, points: list[tuple[float, float]]) -> list[tuple[float, float]]:
        return [(self.s(x), self.s(y)) for x, y in points]

    def rrect(self, x0: float, y0: float, x1: float, y1: float, r: float, fill, outline=None, width: float = 0) -> None:
        self.draw.rounded_rectangle([self.s(x0), self.s(y0), self.s(x1), self.s(y1)], radius=self.s(r), fill=fill,
                                    outline=outline, width=max(1, round(self.s(width))) if outline else 0)


def scallop(cx: float, cy: float, outer: float, inner: float, peaks: int) -> list[tuple[float, float]]:
    return [(cx + (outer if i % 2 == 0 else inner) * math.cos(math.pi * i / peaks - math.pi / 2),
             cy + (outer if i % 2 == 0 else inner) * math.sin(math.pi * i / peaks - math.pi / 2))
            for i in range(peaks * 2)]


def draw_background(c: Canvas) -> None:
    c.rrect(8, 8, 248, 248, 52, SLATE, SLATE_EDGE, 4)


def draw_certificate(px: int) -> Image.Image:
    """The ivory sheet with its text lines, tilted 6° like a document set down on a desk."""
    sheet = Canvas(px)
    sheet.rrect(52, 46, 184, 210, 10, IVORY)
    sheet.rrect(72, 74, 164, 83, 4.5, INK_LINE)
    sheet.rrect(72, 96, 144, 105, 4.5, INK_LINE_LIGHT)
    sheet.rrect(72, 118, 154, 127, 4.5, INK_LINE_LIGHT)
    return sheet.img.rotate(6, resample=Image.BICUBIC, center=(sheet.s(128), sheet.s(128)))


def draw_rosette(c: Canvas) -> None:
    c.draw.polygon(c.pts([(152, 176), (140, 228), (160, 216), (174, 234), (182, 182)]), fill=BRASS_DARK)
    c.draw.polygon(c.pts([(188, 176), (200, 228), (180, 216), (166, 234), (158, 182)]), fill=BRASS_DARK)
    c.draw.polygon(c.pts(scallop(170, 168, 36, 30, 16)), fill=BRASS)
    r = 18
    c.draw.ellipse([c.s(170 - r), c.s(168 - r), c.s(170 + r), c.s(168 + r)], outline=SLATE, width=round(c.s(4)))


def draw_pc_badge(c: Canvas) -> None:
    """Cert Generator Pal's badge: a PC with a brass check, bottom right."""
    def at(x: float, y: float) -> tuple[float, float]:
        return 150 + x, 150 + y

    c.rrect(*at(0, 0), *at(92, 92), 22, SLATE)
    c.rrect(*at(12, 16), *at(80, 62), 7, IVORY)
    c.rrect(*at(20, 24), *at(72, 54), 3, SLATE)
    c.rrect(*at(38, 62), *at(54, 73), 0, IVORY)
    c.rrect(*at(28, 72), *at(64, 79), 3.5, IVORY)
    c.draw.line(c.pts([at(33, 40), at(42, 48), at(59, 31)]), fill=BRASS, width=round(c.s(7)), joint="curve")
    for x, y in (at(33, 40), at(59, 31)):  # round caps
        r = c.s(3.5)
        c.draw.ellipse([c.s(x) - r, c.s(y) - r, c.s(x) + r, c.s(y) + r], fill=BRASS)


def render(px: int, pal: bool) -> Image.Image:
    big = px * SUPER
    c = Canvas(big)
    draw_background(c)
    c.img.alpha_composite(draw_certificate(big))
    draw_rosette(c)
    if pal:
        draw_pc_badge(c)
    return c.img.resize((px, px), Image.LANCZOS)


def write_ico(path: Path, pal: bool) -> None:
    frames = [render(size, pal) for size in ICO_SIZES]
    frames[-1].save(path, format="ICO", sizes=[(s, s) for s in ICO_SIZES], append_images=frames[:-1])
    print(f"wrote {path.relative_to(ROOT)}")


def main() -> None:
    write_ico(ROOT / "app" / "icon.ico", pal=False)
    write_ico(ROOT / "app" / "static" / "icon.ico", pal=False)
    render(512, pal=False).save(ROOT / "app" / "icon.png")
    print("wrote app/icon.png")
    write_ico(ROOT / "pal" / "src" / "CertGeneratorPal" / "pal.ico", pal=True)


if __name__ == "__main__":
    main()
