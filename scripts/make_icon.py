"""Generate app/icon.ico — a padlock mark matching the app's dark theme."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

BG = (15, 17, 23, 255)         # --bg
SURFACE = (26, 29, 39, 255)    # --surface
BORDER = (42, 46, 62, 255)     # --border
ACCENT = (99, 102, 241, 255)   # --accent
ACCENT_HI = (129, 140, 248, 255)  # --accent-hover

OUT_DIR = Path(__file__).parent.parent / "app"
CANVAS = 512


def rounded_square(size: int, radius: int, fill, outline=None, outline_width: int = 0) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=fill, outline=outline, width=outline_width)
    return img


def draw_padlock(draw: ImageDraw.ImageDraw, cx: int, cy: int, scale: float) -> None:
    body_w = int(200 * scale)
    body_h = int(160 * scale)
    body_top = cy - int(20 * scale)
    body_left = cx - body_w // 2
    body_right = cx + body_w // 2
    body_bottom = body_top + body_h
    radius = int(28 * scale)

    shackle_outer_r = int(90 * scale)
    shackle_width = int(34 * scale)
    shackle_cy = body_top

    # Shackle (arc) — draw as thick ring, then mask bottom half away
    shackle_bbox = [cx - shackle_outer_r, shackle_cy - shackle_outer_r, cx + shackle_outer_r, shackle_cy + shackle_outer_r]
    draw.arc(shackle_bbox, start=180, end=360, fill=ACCENT, width=shackle_width)

    # Body
    draw.rounded_rectangle([body_left, body_top, body_right, body_bottom], radius=radius, fill=ACCENT)

    # Keyhole cutout
    hole_r = int(18 * scale)
    hole_cx, hole_cy = cx, body_top + int(55 * scale)
    draw.ellipse([hole_cx - hole_r, hole_cy - hole_r, hole_cx + hole_r, hole_cy + hole_r], fill=BG)
    tri_w = int(14 * scale)
    tri_h = int(38 * scale)
    draw.polygon(
        [
            (hole_cx - tri_w, hole_cy + int(6 * scale)),
            (hole_cx + tri_w, hole_cy + int(6 * scale)),
            (hole_cx, hole_cy + int(6 * scale) + tri_h),
        ],
        fill=BG,
    )


def main() -> None:
    img = rounded_square(CANVAS, radius=96, fill=SURFACE, outline=BORDER, outline_width=6)
    draw = ImageDraw.Draw(img)
    draw_padlock(draw, cx=CANVAS // 2, cy=CANVAS // 2 + 10, scale=CANVAS / 512)

    ico_path = OUT_DIR / "icon.ico"
    sizes = [16, 24, 32, 48, 64, 128, 256]
    img.save(ico_path, format="ICO", sizes=[(s, s) for s in sizes])
    print(f"Wrote {ico_path}")

    png_path = OUT_DIR / "icon.png"
    img.save(png_path, format="PNG")
    print(f"Wrote {png_path}")


if __name__ == "__main__":
    main()
