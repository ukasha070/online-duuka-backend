"""
watermark.py
Watermark compositing utility.

Usage:
    from watermark import add_watermark

    img = add_watermark(img, "/path/to/logo.png")
    img = add_watermark(img, "/path/to/logo.png", position="bottom-right", opacity=180)
"""

from __future__ import annotations
import os

from PIL import Image

from .image_types import WatermarkPosition
from core.config import settings

# Logo is scaled to this fraction of the base image's shorter side.
_LOGO_SCALE: float = 0.20
_PAD: int = 10


def add_watermark(
    img: Image.Image,
    logo_path: str | None,
    position: WatermarkPosition = "center",
    opacity: int = 128,
) -> Image.Image:
    """
    Composite a logo onto img at position with the given opacity.

    Args:
        img:       Source image in RGB mode (guaranteed by the processor).
        logo_path: Path to the logo file (PNG with transparency recommended).
        position:  One of the WatermarkPosition literals.
        opacity:   0 = invisible, 255 = fully opaque.

    Returns:
        A new RGB image – the original is never mutated.
    """

    logo_path = logo_path or str(os.path.join(settings.BASE_DIR, "static/logo.png"))

    logo = _load_logo(logo_path, img.size, opacity)
    base = img.copy().convert("RGBA")
    bw, bh = base.size
    lw, lh = logo.size
    x, y = _calc_offset(position, bw, bh, lw, lh)
    base.paste(logo, (x, y), mask=logo)
    return base.convert("RGB")


# ── private helpers ───────────────────────────────────────────────────────────


def _load_logo(path: str, base_size: tuple[int, int], opacity: int) -> Image.Image:
    logo = Image.open(path).convert("RGBA")
    logo = _scale_logo(logo, base_size)
    r, g, b, a = logo.split()
    a = a.point(lambda v: int(v * opacity / 255))
    logo.putalpha(a)
    return logo


def _scale_logo(logo: Image.Image, base_size: tuple[int, int]) -> Image.Image:
    bw, bh = base_size
    max_side = int(min(bw, bh) * _LOGO_SCALE)
    lw, lh = logo.size
    if lw >= lh:
        new_w, new_h = max_side, int(lh * max_side / lw)
    else:
        new_h, new_w = max_side, int(lw * max_side / lh)
    return logo.resize((new_w, new_h), Image.LANCZOS)  # type: ignore


def _calc_offset(
    position: WatermarkPosition, bw: int, bh: int, lw: int, lh: int
) -> tuple[int, int]:
    offsets: dict[WatermarkPosition, tuple[int, int]] = {
        "center": ((bw - lw) // 2, (bh - lh) // 2),
        "top-left": (_PAD, _PAD),
        "top-right": (bw - lw - _PAD, _PAD),
        "bottom-left": (_PAD, bh - lh - _PAD),
        "bottom-right": (bw - lw - _PAD, bh - lh - _PAD),
    }
    return offsets[position]
