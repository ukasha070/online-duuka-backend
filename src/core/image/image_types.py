"""
image_types.py
Shared type aliases, constants, and result dataclass for the image pipeline.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Literal, TypeAlias

# ── Type aliases ──────────────────────────────────────────────────────────────

WatermarkPosition: TypeAlias = Literal[
    "center", "top-left", "top-right", "bottom-left", "bottom-right"
]
ImagePreset: TypeAlias = Literal["gallery", "cover", "avatar"]

# ── Accepted upload MIME types ────────────────────────────────────────────────
# Covers both standard web formats and common camera formats on iOS / Android.
# HEIC/HEIF support also requires `pip install pillow-heif` at runtime.

ALLOWED_MIME_TYPES: frozenset[str] = frozenset(
    {
        # ── Web ───────────────────────────────────────────────────────────────
        "image/jpeg",  # JPEG   – universal
        "image/png",  # PNG    – universal
        "image/webp",  # WebP   – Android / web
        # ── iPhone (iOS 11+) ──────────────────────────────────────────────────
        "image/heic",  # HEIC   – default iPhone still photo
        "image/heif",  # HEIF   – HEIC container variant
        # ── Android / camera apps ─────────────────────────────────────────────
        "image/tiff",  # TIFF   – pro camera apps, Samsung RAW
        "image/x-adobe-dng",  # DNG    – Adobe RAW (Android pro/manual modes)
        "image/dng",  # DNG    – alternate MIME some devices send
    }
)

# Pillow internal format name → file extension (used in error messages / logs)
PILLOW_FORMAT_TO_EXT: dict[str, str] = {
    "JPEG": "jpg",
    "PNG": "png",
    "WEBP": "webp",
    "HEIF": "heic",
    "TIFF": "tiff",
    "MPO": "jpg",  # Multi-Picture Object – some Sony / Samsung cameras
}

# ── Result dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ProcessedImage:
    """
    Immutable result returned by every processing function.
    Framework-agnostic: works with FastAPI, Flask, or plain scripts.
    """

    data: bytes
    filename: str
    content_type: str = "image/webp"

    @property
    def size(self) -> int:
        return len(self.data)

    def to_stream(self) -> io.BytesIO:
        """Return a seeked BytesIO – pass directly to StreamingResponse etc."""
        buf = io.BytesIO(self.data)
        buf.seek(0)
        return buf
