"""
image_processor.py
Core image processing pipeline – no FastAPI / Django imports here.

All public functions accept plain `bytes` and return `ProcessedImage`.
This keeps the logic testable and reusable outside of a web context.

Usage:
    from image_processor import process_upload, process_url, ProcessConfig

    config = ProcessConfig(preset="cover", site_attribution="My Site")
    result = process_upload(raw_bytes, "image/jpeg", config)

    # result.data      → bytes  (WebP)
    # result.filename  → str
    # result.size      → int
    # result.to_stream() → BytesIO  (for StreamingResponse etc.)
"""

from __future__ import annotations

import io
import urllib.request
from typing import Annotated

from PIL import ExifTags, Image, UnidentifiedImageError
from pydantic import BaseModel, Field

# Optional HEIC/HEIF support – install with: pip install pillow-heif
try:
    import pillow_heif  # type: ignore[import]

    pillow_heif.register_heif_opener()
    _HEIF_SUPPORTED: bool = True
except ImportError:
    _HEIF_SUPPORTED = False

from .image_types import (
    ALLOWED_MIME_TYPES,
    ImagePreset,
    ProcessedImage,
    WatermarkPosition,
)
from .watermark import add_watermark

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_UPLOAD_BYTES: int = 15 * 1024 * 1024  # 15 MB

# Per-preset dimensions and WebP quality
_PRESET_SETTINGS: dict[ImagePreset, dict] = {
    "avatar": {"max_px": 150, "quality": 85, "square": True},
    "cover": {"max_px": 250, "quality": 70, "square": False},
    "gallery": {"max_px": 720, "quality": 80, "square": False},
}

# ── Config model ──────────────────────────────────────────────────────────────


class ProcessConfig(BaseModel):
    """
    All processing options for a single pipeline run.
    Validated by Pydantic so callers get clear errors on bad input.
    """

    preset: ImagePreset = "gallery"

    # Custom dimensions override the preset's max_px (aspect-ratio preserved).
    width: int | None = Field(None, gt=0, le=8000)
    height: int | None = Field(None, gt=0, le=8000)

    # Watermark
    logo_path: str | None = None
    wm_position: WatermarkPosition = "center"
    wm_opacity: Annotated[int, Field(ge=0, le=255)] = 128

    # Metadata embedded in the output WebP as XMP.
    # E.g. "Powered by My Website" – invisible but survives most viewers.
    site_attribution: str = ""

    model_config = {"frozen": True}


# ── Custom exception ──────────────────────────────────────────────────────────


class ImageProcessingError(Exception):
    """Raised for any expected failure in the processing pipeline."""


# ── Public API ────────────────────────────────────────────────────────────────


def process_upload(
    data: bytes,
    content_type: str,
    config: ProcessConfig | None = None,
) -> ProcessedImage:
    """
    Full pipeline for raw image bytes (e.g. from UploadFile.read()).

    Steps: validate → open → orient + strip EXIF → RGB → resize
           → [watermark] → encode as WebP → return ProcessedImage.
    """
    cfg = config or ProcessConfig()
    _validate_bytes(data, content_type)
    try:
        img = _open_image(data)
        img = _apply_orientation_and_strip_exif(img)
        img = _to_rgb(img)
        img = _resize(img, cfg)
        if cfg.logo_path:
            img = add_watermark(
                img,
                cfg.logo_path,
                position=cfg.wm_position,
                opacity=cfg.wm_opacity,
            )
        return _encode_webp(img, cfg)
    except ImageProcessingError:
        raise
    except Exception as exc:
        raise ImageProcessingError(f"Failed to process image: {exc}") from exc


def process_url(
    url: str,
    config: ProcessConfig | None = None,
) -> ProcessedImage:
    """
    Download a remote image and run it through the same processing pipeline.
    Useful for scraping / importing product images from external sources.
    """
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data: bytes = resp.read()
            content_type: str = resp.headers.get("Content-Type", "image/jpeg")
    except Exception as exc:
        raise ImageProcessingError(f"Could not fetch URL: {exc}") from exc

    if len(data) > MAX_UPLOAD_BYTES:
        raise ImageProcessingError("Remote image exceeds 15 MB limit.")

    return process_upload(data, content_type, config)


# ── Private helpers ───────────────────────────────────────────────────────────


def _validate_bytes(data: bytes, content_type: str) -> None:
    if len(data) > MAX_UPLOAD_BYTES:
        mb = len(data) // (1024 * 1024)
        raise ImageProcessingError(f"Image too large ({mb} MB). Max is 15 MB.")

    # Normalise "image/jpeg; charset=..." → "image/jpeg"
    mime = content_type.split(";")[0].strip().lower()
    if mime and mime not in ALLOWED_MIME_TYPES:
        raise ImageProcessingError(
            f"Unsupported type '{mime}'. "
            "Accepted: JPEG, PNG, WebP, HEIC/HEIF (iPhone), TIFF, DNG (Android)."
        )
    if not _HEIF_SUPPORTED and mime in {"image/heic", "image/heif"}:
        raise ImageProcessingError(
            "HEIC/HEIF images require the pillow-heif package. "
            "Install it with: pip install pillow-heif"
        )


def _open_image(data: bytes) -> Image.Image:
    try:
        img = Image.open(io.BytesIO(data))
        img.load()  # Force full decode so errors surface here, not later
        return img
    except UnidentifiedImageError:
        raise ImageProcessingError("Cannot identify image file.")
    except Exception as exc:
        raise ImageProcessingError(f"Cannot open image: {exc}") from exc


def _apply_orientation_and_strip_exif(img: Image.Image) -> Image.Image:
    """Rotate to correct orientation (from EXIF), then drop all metadata."""
    try:
        exif = img._getexif()  # type: ignore[attr-defined]
        if exif:
            for tag_id, value in exif.items():
                if ExifTags.TAGS.get(tag_id) == "Orientation":
                    deg = {3: 180, 6: 270, 8: 90}.get(value)
                    if deg:
                        img = img.rotate(deg, expand=True)
                    break
    except Exception:
        pass  # Not every format has _getexif; silently continue

    # Recreate without metadata
    clean = Image.new(img.mode, img.size)
    clean.putdata(list(img.getdata()))
    return clean


def _to_rgb(img: Image.Image) -> Image.Image:
    """Flatten alpha onto white; convert any palette mode to RGB."""
    if img.mode in ("RGBA", "LA"):
        bg = Image.new("RGB", img.size, (255, 255, 255))
        bg.paste(img, mask=img.split()[-1])  # last channel = alpha
        return bg
    return img if img.mode == "RGB" else img.convert("RGB")


def _resize(img: Image.Image, cfg: ProcessConfig) -> Image.Image:
    settings = _PRESET_SETTINGS[cfg.preset]

    # Explicit custom dimensions take priority over the preset
    if cfg.width or cfg.height:
        return _fit_in_box(img, cfg.width, cfg.height)

    if settings["square"]:
        return _crop_square(img, settings["max_px"])

    max_w: int = settings["max_px"]
    w, h = img.size
    if w <= max_w:
        return img
    return img.resize((max_w, int(h * max_w / w)), Image.LANCZOS)  # type: ignore


def _fit_in_box(
    img: Image.Image,
    width: int | None,
    height: int | None,
) -> Image.Image:
    """Resize to fit within a bounding box, preserving aspect ratio. Never upscales."""
    w, h = img.size
    if width and height:
        scale = min(width / w, height / h)
        new_w, new_h = int(w * scale), int(h * scale)
    elif width:
        new_w, new_h = width, int(h * width / w)
    else:
        assert height
        new_w, new_h = int(w * height / h), height

    if new_w >= w and new_h >= h:  # never upscale
        return img
    return img.resize((new_w, new_h), Image.LANCZOS)  # type: ignore


def _crop_square(img: Image.Image, size: int) -> Image.Image:
    """Center-crop to a square, then resize to size × size."""
    w, h = img.size
    side = min(w, h)
    left, top = (w - side) // 2, (h - side) // 2
    img = img.crop((left, top, left + side, top + side))
    return img.resize((size, size), Image.LANCZOS)  # type: ignore


def _build_xmp(attribution: str) -> bytes:
    return (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<dc:description>{attribution}</dc:description>"
        "</rdf:Description></rdf:RDF></x:xmpmeta>"
    ).encode()


def _encode_webp(img: Image.Image, cfg: ProcessConfig) -> ProcessedImage:
    settings = _PRESET_SETTINGS[cfg.preset]
    save_kwargs: dict = {
        "format": "WEBP",
        "quality": settings["quality"],
        "method": 6,  # best compression (slower encode, same decode)
        "optimize": True,
    }
    if cfg.site_attribution:
        save_kwargs["xmp"] = _build_xmp(cfg.site_attribution)

    buf = io.BytesIO()
    img.save(buf, **save_kwargs)

    suffix: dict[ImagePreset, str] = {
        "avatar": "avatar",
        "cover": "cover",
        "gallery": "img",
    }
    return ProcessedImage(
        data=buf.getvalue(),
        filename=f"product_{suffix[cfg.preset]}.webp",
        content_type="image/webp",
    )
