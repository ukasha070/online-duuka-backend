# storage/file_storage.py
from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from core.image.image_types import ProcessedImage
from core.config import settings

# Where avatar files land on disk, relative to your project root
AVATAR_DIR = os.path.join(settings.BASE_DIR, "media/avatars")


def save(result: ProcessedImage, user_id: str) -> str:
    """
    Persist a ProcessedImage to disk and return the relative path string.
    Example return value: "media/profile_images/avatars/<uuid>.webp"
    """
    dest_dir = Path(os.path.join(AVATAR_DIR, user_id))
    dest_dir.mkdir(parents=True, exist_ok=True)

    filename = f"{user_id}.webp"
    dest = dest_dir / filename
    dest.write_bytes(result.data)

    return str(dest)


def delete(image_path: str | None) -> None:
    """Remove an old avatar file when the user uploads a new one."""
    if not image_path:
        return
    path = Path(image_path)
    if path.exists():
        path.unlink(missing_ok=True)
