from io import BytesIO
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, UploadFile, File, HTTPException, status
from PIL import Image, UnidentifiedImageError

router = APIRouter()

MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 2MB

ALLOWED_CONTENT_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
}

ALLOWED_IMAGE_FORMATS = {
    "JPEG": "jpg",
    "PNG": "png",
    "WEBP": "webp",
}


async def validate_image_file(image: UploadFile) -> tuple[bytes, str]:
    """
    Validate uploaded image and return:
    - image bytes
    - safe file extension
    """

    if not image.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Image filename is required.",
        )

    if image.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only JPEG, PNG, and WEBP images are allowed.",
        )

    image_bytes = await image.read()

    if len(image_bytes) > MAX_IMAGE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Image is too large. Maximum size is 2MB.",
        )

    try:
        img = Image.open(BytesIO(image_bytes))
        img.verify()
    except UnidentifiedImageError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid image file.",
        )

    # Re-open because img.verify() invalidates the image object
    img = Image.open(BytesIO(image_bytes))

    if img.format not in ALLOWED_IMAGE_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported image format.",
        )

    width, height = img.size

    if width > 4000 or height > 4000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Image dimensions are too large.",
        )

    extension = ALLOWED_IMAGE_FORMATS[img.format]

    return image_bytes, extension
