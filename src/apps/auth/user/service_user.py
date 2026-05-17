from typing import Optional, Sequence, Any

from fastapi import HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from apps.auth.user.models import User, AuthType, UserProfile
from apps.auth.security import hash_password, verify_password


async def get_user_by_id(db: AsyncSession, user_id: str) -> Optional[User]:
    statement = select(User).where(User.id == user_id)
    result = await db.exec(statement)
    return result.first()


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    statement = select(User).where(User.email == email.lower().strip())
    result = await db.exec(statement)
    return result.first()


async def get_user_by_google_sub(
    db: AsyncSession,
    google_sub: str,
) -> Optional[User]:
    statement = select(User).where(User.google_sub == google_sub)
    result = await db.exec(statement)
    return result.first()


async def get_users(
    db: AsyncSession,
    offset: int = 0,
    limit: int = 100,
) -> Sequence[User]:
    statement = select(User).offset(offset).limit(limit)
    result = await db.exec(statement)
    return result.all()


async def create_email_user(
    db: AsyncSession,
    email: str,
    password: str,
    full_name: str,
) -> User:
    normalized_email = email.lower().strip()
    existing_user = await get_user_by_email(db, normalized_email)

    if existing_user:
        raise ValueError("User with this email already exists")

    user = User(
        email=normalized_email,
        password=hash_password(password),
        full_name=full_name,
        auth_type=AuthType.EMAIL,
        is_verified=False,
        is_active=True,
    )

    profile = UserProfile(user_id=user.id)
    user.profile = profile

    db.add(user)
    db.add(profile)
    await db.commit()
    await db.refresh(user)

    return user


async def get_or_create_google_user(
    db: AsyncSession, *, email: str, full_name: str, google_sub: str
) -> tuple[User, bool]:  # (user, created)
    normalized_email = email.lower().strip()

    existing = await get_user_by_email(db, normalized_email)

    if existing:
        if existing.google_sub is None:
            existing.google_sub = google_sub
            db.add(existing)
            await db.commit()
            await db.refresh(existing)
        return existing, False

    user = User(
        email=normalized_email,
        full_name=full_name,
        google_sub=google_sub,
        password=None,
        auth_type=AuthType.GOOGLE,
        is_verified=True,
        is_active=True,
    )

    profile = UserProfile(user_id=user.id)
    user.profile = profile

    db.add(user)
    db.add(profile)
    await db.commit()
    await db.refresh(user)

    return user, True


async def update_user(
    db: AsyncSession,
    user_id: str,
    update_data: dict[str, Any],
) -> Optional[User]:
    user = await get_user_by_id(db, user_id)

    if not user:
        return None

    allowed_fields = {
        "email",
        "full_name",
        "is_active",
        "is_superuser",
        "is_verified",
        "auth_type",
    }

    for key, value in update_data.items():
        if key in allowed_fields and value is not None:
            setattr(user, key, value)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def change_password(
    db: AsyncSession,
    user_id: str,
    new_password: str,
) -> User:
    user = await get_user_by_id(db, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    user.password = hash_password(new_password)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def check_password(
    db: AsyncSession,
    user_id: str,
    password: str,
) -> bool:
    user = await get_user_by_id(db, user_id)

    if not user:
        return False

    return user.password == hash_password(password)


async def verify_user(
    db: AsyncSession,
    user_id: str,
) -> Optional[User]:
    user = await get_user_by_id(db, user_id)

    if not user:
        return None

    user.is_verified = True

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def deactivate_user(
    db: AsyncSession,
    user_id: str,
) -> Optional[User]:
    user = await get_user_by_id(db, user_id)

    if not user:
        return None

    user.is_active = False

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def delete_user(
    db: AsyncSession,
    user_id: str,
) -> bool:
    user = await get_user_by_id(db, user_id)

    if not user:
        return False

    await db.delete(user)
    await db.commit()

    return True


async def authenticate_email_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> Optional[User]:
    user = await get_user_by_email(db, email)

    if not user:
        return None

    if user.auth_type != AuthType.EMAIL:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Please Continue with {user.auth_type}.",
        )

    if not user.password:
        return None

    if not verify_password(password, user.password):
        return None

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Contact support your account is inactive.",
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Please Verify account to login.",
        )

    return user
