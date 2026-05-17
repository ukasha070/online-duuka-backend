import secrets
import hashlib
import pyotp

from dataclasses import dataclass
from typing import Literal, Optional

from sqlmodel import col, delete, func, select
from sqlmodel.ext.asyncio.session import AsyncSession

from core.utils import utc_now
from core.config import settings
from apps.auth.user.models import User

from .models import UserAuthenticatorApp, UserTwoFactorRecoveryCode

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I


def _generate_recovery_code() -> str:
    """Return a single XXX-XXX-XXX recovery code."""
    segments = [
        "".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(3))
        for _ in range(3)
    ]
    return "-".join(segments)


def _generate_recovery_codes(count: int = 10) -> list[str]:
    return [_generate_recovery_code() for _ in range(count)]


def _hash_code(code: str) -> str:
    """SHA-256 hash of a normalised recovery code.
    Recovery codes are already high-entropy random strings so a fast
    hash is appropriate here — no need for bcrypt.
    """
    normalised = code.upper().replace(" ", "").strip()
    return hashlib.sha256(normalised.encode()).hexdigest()


def build_provisioning_uri(*, secret: str, issuer: str, account_name: str) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)


# ---------------------------------------------------------------------------
# Setup data container
# ---------------------------------------------------------------------------


@dataclass
class AuthenticatorSetupData:
    authenticator: UserAuthenticatorApp
    secret: str


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class AuthenticatorAppService:
    """All database-level operations for TOTP two-factor authentication."""

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_for_user(
        self,
        *,
        db: AsyncSession,
        user_id: str,
    ) -> Optional[UserAuthenticatorApp]:
        result = await db.exec(
            select(UserAuthenticatorApp).where(UserAuthenticatorApp.user_id == user_id)
        )
        return result.first()

    async def is_enabled(self, *, db: AsyncSession, user_id: str) -> bool:
        authenticator = await self.get_for_user(db=db, user_id=user_id)
        return authenticator is not None and authenticator.is_enabled

    async def get_recovery_codes_remaining(
        self,
        *,
        db: AsyncSession,
        user_id: str,
    ) -> int:
        result = await db.exec(
            select(func.count()).where(
                UserTwoFactorRecoveryCode.user_id == user_id,
                UserTwoFactorRecoveryCode.is_used == False,  # noqa: E712
            )
        )
        return result.one()

    # ------------------------------------------------------------------
    # Setup flow: start → confirm
    # ------------------------------------------------------------------

    async def start_setup(
        self,
        *,
        db: AsyncSession,
        user: User,
    ) -> AuthenticatorSetupData:
        """
        Begin TOTP setup for a user.

        - If the user already has a confirmed (enabled) authenticator, raises
          ValueError — the caller should surface this as a 400.
        - If a pending (unconfirmed) authenticator exists it is reset so the
          user can re-scan a fresh QR code.
        - Always generates a brand-new TOTP secret.
        """
        existing = await self.get_for_user(db=db, user_id=user.id)

        if existing and existing.is_enabled:
            raise ValueError("Two-factor authentication is already enabled.")

        secret = pyotp.random_base32()
        now = utc_now()

        if existing:
            # Reset any in-progress setup with a fresh secret
            existing.secret = secret
            existing.is_enabled = False
            existing.confirmed_at = None
            existing.updated_at = now
            db.add(existing)
            await db.commit()
            await db.refresh(existing)
            return AuthenticatorSetupData(authenticator=existing, secret=secret)

        authenticator = UserAuthenticatorApp(
            user_id=user.id,
            secret=secret,
            issuer=settings.APP_NAME,
        )
        db.add(authenticator)
        await db.commit()
        await db.refresh(authenticator)

        return AuthenticatorSetupData(authenticator=authenticator, secret=secret)

    async def confirm_setup(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        code: str,
    ) -> Optional[list[str]]:
        """
        Verify the first TOTP code the user submits after scanning the QR.

        Returns the list of plaintext recovery codes on success, or None if
        the code is wrong / no pending setup exists.
        """
        authenticator = await self.get_for_user(db=db, user_id=user_id)

        if not authenticator or authenticator.is_enabled:
            return None

        if not self._verify_totp(secret=authenticator.secret, code=code):
            return None

        now = utc_now()
        authenticator.is_enabled = True
        authenticator.confirmed_at = now
        authenticator.updated_at = now
        db.add(authenticator)

        recovery_codes = _generate_recovery_codes(10)
        await self._replace_recovery_codes(db=db, user_id=user_id, codes=recovery_codes)

        await db.commit()
        return recovery_codes

    # ------------------------------------------------------------------
    # Login verification
    # ------------------------------------------------------------------

    async def verify_login_code_or_recovery_code(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        code: str,
    ) -> Optional[Literal["totp", "recovery_code"]]:
        """
        Try the submitted code as a TOTP code first, then as a recovery code.

        Returns:
            "totp"          — valid TOTP code
            "recovery_code" — valid (unused) recovery code, now marked used
            None            — invalid code
        """
        authenticator = await self.get_for_user(db=db, user_id=user_id)

        if not authenticator or not authenticator.is_enabled:
            return None

        # --- TOTP check ---
        if self._verify_totp(secret=authenticator.secret, code=code):
            await self._touch_authenticator(db=db, authenticator=authenticator)
            return "totp"

        # --- Recovery code check ---
        recovery_record = await self._find_unused_recovery_code(
            db=db, user_id=user_id, code=code
        )

        if recovery_record:
            now = utc_now()
            recovery_record.is_used = True
            recovery_record.used_at = now
            recovery_record.updated_at = now
            db.add(recovery_record)

            await self._touch_authenticator(db=db, authenticator=authenticator)
            return "recovery_code"

        return None

    # ------------------------------------------------------------------
    # Recovery code regeneration
    # ------------------------------------------------------------------

    async def regenerate_recovery_codes(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        code: str,
    ) -> Optional[list[str]]:
        """
        Verify the current TOTP code and replace all recovery codes.

        Returns the new plaintext recovery codes, or None if the code is wrong.
        """
        authenticator = await self.get_for_user(db=db, user_id=user_id)

        if not authenticator or not authenticator.is_enabled:
            return None

        if not self._verify_totp(secret=authenticator.secret, code=code):
            return None

        recovery_codes = _generate_recovery_codes(10)
        await self._replace_recovery_codes(db=db, user_id=user_id, codes=recovery_codes)
        await db.commit()

        return recovery_codes

    # ------------------------------------------------------------------
    # Disable
    # ------------------------------------------------------------------

    async def disable(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        code: str,
    ) -> bool:
        """
        Verify the current TOTP code and fully disable two-factor auth.

        Wipes the authenticator state and all recovery codes.
        Returns True on success, False if the code is wrong.
        """
        authenticator = await self.get_for_user(db=db, user_id=user_id)

        if not authenticator or not authenticator.is_enabled:
            return False

        if not self._verify_totp(secret=authenticator.secret, code=code):
            return False

        now = utc_now()
        authenticator.is_enabled = False
        authenticator.confirmed_at = None
        authenticator.last_used_at = None
        authenticator.last_used_counter = None
        authenticator.updated_at = now
        db.add(authenticator)

        await self._delete_all_recovery_codes(db=db, user_id=user_id)
        await db.commit()

        return True

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _verify_totp(self, *, secret: str, code: str) -> bool:
        """
        Verify a TOTP code with a ±1 window to tolerate slight clock drift.
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    async def _touch_authenticator(
        self,
        *,
        db: AsyncSession,
        authenticator: UserAuthenticatorApp,
    ) -> None:
        now = utc_now()
        authenticator.last_used_at = now
        authenticator.updated_at = now
        db.add(authenticator)
        await db.commit()

    async def _find_unused_recovery_code(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        code: str,
    ) -> Optional[UserTwoFactorRecoveryCode]:
        code_hash = _hash_code(code)
        result = await db.exec(
            select(UserTwoFactorRecoveryCode).where(
                UserTwoFactorRecoveryCode.user_id == user_id,
                UserTwoFactorRecoveryCode.code_hash == code_hash,
                UserTwoFactorRecoveryCode.is_used == False,  # noqa: E712
            )
        )
        return result.first()

    async def _replace_recovery_codes(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        codes: list[str],
    ) -> None:
        """Delete all existing recovery codes for the user and insert fresh ones."""
        await self._delete_all_recovery_codes(db=db, user_id=user_id)

        for code in codes:
            db.add(
                UserTwoFactorRecoveryCode(
                    user_id=user_id,
                    code_hash=_hash_code(code),
                )
            )

    async def _delete_all_recovery_codes(
        self,
        *,
        db: AsyncSession,
        user_id: str,
    ) -> None:
        await db.exec(
            delete(UserTwoFactorRecoveryCode).where(
                col(UserTwoFactorRecoveryCode.user_id) == user_id
            )
        )


authenticator_app_service = AuthenticatorAppService()
