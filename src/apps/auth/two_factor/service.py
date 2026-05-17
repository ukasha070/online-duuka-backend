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
    """
    Generate a single human-friendly recovery code.

    Format:
        XXX-XXX-XXX

    The alphabet avoids confusing characters like:
        0 / O
        1 / I
    """
    segments = [
        "".join(secrets.choice(_RECOVERY_CODE_ALPHABET) for _ in range(3))
        for _ in range(3)
    ]
    return "-".join(segments)


def _generate_recovery_codes(count: int = 10) -> list[str]:
    """
    Generate a list of plaintext recovery codes.

    These plaintext values should only be returned to the user once.
    Only hashed versions are stored in the database.
    """
    return [_generate_recovery_code() for _ in range(count)]


def _hash_code(code: str) -> str:
    """
    Hash a recovery code before storing or comparing it.

    Recovery codes are already random and high entropy, so SHA-256 is enough here.
    We do not need bcrypt because these are not user-chosen passwords.
    """
    normalised = code.upper().replace(" ", "").strip()
    return hashlib.sha256(normalised.encode()).hexdigest()


def build_provisioning_uri(*, secret: str, issuer: str, account_name: str) -> str:
    """
    Build the otpauth:// URI used by authenticator apps.

    This URI is usually converted into a QR code on the frontend.
    """
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=account_name, issuer_name=issuer)


# ---------------------------------------------------------------------------
# Setup data container
# ---------------------------------------------------------------------------


@dataclass
class AuthenticatorSetupData:
    """
    Data returned when a user starts authenticator-app setup.

    `secret` is returned so the caller can build/display a QR code.
    """

    authenticator: UserAuthenticatorApp
    secret: str


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class AuthenticatorAppService:
    """
    Database-level operations for TOTP two-factor authentication.

    This service handles:
        - starting authenticator setup
        - confirming authenticator setup
        - verifying login TOTP codes
        - verifying recovery codes
        - regenerating recovery codes
        - disabling authenticator-based 2FA

    Important design rule:
        Private helpers should prepare queries or mutate objects,
        but public service methods should decide when to commit.

    This makes transaction boundaries easier to understand.
    """

    # ------------------------------------------------------------------
    # Query builders
    # ------------------------------------------------------------------
    #
    # These helpers do not execute queries.
    # They only build SQL statements.
    #
    # This keeps repeated query logic in one place and makes the public
    # methods easier to read.

    def _authenticator_for_user_query(self, *, user_id: str):
        """
        Query the authenticator-app record belonging to a user.
        """
        return select(UserAuthenticatorApp).where(
            UserAuthenticatorApp.user_id == user_id
        )

    def _unused_recovery_codes_count_query(self, *, user_id: str):
        """
        Query the number of unused recovery codes for a user.
        """
        return select(func.count()).where(
            UserTwoFactorRecoveryCode.user_id == user_id,
            UserTwoFactorRecoveryCode.is_used == False,  # noqa: E712
        )

    def _unused_recovery_code_query(self, *, user_id: str, code_hash: str):
        """
        Query a specific unused recovery code by its hash.
        """
        return select(UserTwoFactorRecoveryCode).where(
            UserTwoFactorRecoveryCode.user_id == user_id,
            UserTwoFactorRecoveryCode.code_hash == code_hash,
            UserTwoFactorRecoveryCode.is_used == False,  # noqa: E712
        )

    def _delete_recovery_codes_query(self, *, user_id: str):
        """
        Build a delete statement for all recovery codes belonging to a user.
        """
        return delete(UserTwoFactorRecoveryCode).where(
            col(UserTwoFactorRecoveryCode.user_id) == user_id
        )

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    async def get_for_user(
        self,
        *,
        db: AsyncSession,
        user_id: str,
    ) -> Optional[UserAuthenticatorApp]:
        """
        Return the authenticator-app record for a user, if it exists.
        """
        result = await db.exec(self._authenticator_for_user_query(user_id=user_id))
        return result.first()

    async def is_enabled(
        self,
        *,
        db: AsyncSession,
        user_id: str,
    ) -> bool:
        """
        Return True if the user has an enabled authenticator app.
        """
        authenticator = await self.get_for_user(db=db, user_id=user_id)
        return authenticator is not None and authenticator.is_enabled

    async def get_recovery_codes_remaining(
        self,
        *,
        db: AsyncSession,
        user_id: str,
    ) -> int:
        """
        Return the number of unused recovery codes remaining for a user.
        """
        result = await db.exec(self._unused_recovery_codes_count_query(user_id=user_id))
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

        Behavior:
            - If the user already has an enabled authenticator, raise ValueError.
            - If the user has a pending authenticator setup, reset it.
            - If the user has no authenticator setup, create one.
            - Always generate a fresh TOTP secret.

        The caller can use the returned secret to build a QR code.
        """
        existing = await self.get_for_user(db=db, user_id=user.id)

        if existing and existing.is_enabled:
            raise ValueError("Two-factor authentication is already enabled.")

        secret = pyotp.random_base32()
        now = utc_now()

        if existing:
            # User had started setup before but did not confirm it.
            # Reset the pending setup with a fresh secret.
            existing.secret = secret
            existing.is_enabled = False
            existing.confirmed_at = None
            existing.updated_at = now

            db.add(existing)
            await db.commit()
            await db.refresh(existing)

            return AuthenticatorSetupData(
                authenticator=existing,
                secret=secret,
            )

        # User has no authenticator record yet, so create a new pending setup.
        authenticator = UserAuthenticatorApp(
            user_id=user.id,
            secret=secret,
            issuer=settings.APP_NAME,
        )

        db.add(authenticator)
        await db.commit()
        await db.refresh(authenticator)

        return AuthenticatorSetupData(
            authenticator=authenticator,
            secret=secret,
        )

    async def confirm_setup(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        code: str,
    ) -> Optional[list[str]]:
        """
        Confirm authenticator setup using the first TOTP code.

        Returns:
            list[str] — plaintext recovery codes on success
            None      — invalid code, no setup, or setup already enabled

        Important:
            Plaintext recovery codes are only returned once.
            Only hashes are stored in the database.
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

        # This helper only mutates the session.
        # The commit happens here in the public method.
        await self._replace_recovery_codes(
            db=db,
            user_id=user_id,
            codes=recovery_codes,
        )

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
        Verify a login code.

        The submitted code is checked in this order:
            1. TOTP code from authenticator app
            2. Recovery code

        Returns:
            "totp"          — valid authenticator-app code
            "recovery_code" — valid unused recovery code, now marked as used
            None            — invalid code
        """
        authenticator = await self.get_for_user(db=db, user_id=user_id)

        if not authenticator or not authenticator.is_enabled:
            return None

        # First try the code as a normal TOTP code.
        if self._verify_totp(secret=authenticator.secret, code=code):
            self._mark_authenticator_used(authenticator=authenticator)

            db.add(authenticator)
            await db.commit()

            return "totp"

        # If it is not a TOTP code, try it as a recovery code.
        recovery_record = await self._find_unused_recovery_code(
            db=db,
            user_id=user_id,
            code=code,
        )

        if recovery_record:
            now = utc_now()

            recovery_record.is_used = True
            recovery_record.used_at = now
            recovery_record.updated_at = now

            self._mark_authenticator_used(authenticator=authenticator)

            db.add(recovery_record)
            db.add(authenticator)

            await db.commit()

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
        Replace all recovery codes after verifying the current TOTP code.

        Returns:
            list[str] — new plaintext recovery codes
            None      — invalid TOTP code or 2FA not enabled
        """
        authenticator = await self.get_for_user(db=db, user_id=user_id)

        if not authenticator or not authenticator.is_enabled:
            return None

        if not self._verify_totp(secret=authenticator.secret, code=code):
            return None

        recovery_codes = _generate_recovery_codes(10)

        await self._replace_recovery_codes(
            db=db,
            user_id=user_id,
            codes=recovery_codes,
        )

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
        Disable authenticator-app two-factor authentication.

        Behavior:
            - Verify the current TOTP code.
            - Mark authenticator as disabled.
            - Clear authenticator usage state.
            - Delete all recovery codes.

        Returns:
            True  — disabled successfully
            False — invalid code or 2FA not enabled
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
    # Private state mutation helpers
    # ------------------------------------------------------------------
    #
    # These helpers modify Python/SQLModel objects or stage DB operations.
    # They intentionally do not commit.
    #
    # The public service methods above decide when to commit.

    def _mark_authenticator_used(
        self,
        *,
        authenticator: UserAuthenticatorApp,
    ) -> None:
        """
        Mark the authenticator as recently used.

        This does not call db.add() or db.commit().
        The caller controls the transaction.
        """
        now = utc_now()

        authenticator.last_used_at = now
        authenticator.updated_at = now

    async def _replace_recovery_codes(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        codes: list[str],
    ) -> None:
        """
        Delete all existing recovery codes and stage fresh ones.

        This helper does not commit.
        """
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
        """
        Delete all recovery codes for a user.

        This helper does not commit.
        """
        await db.exec(self._delete_recovery_codes_query(user_id=user_id))

    # ------------------------------------------------------------------
    # Private lookup helpers
    # ------------------------------------------------------------------

    async def _find_unused_recovery_code(
        self,
        *,
        db: AsyncSession,
        user_id: str,
        code: str,
    ) -> Optional[UserTwoFactorRecoveryCode]:
        """
        Find a matching unused recovery code.

        The submitted plaintext code is hashed first, then compared with the
        stored hash.
        """
        code_hash = _hash_code(code)

        result = await db.exec(
            self._unused_recovery_code_query(
                user_id=user_id,
                code_hash=code_hash,
            )
        )

        return result.first()

    # ------------------------------------------------------------------
    # Private verification helpers
    # ------------------------------------------------------------------

    def _verify_totp(
        self,
        *,
        secret: str,
        code: str,
    ) -> bool:
        """
        Verify a TOTP code.

        valid_window=1 allows a small clock drift:
            - previous time window
            - current time window
            - next time window
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)


authenticator_app_service = AuthenticatorAppService()
