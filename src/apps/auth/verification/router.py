from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from core.db import get_db

from apps.auth.user.models import AuthType
from apps.auth.user import service_user as user_service
from apps.auth import tasks as _tasks

from . import services as verification_service
from . import tasks
from .schemas import RequestVerificationEmailPayload

router = APIRouter(prefix="")

# TODO  add ratelimiting here


GENERIC_VERIFICATION_RESPONSE = {
    "detail": "If an account with that email exists, a verification email has been sent."
}


# -------------------------------------------------------------------
# Email verification endpoints
# -------------------------------------------------------------------


@router.post("/request/", status_code=status.HTTP_202_ACCEPTED)
async def request_verification_email(
    payload: RequestVerificationEmailPayload,
    db: AsyncSession = Depends(get_db),
):
    """
    Request a new email verification link.

    Security note:
    - Always return the same response whether the user exists or not.
    - This prevents attackers from checking which emails are registered.
    """

    user = await user_service.get_user_by_email(
        db=db,
        email=payload.email,
    )

    # Do not reveal whether the account exists.
    if not user:
        return GENERIC_VERIFICATION_RESPONSE

    # Only email/password accounts need email verification.
    # OAuth users should not receive verification emails from this flow.
    #
    # We still return the generic response to avoid leaking account type.
    if user.auth_type != AuthType.EMAIL:
        return GENERIC_VERIFICATION_RESPONSE

    if not user.is_active:
        return {"detail": "Your account is inactive contact support for more"}

    # If already verified, no need to create or send another token.
    # Return the same generic response for consistency.
    if user.is_verified:
        return GENERIC_VERIFICATION_RESPONSE

    # Create a new token or update the existing one for this user.
    verification_token = await verification_service.create_or_update_verification_token(
        db=db,
        user_id=user.id,
    )

    # Send email asynchronously using
    tasks.send_verification_email.delay(  # type: ignore[attr-defined]
        to_email=user.email,
        full_name=user.full_name,
        token=verification_token.token,
    )

    return GENERIC_VERIFICATION_RESPONSE


@router.get("/confirm/{token}", status_code=status.HTTP_200_OK)
async def confirm_verification_token(
    token: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Confirm a user's email verification token.

    If the token is valid:
    - Mark the user as verified.
    - Mark/delete/expire the verification token depending on service logic.
    """

    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token is required.",
        )

    verified_user = await verification_service.confirm_verification_token(
        db=db,
        token=token,
    )

    if not verified_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        )

    # send welcome email after account verification
    _tasks.send_welcome_email.delay(  # type: ignore
        to_email=verified_user.email, full_name=verified_user.full_name
    )

    return {
        "detail": "Email verified successfully.",
    }
