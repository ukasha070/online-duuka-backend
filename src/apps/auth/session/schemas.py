from pydantic import BaseModel

from .models import UserSession


class LoginSession(BaseModel):
    access_token: str
    refresh_token: str
    session: UserSession


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
