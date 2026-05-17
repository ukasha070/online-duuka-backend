from pydantic import BaseModel, EmailStr


class RequestVerificationEmailPayload(BaseModel):
    email: EmailStr
