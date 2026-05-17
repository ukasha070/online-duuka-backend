from pydantic import BaseModel, Field
from apps.auth.utils import ClientContext


class DeviceInfoPayload(BaseModel):
    device_id: str | None = Field(default=None, max_length=50)
    device_name: str = Field(max_length=100)
    device_type: str = Field(max_length=50)
    os_name: str = Field(max_length=100)
    browser_name: str | None = Field(default=None, max_length=100)


class CreateSessionPayload(DeviceInfoPayload, ClientContext):
    remember_me: bool = Field(default=False)
