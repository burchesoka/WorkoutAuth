from datetime import datetime
from typing import Optional

from .base import MyBaseModel


class Token(MyBaseModel):
    access_token: str
    refresh_token: str
    token_type: str = 'bearer'


class InRefreshToken(MyBaseModel):
    user_id: int
    refresh_token: str


class RefreshToken(InRefreshToken):
    id: int


class RefreshTokenOnly(MyBaseModel):
    refresh_token: str


class BaseUser(MyBaseModel):
    email: str
    name: str
    api_id: Optional[int]
    telegram_id: Optional[int]


class UserCreate(BaseUser):
    password: str


class UserUpdate(BaseUser):
    pass


class InUser(BaseUser):
    password_hash: str
    last_seen: datetime
    deleted: bool


class OutUser(BaseUser):
    id: int
    last_seen: datetime


class User(BaseUser):
    id: int
    password_hash: str
    last_seen: datetime
    deleted: bool