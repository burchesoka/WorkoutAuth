from datetime import datetime
from typing import Optional

from .base import BaseSchema


class Token(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str = 'bearer'


class RefreshTokenCreate(BaseSchema):
    user_id: int
    refresh_token: str


class RefreshToken(RefreshTokenCreate):
    id: int


class BaseUser(BaseSchema):
    email: str
    name: str
    telegram_id: Optional[int]
    last_seen: datetime


class UserCreate(BaseUser):
    password: str


class UserUpdate(BaseUser):
    api_id: Optional[int]
    password: str


class User(BaseUser):
    id: int
    api_id: Optional[int]

