from datetime import datetime
from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = 'bearer'


class RefreshToken(BaseModel):
    user_id: int
    refresh_token: str

    class Config:
        orm_mode = True


class BaseUser(BaseModel):
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

    class Config:
        orm_mode = True
