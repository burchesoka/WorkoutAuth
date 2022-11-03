from datetime import datetime
from enum import Enum
from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = 'bearer'


class UserStatus(str, Enum):
    user = "user"
    just_added_by_trainer = 'just_added_by_trainer'
    new_user = "new-self_added"
    user_without_trainer = "user_without_trainer"


class BaseUser(BaseModel):
    email: str
    name: str
    status: UserStatus
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
