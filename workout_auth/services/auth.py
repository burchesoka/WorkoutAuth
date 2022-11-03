import logging
from datetime import (
    datetime,
    timedelta,
)

from fastapi import (
    Depends,
    HTTPException,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from jose import (
    JWTError,
    jwt,
)
from passlib.hash import bcrypt
from pydantic import ValidationError
from sqlalchemy.orm import Session
from sqlalchemy.future import select

from .. import (
    models,
    tables,
)
from ..database import get_session
from ..settings import settings


logger = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/sign-in/')


def get_current_user(token: str = Depends(oauth2_scheme)) -> models.User:
    return AuthService.verify_token(token)


class AuthService:
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def verify_token(cls, token: str) -> models.User:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm],
            )
        except JWTError:
            raise exception from None

        user_data = payload.get('user')

        try:
            user = models.User.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    @classmethod
    def create_token(cls, user: tables.User) -> models.Token:
        user_data = models.User.from_orm(user)
        now = datetime.utcnow()
        user_data.last_seen = str(user_data.last_seen)
        print(user_data)
        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + timedelta(seconds=settings.jwt_expires_s),
            'sub': str(user_data.id),
            'user': user_data.dict(),
        }
        token = jwt.encode(
            payload,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        return models.Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    async def register_new_user(
        self,
        user_data: models.UserCreate,
    ) -> models.Token:
        logger.debug('register_new_user')
        user = tables.User(
            email=user_data.email,
            api_id=1,
            name=user_data.name,
            password_hash=self.hash_password(user_data.password),
            last_seen=datetime.utcnow(),
            status='user',
            telegram_id=1,
        )
        print(user)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return self.create_token(user)

    async def authenticate_user(
        self,
        email: str,
        password: str,
    ) -> models.Token:
        print('QQQQ!!!!QQQQ')
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect email or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )

        result = await self.session.execute(
            select(tables.User)
            .where(tables.User.email == email)
        )
        user = result.scalar()
        print(user)
        print(models.User.from_orm(user))
        if not user:
            raise exception

        if not self.verify_password(password, user.password_hash):
            raise exception

        return self.create_token(user)
