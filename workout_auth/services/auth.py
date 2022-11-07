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
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from .. import (
    models,
    tables,
)
from ..database import get_session
from ..settings import settings


logger = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/sign-in/')


class AuthService:
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def verify_token(cls, token: str) -> models.User:
        logger.debug('verify_token')

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

    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    async def register_new_user(
        self,
        user_data: models.UserCreate,
    ) -> models.Token:
        logger.debug('register_new_user %s', user_data)

        """ Check email if it already in db """
        result = await self.session.execute(
            select(tables.User)
            .where(tables.User.email == user_data.email)
        )
        check_email = result.scalar()
        if check_email:
            logger.info('user with email: %s exist', user_data.email)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='User with this email already exist'
            )

        user = tables.User(
            email=user_data.email,
            name=user_data.name,
            password_hash=self.hash_password(user_data.password),
            last_seen=datetime.utcnow(),
            telegram_id=user_data.telegram_id,
        )
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return await self.create_token(user)

    async def create_token(self, user: tables.User) -> models.Token:
        user_data = models.User.from_orm(user)
        now = datetime.utcnow()
        user_data.last_seen = str(user_data.last_seen)
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

        ''' Making refresh token '''
        payload['exp'] = now + timedelta(days=settings.jwt_refresh_expires_d)

        refresh_token = jwt.encode(
            payload,
            settings.jwt_refresh_secret,
            algorithm=settings.jwt_algorithm,
        )

        refresh_token_entry = tables.RefreshToken(
            user_id=user.id,
            refresh_token=refresh_token,
        )
        self.session.add(refresh_token_entry)
        await self.session.commit()

        return models.Token(access_token=token, refresh_token=refresh_token)

    async def authenticate_user(
        self,
        email: str,
        password: str,
    ) -> models.Token:
        logger.debug('authenticate_user %s', email)

        result = await self.session.execute(
            select(tables.User)
            .where(tables.User.email == email)
        )
        user = result.scalar()

        exception = HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail='Incorrect email or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )

        if not user:
            raise exception

        if not self.verify_password(password, user.password_hash):
            raise exception

        return await self.create_token(user)

    async def logout(self, user):
        """
        Logging out user, delete all refresh-tokens.
        Is it needed to log out on all devices?
        """

    async def refresh_token(self, refresh_token: str) -> models.Token:
        logger.debug('refresh_token %s', refresh_token)

        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )

        try:
            payload = jwt.decode(
                refresh_token,
                settings.jwt_refresh_secret,
                algorithms=[settings.jwt_algorithm],

            )
        except JWTError as e:
            raise exception from None

        user_data = payload.get('user')
        logger.debug(user_data)

        try:
            user_model = models.User.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        result = await self.session.execute(
            select(tables.User)
            .where(tables.User.id == user_model.id)
        )
        user = result.scalar()

        ''' If user was deleted: '''
        if not user:
            raise exception

        await self._compare_with_refresh_tokens_in_db(refresh_token, user.id)

        return await self.create_token(user)

    async def _compare_with_refresh_tokens_in_db(self, refresh_token: str, user_id: int):
        logger.debug('compare received refresh_token with refresh_tokens in db')

        ''' Get all user's refresh tokens stored in db '''
        result = await self.session.execute(
            select(tables.RefreshToken)
            .where(tables.RefreshToken.user_id == user_id)
        )
        all_refresh_tokens = result.scalars().all()

        ''' Find accordance received refresh token with tokens in db. '''
        ''' On success delete chosen token from db, otherwise raise 401 '''
        for entry in all_refresh_tokens:
            logger.debug(entry.refresh_token)
            if refresh_token == entry.refresh_token:
                await self.session.delete(entry)
                await self.session.commit()
                return

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )


def get_current_user(token: str = Depends(oauth2_scheme)) -> models.User:
    return AuthService.verify_token(token)


async def refresh_current_user_token(
        auth_service: AuthService = Depends(),
        refresh_token: str = Depends(oauth2_scheme),
) -> models.Token:
    return await auth_service.refresh_token(refresh_token)
