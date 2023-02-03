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
)
from ..db import tables
from ..db.database import get_session
from ..settings import settings
from ..db.repositories import UsersRepository, RefreshTokensRepository


logger = logging.getLogger(__name__)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/sign-in/')


class AuthService:
    def __init__(self, session: AsyncSession = Depends(get_session)):
        self.session = session

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def verify_token(cls, token: str) -> models.OutUser:
        """ TODO? check user in db if he was deleted?"""
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
        logger.debug(user_data)

        try:
            user = models.OutUser.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    async def register_new_user(
        self,
        user_data: models.UserCreate,
    ) -> models.Token:
        logger.debug('register_new_user %s', user_data)

        users_repo = UsersRepository(session=self.session)

        """ Check email if it already in db """
        check_email = await users_repo.get_by_email(user_data.email)

        if check_email:
            logger.info('user with email: %s exist', user_data.email)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail='User with this email already exist'
            )

        user = models.InUser(
            email=user_data.email,
            name=user_data.name,
            password_hash=self.hash_password(user_data.password),
            last_seen=datetime.utcnow(),
            telegram_id=user_data.telegram_id,
            deleted=False,
        )

        created_user = await users_repo.create(in_model=user)

        return await self.create_token(created_user)

    async def create_token(self, user: tables.User) -> models.Token:
        user_data = models.OutUser.from_orm(user)
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

        refresh_token_repo = RefreshTokensRepository(session=self.session)
        await refresh_token_repo.create(
            models.InRefreshToken(
                user_id=user.id,
                refresh_token=refresh_token,
            )
        )

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
        except JWTError:
            raise exception from None

        user_data = payload.get('user')
        logger.debug(user_data)

        try:
            user_from_token = models.OutUser.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        await self._compare_with_refresh_tokens_in_db(refresh_token, user_from_token.id)

        users_repo = UsersRepository(self.session)
        user_from_db = await users_repo.get_by_id(user_from_token.id)

        ''' If user was deleted: '''
        if not user_from_db or user_from_db.deleted:
            raise exception

        return await self.create_token(user_from_db)

    async def _compare_with_refresh_tokens_in_db(self, refresh_token: str, user_id: int):
        logger.debug('compare received refresh_token with refresh_tokens in db')

        ''' Get all user's refresh tokens stored in db '''
        refresh_token_repo = RefreshTokensRepository(session=self.session)
        users_refresh_tokens = await refresh_token_repo.get_users_refresh_tokens(user_id)

        logger.debug(users_refresh_tokens)

        ''' Find accordance received refresh token with tokens in db. '''
        ''' On success delete chosen token from db, otherwise raise 401 '''
        for token in users_refresh_tokens:
            logger.debug(token.refresh_token)
            if refresh_token == token.refresh_token:
                await refresh_token_repo.delete(token.id)
                return True

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate refresh token',
            headers={'WWW-Authenticate': 'Bearer'},
        )


def get_current_user(token: str = Depends(oauth2_scheme)) -> models.OutUser:
    return AuthService.verify_token(token)


async def refresh_current_user_token(
        auth_service: AuthService = Depends(),
        refresh_token: str = Depends(oauth2_scheme),
) -> models.Token:
    return await auth_service.refresh_token(refresh_token)
