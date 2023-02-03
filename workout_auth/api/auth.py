import logging

from fastapi import (
    APIRouter,
    Depends,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm

from .. import models
from workout_auth.db.repositories import UsersRepository, RefreshTokensRepository
from ..services.auth import (
    AuthService,
    get_current_user,
    refresh_current_user_token,
)


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix='/auth',
    tags=['auth'],
)


@router.post(
    '/sign-up/',
    summary="Create new user",
    response_model=models.Token,
    status_code=status.HTTP_201_CREATED,
)
async def sign_up(
    user_data: models.UserCreate,
    auth_service: AuthService = Depends(),
):
    logger.debug('sign_up')
    return await auth_service.register_new_user(user_data)


@router.post(
    '/sign-in/',
    response_model=models.Token,
)
async def sign_in(
    auth_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(),
):
    return await auth_service.authenticate_user(
        auth_data.username,
        auth_data.password,
    )


@router.post('/refresh/', response_model=models.Token)
def refresh(
        new_token: models.OutUser = Depends(refresh_current_user_token),
):
    return new_token


@router.post('/logout/', status_code=status.HTTP_204_NO_CONTENT)
async def logout(
        refresh_token: models.RefreshTokenOnly,
        user: models.OutUser = Depends(get_current_user),
        repository: RefreshTokensRepository = Depends(),
):
    await repository.delete_by_refresh_token(refresh_token)
    return status.HTTP_204_NO_CONTENT


@router.get(
    '/user/',
    response_model=models.OutUser,
)
async def get_user(
        user: models.OutUser = Depends(get_current_user),
        repository: UsersRepository = Depends(),
):
    logger.debug('get_user')
    user_from_bd = await repository.get_by_id(user.id)
    return models.OutUser.parse_obj(user_from_bd)


@router.put('/user/',
            summary="Update user",
            response_model=models.OutUser,
            status_code=status.HTTP_200_OK,
            )
async def update_user(
        user_data: models.UserUpdate,
        user: models.OutUser = Depends(get_current_user),
        repository: UsersRepository = Depends(),
):
    logger.debug('Update user id: %s, data: %s', user.id, user_data)

    user_from_db = await repository.get_by_id(user.id)
    in_user_data = models.InUser(
        **user_data.dict(),
        last_seen=user_from_db.last_seen,
        password_hash=user_from_db.password_hash,
        deleted=user_from_db.deleted,
    )

    return await repository.update(user.id, in_user_data)
