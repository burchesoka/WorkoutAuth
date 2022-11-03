import logging

from fastapi import (
    APIRouter,
    Depends,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm

from .. import models
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
        new_token: models.User = Depends(refresh_current_user_token),
):
    return new_token


@router.get(
    '/user/',
    response_model=models.User,
)
def get_user(user: models.User = Depends(get_current_user)):
    return user
