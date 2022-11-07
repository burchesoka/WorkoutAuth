import time

import pytest
from httpx import AsyncClient
from starlette import status

from workout_auth import models
from workout_auth.settings import settings

pytestmark = pytest.mark.asyncio


async def _preconditions(async_client) -> models.Token:
    """
    Creates records in DB for tests
    """
    request_data = {
        "email": "test@test.com",
        "name": "test",
        "telegram_id": 111,
        "last_seen": "2022-11-05T14:51:47.306",
        "password": "test"
    }
    response = await async_client.post('/auth/sign-up/', json=request_data)

    return models.Token.parse_obj(response.json())


async def test_sign_up(async_client: AsyncClient) -> None:
    """
    Проверка регистрации
    TODO Проверка верификации емайла и сложности пароля. Или это сделать на стадии ввода на фронтенде???
    """
    request_data = {
      "email": "test2@test.com",
      "name": "test2",
      "telegram_id": 222,
      "last_seen": "2022-11-05T14:51:47.306",
      "password": "test2"
    }
    response = await async_client.post('/auth/sign-up/', json=request_data)
    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()['access_token'] is not None
    assert response.json()['refresh_token'] is not None
    assert response.json()['token_type'] == 'bearer'


async def test_fail_sign_up(async_client: AsyncClient) -> None:
    await _preconditions(async_client)
    request_data = {
        "email": "test@test.com",
        "name": "test",
        "telegram_id": 11121,
        "last_seen": "2022-11-05T14:51:47.306",
        "password": "test"
    }

    response = await async_client.post('/auth/sign-up/', json=request_data)
    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()['detail'] == 'User with this email already exist'


async def test_sing_in(async_client: AsyncClient) -> None:
    """
    Проверка удачного входа
    """
    await _preconditions(async_client)
    request_data = {
      "username": "test@test.com",
      "password": "test"
    }
    response = await async_client.post('/auth/sign-in/', data=request_data)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()['access_token'] is not None
    assert response.json()['refresh_token'] is not None
    assert response.json()['token_type'] == 'bearer'


async def test_fail_sign_in(async_client: AsyncClient) -> None:
    """
    Wrong credentials
    """
    request_data = {
      "username": "test2@test.com",
      "password": "wrong_pass"
    }
    response = await async_client.post('/auth/sign-in/', data=request_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()['detail'] == 'Incorrect email or password'

    request_data = {
      "username": "wrong@email.com",
      "password": "test2"
    }
    response = await async_client.post('/auth/sign-in/', data=request_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()['detail'] == 'Incorrect email or password'


async def test_refresh_token(async_client: AsyncClient) -> None:
    """
    +Проверка обновления токена
    Если просрочен рефреш токен
    Если он изменен, ??? или от другого аккаунта ???
    Возможно ли выпускать несколько токенов
    Проверить, сохраняются ли в бд рефреш токены???
    """
    tokens = await _preconditions(async_client)
    response = await async_client.post(
        '/auth/refresh/',
        headers={'Authorization': f'Bearer {tokens.refresh_token}'},
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()['access_token'] is not None
    assert response.json()['refresh_token'] is not None
    assert response.json()['token_type'] == 'bearer'


async def test_get_current_user(async_client: AsyncClient) -> None:
    """
    статус 200
    """

    tokens = await _preconditions(async_client)

    responce = await async_client.get(
        '/auth/user/',
        headers={'Authorization': f'Bearer {tokens.access_token}'}
    )
    assert responce.status_code == status.HTTP_200_OK

    user = models.User.parse_obj(responce.json())

    assert user.email == "test@test.com"
    assert responce.json()['name'] == "test"
    assert responce.json()['telegram_id'] == 111


async def test_fail_get_current_user(async_client: AsyncClient) -> None:
    """
    при неверном и при просроченном токене - 401
    """
    old_value = settings.jwt_expires_s

    settings.jwt_expires_s = 1
    tokens = await _preconditions(async_client)
    settings.jwt_expires_s = old_value
    corrupted_token = tokens.access_token[:-7] + 'corrupt'

    response1 = await async_client.get(
        '/auth/user/',
        headers={'Authorization': f'Bearer {corrupted_token}'}
    )
    assert response1.status_code == status.HTTP_401_UNAUTHORIZED
    assert response1.json()['detail'] == 'Could not validate credentials'

    time.sleep(2)

    response2 = await async_client.get(
        '/auth/user/',
        headers={'Authorization': f'Bearer {tokens.access_token}'}
    )
    assert response2.status_code == status.HTTP_401_UNAUTHORIZED
    assert response2.json()['detail'] == 'Could not validate credentials'


async def test_logout(async_client: AsyncClient) -> None:
    """
    При выходе удаляются все рефреш токены
    """
