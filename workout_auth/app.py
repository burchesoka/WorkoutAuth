from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import api
from .settings import logger_init


logger = logger_init('workout_auth')


tags_metadata = [
    {
        'name': 'auth',
        'description': 'Авторизация и регистрация',
    },
]

app = FastAPI(
    title='Workout auth',
    description='Сервис регистрации и авторизации',
    version='0.1.0',
    openapi_tags=tags_metadata,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event('startup')
async def startup():
    logger.info('APP STARTED')


@app.on_event('shutdown')
async def shutdown():
    logger.info('APP SHUTDOWN')

app.include_router(api.router)
