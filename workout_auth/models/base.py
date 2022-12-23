from pydantic import BaseModel


class MyBaseModel(BaseModel):
    class Config(BaseModel.Config):
        orm_mode = True
