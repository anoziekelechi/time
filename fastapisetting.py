#mail.py
from fastapi_mail import FastMail, ConnectionConfig
from api.core.settings import get_settings
from typing import AsyncGenerator,Annotated
#from api.main import app
from fastapi import Depends

mail_config = ConnectionConfig(
    MAIL_USERNAME=get_settings().mail_username,
    MAIL_PASSWORD=get_settings().mail_password,
    MAIL_FROM=get_settings().mail_from,
    MAIL_PORT=get_settings().mail_port,
    MAIL_SERVER=get_settings().mail_server,
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
)


# core/settings.py
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
import os
from typing import Union
from pathlib import Path
from sqlmodel import Field
from enum import StrEnum
from functools import lru_cache


class AppMode(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TESTING = "testing"

class BaseAppSettings(BaseSettings):
    # DTABASE SETTINGS
    app_mode:AppMode = Field(default=AppMode.DEVELOPMENT, alias="APP_MODE")
    postgres_user:str =Field(..., alias=" POSTGRES_USER")
    postgres_password:SecretStr =Field(..., alias="POSTGRES_PASSWORD")
    postgres_host: str = Field(..., alias="POSTGRES_HOST")
    postgres_db:str = Field(..., alias=" POSTGRES_DB")
    postgres_port:int = Field(..., alias="POSTGRES_PORT")
    # ____ EMAIL SETTINGS ____
    mail_username:str= Field(..., alias="MAIL_USERNAME")
    mail_password:SecretStr = Field(...,alias="MAIL_PASSWORD")
    mail_server:str = Field(..., alias="MAIL_SERVER")
    mail_from:str = Field(..., alias="MAIL_FROM")
    mail_port:int = Field(..., alias="MAIL_PORT")
    #mail_starttls: bool = Field(...,alias="MAIL_STARTTLS")
   # mail_ssl_tls:bool = Field(..., alias="MAIL_SSL_TLS")
    #___REDIS ___
    redis_url : str = Field(..., alias="REDIS_URL")
    image_dev:str = "development/"
    image_pro:str = "production/"
    
    def is_production(self) -> bool:
        return self.app_mode == AppMode.PRODUCTION
    @property
    def database_url(self) -> str:
        return f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password.get_secret_value()}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        
    @property
    def image_prefix(self) -> str:
         return self.image_pro if self.is_production() else self.image_dev
 # DEV SETTING
class DevSettings(BaseAppSettings):
    model_config = SettingsConfigDict(
    env_file = str(Path(__file__).parent.parent.parent.parent / ".env.development"),
    env_file_encoding='utf-8',
    extra="ignore",
    case_sensitive=False,
    )
    
class Prod(BaseAppSettings):
    aws_region: str = Field(..., alias="AWS_REGION")
   
    model_config = SettingsConfigDict(
    env_file = None, #None, #lets docker injects
    env_file_encoding='utf-8',
    extra="ignore",
    case_sensitive=False,
    )
    
    
@lru_cache()
def get_settings() -> BaseAppSettings:
#def get_settings() -> Union[DevSettings,Prod]:
    env = os.getenv("APP_MODE", "development").lower()
    if env == "development":
        return  DevSettings()
    else:
        return Prod()
