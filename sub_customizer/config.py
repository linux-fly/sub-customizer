import pathlib
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    debug: bool = False
    secret_key: str = "unsafe secret key"  # 请生成一个随机字符串
    root_dir: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent


class APISettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".apienv", extra="ignore")

    debug: bool = False
    cors_all: bool = False
    default_remote_config: Optional[str] = None


settings = Settings()
api_settings = APISettings()
