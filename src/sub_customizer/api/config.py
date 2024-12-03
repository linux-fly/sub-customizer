import pathlib
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".apienv", extra="ignore")

    debug: bool = False
    root_dir: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent
    api_dir: pathlib.Path = pathlib.Path(__file__).resolve().parent
    cors_all: bool = False
    default_remote_config: Optional[str] = None


settings = Settings()
