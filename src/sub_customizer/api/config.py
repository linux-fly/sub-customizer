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
    admin_token: Optional[str] = None
    url_block_private_network: bool = True
    url_resolve_host_ips: bool = False
    url_allowlist: str = ""
    url_blocklist: str = ""
    overlay_file_dir: str = "overlay_configs"
    overlay_function_dir: str = "overlay_providers"


settings = Settings()
