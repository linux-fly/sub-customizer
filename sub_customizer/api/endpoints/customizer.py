from typing import Annotated

from fastapi import APIRouter, Request
from fastapi.params import Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import HttpUrl

from sub_customizer import ClashSubCustomizer
from sub_customizer.api.config import settings
from sub_customizer.api.render import templates

router = APIRouter()


@router.get("/sub_custom", summary="订阅自定义")
def clash_sub(
    url: Annotated[HttpUrl, Query(description="订阅链接")],
    remote_config: Annotated[HttpUrl, Query(description="远程配置文件")] = None,
    no_proxy: Annotated[
        bool, Query(description="获取订阅链接时是否强制不使用代理")
    ] = False,
):
    remote_config = remote_config or settings.default_remote_config
    sub = ClashSubCustomizer.from_url(str(url), no_proxy=no_proxy)
    written = sub.write_remote_config(str(remote_config))
    return PlainTextResponse(written)


@router.get("/sub_customizer", summary="订阅自定义面板")
def sub_customizer(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="customizer.html",
        context={
            "base_url": request.url_for("clash_sub"),
            "remote_config": settings.default_remote_config,
        },
    )
