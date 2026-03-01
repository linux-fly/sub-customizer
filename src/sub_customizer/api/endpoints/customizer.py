import ipaddress
import socket
from typing import Annotated, Optional
from urllib import parse

from fastapi import APIRouter, HTTPException, Request
from fastapi.params import Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import HttpUrl

from sub_customizer import ClashSubCustomizer
from sub_customizer.api.config import settings
from sub_customizer.api.render import templates
from sub_customizer.customizer import CustomizerError, is_url

router = APIRouter()


def _split_rules(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _resolve_host_ips(host: str) -> set[str]:
    host_ip = _parse_ip(host)
    if host_ip is not None:
        return {str(host_ip)}

    resolved_ips = set()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return resolved_ips

    for info in infos:
        addr = info[4][0]
        ip_obj = _parse_ip(addr)
        if ip_obj is not None:
            resolved_ips.add(str(ip_obj))
    return resolved_ips


def _is_private_like_ip(ip_str: str) -> bool:
    ip_obj = ipaddress.ip_address(ip_str)
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or getattr(ip_obj, "is_site_local", False)
    )


def _host_matches_rule(host: str, resolved_ips: set[str], rule: str) -> bool:
    normalized_rule = rule.strip().lower()
    if not normalized_rule:
        return False

    try:
        network = ipaddress.ip_network(normalized_rule, strict=False)
    except ValueError:
        network = None

    if network is not None:
        candidates = set(resolved_ips)
        host_ip = _parse_ip(host)
        if host_ip is not None:
            candidates.add(str(host_ip))
        for ip_str in candidates:
            if ipaddress.ip_address(ip_str) in network:
                return True
        return False

    normalized_host = host.lower()
    if normalized_rule.startswith("*."):
        suffix = normalized_rule[2:]
        return normalized_host.endswith(f".{suffix}")
    if normalized_rule.startswith("."):
        suffix = normalized_rule[1:]
        return normalized_host == suffix or normalized_host.endswith(f".{suffix}")
    return normalized_host == normalized_rule or normalized_host.endswith(
        f".{normalized_rule}"
    )


def _matches_any_rule(host: str, resolved_ips: set[str], rules: list[str]) -> bool:
    return any(_host_matches_rule(host, resolved_ips, rule) for rule in rules)


def _validate_outbound_url(url_value: str, field_name: str):
    parsed = parse.urlparse(url_value)
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise HTTPException(status_code=422, detail=f"{field_name} 缺少主机名")

    resolved_ips = _resolve_host_ips(host) if settings.url_resolve_host_ips else set()
    host_ip = _parse_ip(host)
    if settings.url_block_private_network:
        candidates = set()
        if host_ip is not None:
            candidates.add(str(host_ip))
        if settings.url_resolve_host_ips:
            candidates.update(resolved_ips)
        for ip_str in candidates:
            if _is_private_like_ip(ip_str):
                raise HTTPException(
                    status_code=422,
                    detail=f"{field_name} 禁止访问内网或保留地址: {host}",
                )

    blocklist = _split_rules(settings.url_blocklist)
    if blocklist and _matches_any_rule(host, resolved_ips, blocklist):
        raise HTTPException(status_code=422, detail=f"{field_name} 命中黑名单: {host}")

    allowlist = _split_rules(settings.url_allowlist)
    if allowlist and not _matches_any_rule(host, resolved_ips, allowlist):
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} 不在白名单中: {host}",
        )


def _ensure_overlay_permission(overlay_config: Optional[str], token: Optional[str]):
    if not overlay_config:
        return
    source = "url"
    if overlay_config.startswith("func:"):
        source = "function"
    elif not is_url(overlay_config):
        source = "file"

    if source == "url":
        return

    is_admin = bool(settings.admin_token) and token == settings.admin_token
    if not is_admin:
        raise HTTPException(
            status_code=403,
            detail=(
                "文件和函数类型的 overlay_config 仅管理员可用。"
                "请在 query 中提供有效 token。"
            ),
        )


@router.get("/sub_custom", summary="订阅自定义")
def clash_sub(
    url: Annotated[HttpUrl, Query(description="订阅链接")],
    remote_config: Annotated[HttpUrl, Query(description="远程配置文件")] = None,
    overlay_config: Annotated[
        Optional[str],
        Query(
            description=(
                "补丁配置来源。支持文件、URL，"
                "或函数来源 func:module:function。"
                "文件和函数来源仅从各自配置目录加载。"
            ),
        ),
    ] = None,
    token: Annotated[
        Optional[str], Query(description="管理员 token，用于启用文件/函数类型 overlay")
    ] = None,
    no_proxy: Annotated[
        bool, Query(description="获取订阅链接时是否强制不使用代理")
    ] = False,
):
    try:
        remote_config = remote_config or settings.default_remote_config
        url_str = str(url)
        remote_config_str = str(remote_config) if remote_config else None

        _ensure_overlay_permission(overlay_config, token)
        _validate_outbound_url(url_str, "url")
        if remote_config_str and is_url(remote_config_str):
            _validate_outbound_url(remote_config_str, "remote_config")
        if overlay_config and is_url(overlay_config):
            _validate_outbound_url(overlay_config, "overlay_config")

        sub = ClashSubCustomizer.from_url(str(url), no_proxy=no_proxy)
        written = sub.write_remote_config(
            remote_config_str,
            overlay_config=overlay_config,
            overlay_file_dir=settings.overlay_file_dir,
            overlay_function_dir=settings.overlay_function_dir,
        )
        return PlainTextResponse(
            written,
            headers=sub.get_passthrough_response_headers(),
        )
    except CustomizerError as e:
        raise HTTPException(
            status_code=422,
            detail=str(e),
        ) from e


@router.get("/sub_customizer", summary="订阅自定义面板")
def sub_customizer(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="customizer.html",
        context={
            "base_url": request.url_for("clash_sub"),
            "remote_config": settings.default_remote_config,
            "overlay_config": None,
            "token": None,
            "overlay_file_dir": settings.overlay_file_dir,
            "overlay_function_dir": settings.overlay_function_dir,
        },
    )
