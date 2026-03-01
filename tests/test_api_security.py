import pytest
from fastapi import HTTPException

from sub_customizer.api.endpoints import customizer as endpoint
from sub_customizer.customizer import OverlayConfigError


class _DummySub:
    def write_remote_config(self, *args, **kwargs):
        return b"ok"

    @staticmethod
    def get_passthrough_response_headers():
        return {"subscription-userinfo": "upload=1; download=2; total=3; expire=4"}


def _setup_open_url_policy(monkeypatch):
    monkeypatch.setattr(endpoint.settings, "url_block_private_network", False)
    monkeypatch.setattr(endpoint.settings, "url_resolve_host_ips", False)
    monkeypatch.setattr(endpoint.settings, "url_allowlist", "")
    monkeypatch.setattr(endpoint.settings, "url_blocklist", "")


def test_anonymous_cannot_use_file_overlay(monkeypatch):
    _setup_open_url_policy(monkeypatch)
    monkeypatch.setattr(endpoint.settings, "admin_token", "secret")
    monkeypatch.setattr(
        endpoint.ClashSubCustomizer, "from_url", lambda *args, **kwargs: _DummySub()
    )

    with pytest.raises(HTTPException) as exc_info:
        endpoint.clash_sub(
            url="https://example.com/sub",
            overlay_config="overlay.yaml",
            token=None,
        )
    assert exc_info.value.status_code == 403


def test_admin_can_use_file_overlay(monkeypatch):
    _setup_open_url_policy(monkeypatch)
    monkeypatch.setattr(endpoint.settings, "admin_token", "secret")
    monkeypatch.setattr(
        endpoint.ClashSubCustomizer, "from_url", lambda *args, **kwargs: _DummySub()
    )

    response = endpoint.clash_sub(
        url="https://example.com/sub",
        overlay_config="overlay.yaml",
        token="secret",
    )
    assert response.status_code == 200
    assert response.body == b"ok"


def test_customizer_error_is_mapped_to_422(monkeypatch):
    _setup_open_url_policy(monkeypatch)
    monkeypatch.setattr(endpoint.settings, "admin_token", None)

    def _raise(*args, **kwargs):
        raise OverlayConfigError("bad overlay")

    monkeypatch.setattr(endpoint.ClashSubCustomizer, "from_url", _raise)

    with pytest.raises(HTTPException) as exc_info:
        endpoint.clash_sub(url="https://example.com/sub")
    assert exc_info.value.status_code == 422
    assert "bad overlay" in str(exc_info.value.detail)


def test_private_network_url_is_blocked(monkeypatch):
    monkeypatch.setattr(endpoint.settings, "admin_token", None)
    monkeypatch.setattr(endpoint.settings, "url_block_private_network", True)
    monkeypatch.setattr(endpoint.settings, "url_resolve_host_ips", False)
    monkeypatch.setattr(endpoint.settings, "url_allowlist", "")
    monkeypatch.setattr(endpoint.settings, "url_blocklist", "")

    with pytest.raises(HTTPException) as exc_info:
        endpoint.clash_sub(url="http://127.0.0.1/sub")
    assert exc_info.value.status_code == 422
    assert "url 禁止访问内网或保留地址" in str(exc_info.value.detail)


def test_allowlist_denies_unknown_host(monkeypatch):
    monkeypatch.setattr(endpoint.settings, "admin_token", None)
    monkeypatch.setattr(endpoint.settings, "url_block_private_network", False)
    monkeypatch.setattr(endpoint.settings, "url_resolve_host_ips", False)
    monkeypatch.setattr(endpoint.settings, "url_allowlist", "allowed.com")
    monkeypatch.setattr(endpoint.settings, "url_blocklist", "")
    monkeypatch.setattr(endpoint, "_resolve_host_ips", lambda host: set())

    with pytest.raises(HTTPException) as exc_info:
        endpoint.clash_sub(url="https://blocked.com/sub")
    assert exc_info.value.status_code == 422
    assert "不在白名单中" in str(exc_info.value.detail)


def test_blocklist_denies_host(monkeypatch):
    monkeypatch.setattr(endpoint.settings, "admin_token", None)
    monkeypatch.setattr(endpoint.settings, "url_block_private_network", False)
    monkeypatch.setattr(endpoint.settings, "url_resolve_host_ips", False)
    monkeypatch.setattr(endpoint.settings, "url_allowlist", "")
    monkeypatch.setattr(endpoint.settings, "url_blocklist", "blocked.com")
    monkeypatch.setattr(endpoint, "_resolve_host_ips", lambda host: set())

    with pytest.raises(HTTPException) as exc_info:
        endpoint.clash_sub(url="https://blocked.com/sub")
    assert exc_info.value.status_code == 422
    assert "命中黑名单" in str(exc_info.value.detail)


def test_domain_with_fake_ip_not_blocked_when_dns_resolution_disabled(monkeypatch):
    monkeypatch.setattr(endpoint.settings, "admin_token", None)
    monkeypatch.setattr(endpoint.settings, "url_block_private_network", True)
    monkeypatch.setattr(endpoint.settings, "url_resolve_host_ips", False)
    monkeypatch.setattr(endpoint.settings, "url_allowlist", "")
    monkeypatch.setattr(endpoint.settings, "url_blocklist", "")
    monkeypatch.setattr(endpoint, "_resolve_host_ips", lambda host: {"198.18.0.1"})
    monkeypatch.setattr(
        endpoint.ClashSubCustomizer, "from_url", lambda *args, **kwargs: _DummySub()
    )

    response = endpoint.clash_sub(url="https://example.com/sub")
    assert response.status_code == 200


def test_domain_with_fake_ip_blocked_when_dns_resolution_enabled(monkeypatch):
    monkeypatch.setattr(endpoint.settings, "admin_token", None)
    monkeypatch.setattr(endpoint.settings, "url_block_private_network", True)
    monkeypatch.setattr(endpoint.settings, "url_resolve_host_ips", True)
    monkeypatch.setattr(endpoint.settings, "url_allowlist", "")
    monkeypatch.setattr(endpoint.settings, "url_blocklist", "")
    monkeypatch.setattr(endpoint, "_resolve_host_ips", lambda host: {"198.18.0.1"})

    with pytest.raises(HTTPException) as exc_info:
        endpoint.clash_sub(url="https://example.com/sub")
    assert exc_info.value.status_code == 422
    assert "url 禁止访问内网或保留地址" in str(exc_info.value.detail)
