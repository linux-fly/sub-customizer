import pytest
import yaml

from sub_customizer.customizer import ClashSubCustomizer, OverlayConfigError

BASE_YAML = """
proxies:
  - name: US
    type: ss
    server: us.example.com
    port: 443
    cipher: aes-128-gcm
    password: pass
proxy-groups:
  - name: Proxies
    type: select
    proxies:
      - US
  - name: Google
    type: select
    proxies:
      - Proxies
rules:
  - DOMAIN,example.com,DIRECT
"""

OVERLAY_YAML = """
append_proxies:
  - name: "Webshare-NY"
    type: socks5
    server: 64.52.28.96
    port: 7783
    username: "demo"
    password: "demo"
    udp: false
    dialer-proxy: "US"
append_proxy_groups:
  - name: "Webshare"
    type: select
    proxies:
      - "Webshare-NY"
inject_group_proxies:
  - group: "Proxies"
    proxies: ["Webshare"]
  - group: "Google"
    proxies: ["Webshare"]
prepend_rules:
  - "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
"""


def _load_output_config(raw: bytes) -> dict:
    return yaml.safe_load(raw.decode("utf-8"))


def _assert_overlay_effect(config: dict):
    proxy_names = [proxy["name"] for proxy in config["proxies"]]
    assert "Webshare-NY" in proxy_names

    groups = {group["name"]: group for group in config["proxy-groups"]}
    assert "Webshare" in groups
    assert "Webshare-NY" in groups["Webshare"]["proxies"]
    assert "Webshare" in groups["Proxies"]["proxies"]
    assert "Webshare" in groups["Google"]["proxies"]

    assert config["rules"][0] == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"


def test_passthrough_response_headers():
    sub = ClashSubCustomizer(
        BASE_YAML,
        source_headers={
            "Subscription-Userinfo": "upload=1; download=2; total=3; expire=4",
            "Profile-Update-Interval": "24",
            "Profile-Web-Page": "https://example.com",
            "X-Clash-Trace": "trace-id",
            "Content-Type": "text/plain",
        },
    )
    headers = sub.get_passthrough_response_headers()
    assert headers["subscription-userinfo"].startswith("upload=1")
    assert headers["profile-update-interval"] == "24"
    assert headers["profile-web-page"] == "https://example.com"
    assert headers["x-clash-trace"] == "trace-id"
    assert "content-type" not in headers


def test_overlay_from_file(tmp_path, monkeypatch):
    overlay_dir = tmp_path / "overlay_configs"
    overlay_dir.mkdir()
    (overlay_dir / "overlay.yaml").write_text(OVERLAY_YAML, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    sub = ClashSubCustomizer(BASE_YAML)
    raw = sub.write_remote_config(
        remote_url=None,
        overlay_config="overlay.yaml",
        overlay_file_dir="overlay_configs",
    )

    _assert_overlay_effect(_load_output_config(raw))


def test_overlay_file_dir_auto_created_when_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target_dir = tmp_path / "overlay_configs"
    assert not target_dir.exists()

    sub = ClashSubCustomizer(BASE_YAML)
    with pytest.raises(OverlayConfigError):
        sub.write_remote_config(
            remote_url=None,
            overlay_config="missing.yaml",
            overlay_file_dir="overlay_configs",
        )
    assert target_dir.is_dir()


def test_overlay_file_outside_dir_not_allowed(tmp_path, monkeypatch):
    overlay_dir = tmp_path / "overlay_configs"
    overlay_dir.mkdir()
    (tmp_path / "outside.yaml").write_text(OVERLAY_YAML, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    sub = ClashSubCustomizer(BASE_YAML)
    with pytest.raises(OverlayConfigError):
        sub.write_remote_config(
            remote_url=None,
            overlay_config="../outside.yaml",
            overlay_file_dir="overlay_configs",
        )


def test_overlay_file_dir_outside_cwd_not_allowed(tmp_path):
    outside_dir = tmp_path / "outside_overlay_configs"
    outside_dir.mkdir()
    (outside_dir / "overlay.yaml").write_text(OVERLAY_YAML, encoding="utf-8")

    sub = ClashSubCustomizer(BASE_YAML)
    with pytest.raises(OverlayConfigError):
        sub.write_remote_config(
            remote_url=None,
            overlay_config="overlay.yaml",
            overlay_file_dir=str(outside_dir),
        )


def test_overlay_function_dir_auto_created_when_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target_dir = tmp_path / "overlay_providers"
    assert not target_dir.exists()

    sub = ClashSubCustomizer(BASE_YAML)
    with pytest.raises(OverlayConfigError):
        sub.write_remote_config(
            remote_url=None,
            overlay_config="func:webshare:get_overlay",
            overlay_function_dir="overlay_providers",
        )
    assert target_dir.is_dir()


def test_overlay_from_url(monkeypatch):
    class DummyResponse:
        text = OVERLAY_YAML

        @staticmethod
        def raise_for_status():
            return None

    def fake_get(url, headers=None):
        assert url == "https://example.com/overlay.yaml"
        return DummyResponse()

    monkeypatch.setattr("sub_customizer.customizer.requests.get", fake_get)

    sub = ClashSubCustomizer(BASE_YAML)
    raw = sub.write_remote_config(
        remote_url=None, overlay_config="https://example.com/overlay.yaml"
    )

    _assert_overlay_effect(_load_output_config(raw))


def test_overlay_from_function_module(tmp_path, monkeypatch):
    provider_content = (
        "def get_overlay():\n"
        "    return {\n"
        "        'append_proxies': [{\n"
        "            'name': 'Webshare-From-Function',\n"
        "            'type': 'socks5',\n"
        "            'server': '10.0.0.1',\n"
        "            'port': 9001,\n"
        "            'username': 'user',\n"
        "            'password': 'pass',\n"
        "            'udp': False,\n"
        "            'dialer-proxy': 'US',\n"
        "        }],\n"
        "        'append_proxy_groups': [{\n"
        "            'name': 'Webshare',\n"
        "            'type': 'select',\n"
        "            'proxies': ['Webshare-From-Function'],\n"
        "        }],\n"
        "        'inject_group_proxies': [{'group': 'Proxies', 'proxies': ['Webshare']}],\n"
        "        'prepend_rules': ['AND,((NETWORK,UDP),(DST-PORT,443)),REJECT'],\n"
        "    }\n"
    )
    providers_dir = tmp_path / "overlay_providers"
    providers_dir.mkdir()
    (providers_dir / "webshare.py").write_text(provider_content, encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    sub = ClashSubCustomizer(BASE_YAML)
    raw = sub.write_remote_config(
        remote_url=None,
        overlay_config="func:webshare:get_overlay",
        overlay_function_dir="overlay_providers",
    )

    config = _load_output_config(raw)
    groups = {group["name"]: group for group in config["proxy-groups"]}
    assert "Webshare" in groups
    assert "Webshare-From-Function" in groups["Webshare"]["proxies"]
    assert config["rules"][0] == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"


def test_overlay_from_function_custom_dir(tmp_path, monkeypatch):
    providers_dir = tmp_path / "custom_code"
    providers_dir.mkdir()
    (providers_dir / "provider.py").write_text(
        "def build_overlay(config):\n"
        "    return {\n"
        "        'prepend_rules': ['RULE-SET,local,US'],\n"
        "        'inject_group_proxies': [{'group': 'Google', 'proxies': ['US']}],\n"
        "    }\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    sub = ClashSubCustomizer(BASE_YAML)
    raw = sub.write_remote_config(
        remote_url=None,
        overlay_config="func:provider:build_overlay",
        overlay_function_dir="custom_code",
    )

    config = _load_output_config(raw)
    groups = {group["name"]: group for group in config["proxy-groups"]}
    assert groups["Google"]["proxies"][-1] == "US"
    assert config["rules"][0] == "RULE-SET,local,US"


def test_overlay_inject_nonexistent_group_raises():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: NotExists
    proxies: ["Webshare"]
"""
    with pytest.raises(OverlayConfigError):
        sub.apply_overlay_config(yaml.safe_load(overlay))


def test_overlay_function_accepts_current_config(tmp_path, monkeypatch):
    providers_dir = tmp_path / "overlay_providers"
    providers_dir.mkdir()
    (providers_dir / "webshare.py").write_text(
        "def get_overlay_with_config(config):\n"
        "    proxy_names = [p.get('name') for p in config.get('proxies', [])]\n"
        "    group_name = 'Google' if 'US' in proxy_names else 'Proxies'\n"
        "    return {\n"
        "        'inject_group_proxies': [{'group': group_name, 'proxies': ['US']}],\n"
        "        'prepend_rules': ['RULE-SET,example,US'],\n"
        "    }\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    sub = ClashSubCustomizer(BASE_YAML)
    raw = sub.write_remote_config(
        remote_url=None,
        overlay_config="func:webshare:get_overlay_with_config",
        overlay_function_dir="overlay_providers",
    )

    config = _load_output_config(raw)
    groups = {group["name"]: group for group in config["proxy-groups"]}
    assert groups["Google"]["proxies"][-1] == "US"
    assert config["rules"][0] == "RULE-SET,example,US"


def test_overlay_function_path_not_allowed():
    sub = ClashSubCustomizer(BASE_YAML)
    with pytest.raises(OverlayConfigError):
        sub.write_remote_config(
            remote_url=None,
            overlay_config="func:/tmp/evil.py:get_overlay",
            overlay_function_dir="overlay_providers",
        )


def test_overlay_function_dir_outside_cwd_not_allowed(tmp_path):
    outside_dir = tmp_path / "outside_providers"
    outside_dir.mkdir()
    (outside_dir / "webshare.py").write_text("def get_overlay():\n    return {}\n")

    sub = ClashSubCustomizer(BASE_YAML)
    with pytest.raises(OverlayConfigError):
        sub.write_remote_config(
            remote_url=None,
            overlay_config="func:webshare:get_overlay",
            overlay_function_dir=str(outside_dir),
        )


def test_overlay_inject_position_start():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Proxies
    position: start
    proxies:
      - Webshare
"""
    sub.apply_overlay_config(yaml.safe_load(overlay))
    groups = {group["name"]: group for group in sub.config["proxy-groups"]}
    assert groups["Proxies"]["proxies"][0] == "Webshare"


def test_overlay_inject_before_anchor():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Proxies
    before: US
    proxies:
      - Webshare
"""
    sub.apply_overlay_config(yaml.safe_load(overlay))
    groups = {group["name"]: group for group in sub.config["proxy-groups"]}
    assert groups["Proxies"]["proxies"] == ["Webshare", "US"]


def test_overlay_inject_after_anchor():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Google
    after: Proxies
    proxies:
      - Webshare
"""
    sub.apply_overlay_config(yaml.safe_load(overlay))
    groups = {group["name"]: group for group in sub.config["proxy-groups"]}
    assert groups["Google"]["proxies"] == ["Proxies", "Webshare"]


def test_overlay_inject_before_missing_anchor_raises():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Proxies
    before: NotExists
    proxies:
      - Webshare
"""
    with pytest.raises(OverlayConfigError):
        sub.apply_overlay_config(yaml.safe_load(overlay))


def test_overlay_inject_with_position_and_before_raises():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Proxies
    position: start
    before: US
    proxies:
      - Webshare
"""
    with pytest.raises(OverlayConfigError):
        sub.apply_overlay_config(yaml.safe_load(overlay))


def test_overlay_inject_before_regex_anchor():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Proxies
    before: "re:^U"
    proxies:
      - Webshare
"""
    sub.apply_overlay_config(yaml.safe_load(overlay))
    groups = {group["name"]: group for group in sub.config["proxy-groups"]}
    assert groups["Proxies"]["proxies"] == ["Webshare", "US"]


def test_overlay_inject_after_regex_anchor():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Google
    after: "re:^Prox"
    proxies:
      - Webshare
"""
    sub.apply_overlay_config(yaml.safe_load(overlay))
    groups = {group["name"]: group for group in sub.config["proxy-groups"]}
    assert groups["Google"]["proxies"] == ["Proxies", "Webshare"]


def test_overlay_inject_before_invalid_regex_raises():
    sub = ClashSubCustomizer(BASE_YAML)
    overlay = """
inject_group_proxies:
  - group: Proxies
    before: "re:["
    proxies:
      - Webshare
"""
    with pytest.raises(OverlayConfigError):
        sub.apply_overlay_config(yaml.safe_load(overlay))
