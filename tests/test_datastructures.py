import pytest
from pydantic import ValidationError

from sub_customizer.datastructures import ClashConfig


# 测试ClashConfig模型的基本验证
def test_clash_config_valid():
    config_data = {
        "port": 7890,
        "socks_port": 1080,
        "redir_port": 1081,
        "tproxy_port": 1082,
        "mixed_port": 1083,
        "authentication": ["user:pass"],
        "skip_auth_prefixes": ["127.0.0.1/8"],
        "lan_allowed_ips": ["0.0.0.0/0"],
        "lan_disallowed_ips": ["192.168.0.3/32"],
        "allow_lan": True,
        "bind_address": "0.0.0.0",
        "mode": "rule",
        "log_level": "info",
        "ipv6": True,
        "unified_delay": True,
        "tcp_concurrent": True,
        "find_process_mode": "strict",
        "global_client_fingerprint": "chrome",
        "keep_alive_idle": 600,
        "keep_alive_interval": 15,
        "external_controller": "0.0.0.0:9090",
        "external_controller_tls": "0.0.0.0:9443",
        "external_ui": "/path/to/ui",
        "external_ui_name": "metacubexd",
        "external_ui_url": "https://example.com/ui.zip",
        "external_doh_server": "/dns-query",
        "secret": "mysecret",
        "interface_name": "eth0",
        "routing_mark": 100,
        "hosts": {"example.com": "1.2.3.4"},
        "profile": {"path": "/path/to/profile"},
        "geodata_mode": True,
        "geodata_loader": "standard",
        "geosite_matcher": "mph",
        "geox_url": {"geoip": "https://example.com/geoip.dat"},
        "geo_auto_update": False,
        "geo_update_interval": 24,
        "dns": {
            "enable": True,
            "listen": "0.0.0.0",
            "default_nameserver": ["8.8.8.8", "8.8.4.4"],
            "enhanced-mode": "fake-ip",
            "fake_ip_range": "198.18.0.0/16",
            "nameserver": ["1.1.1.1"],
            "fallback": ["2.2.2.2"],
            "fallback_filter": {"geosite": "category-ads"},
            "nameserver_policy": {"geosite:category-ads": "1.1.1.1"},
        },
        "sniffer": {"enable": True},
        "tun": {"enable": True, "stack": "mixed"},
        "ntp": {"enable": True, "server": "time.apple.com", "port": 123},
        "listeners": [{"name": "mixed-in", "type": "mixed", "port": 10810}],
        "proxies": [
            {
                "name": "proxy1",
                "type": "vmess",
                "server": "server1.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "alterId": 64,
                "cipher": "auto",
                "network": "tcp",
                "tls": True,
                "skip-cert-verify": True,
                "server-name": "server1.example.com",
                "ws-opts": {"path": "/ws", "headers": {"Host": "example.com"}},
                "h2-opts": {"path": "/h2"},
                "grpc-opts": {"grpc-service-name": "example"},
                "obfs": "http",
                "protocol": "auth",
                "obfs-param": "param1",
                "protocol-param": "param2",
                "udp": True,
            }
        ],
        "proxy_groups": [
            {
                "name": "group1",
                "type": "load-balance",
                "proxies": ["proxy1", "proxy2"],
                "url": "http://example.com",
                "interval": 300,
                "strategy": "random",
                "interface-name": "eth1",
                "routing-mark": 200,
                "use": ["group2"],
            }
        ],
        "proxy_providers": {
            "provider1": {
                "type": "http",
                "url": "http://example.com/providers",
                "interval": 3600,
                "path": "/path/to/providers",
                "health-check": {"url": "http://example.com/health"},
            }
        },
        "rule_providers": {
            "rule1": {
                "type": "http",
                "behavior": "classical",
                "url": "http://example.com/rules.yaml",
                "path": "/path/to/rules.yaml",
            }
        },
        "tunnels": [
            {
                "network": ["tcp", "udp"],
                "address": "1.2.3.4",
                "target": "example.com:80",
                "proxy": "proxy1",
            },
            "tcp,127.0.0.1:6666,rds.mysql.com:3306,vpn",
        ],
        "rules": ["DOMAIN-SUFFIX,example.com,proxy1"],
        "sub_rules": {"sub-rule-name1": ["DOMAIN,google.com,proxy1"]},
    }

    config = ClashConfig(**config_data)
    assert config.port == 7890
    assert config.unified_delay is True
    assert config.tcp_concurrent is True
    assert config.find_process_mode == "strict"
    assert config.global_client_fingerprint == "chrome"
    assert config.keep_alive_idle == 600
    assert config.keep_alive_interval == 15
    assert config.geodata_mode is True
    assert config.geodata_loader == "standard"
    assert config.geosite_matcher == "mph"
    assert config.geox_url == {"geoip": "https://example.com/geoip.dat"}
    assert config.geo_auto_update is False
    assert config.geo_update_interval == 24
    assert config.dns.enhanced_mode == "fake-ip"
    assert config.sniffer.enable is True
    assert config.tun.enable is True
    assert config.tun.stack == "mixed"
    assert config.ntp == {"enable": True, "server": "time.apple.com", "port": 123}
    assert config.external_controller_tls == "0.0.0.0:9443"
    assert config.external_ui_name == "metacubexd"
    assert config.external_doh_server == "/dns-query"
    assert config.proxy_providers["provider1"].type == "http"
    assert config.rule_providers["rule1"].behavior == "classical"
    assert config.listeners[0].name == "mixed-in"


# 测试ClashConfig模型的错误处理
def test_clash_config_invalid():
    invalid_data = {
        "port": "not_an_int",  # port字段应为整数
        # 其他无效数据...
    }

    with pytest.raises(ValidationError):
        ClashConfig(**invalid_data)


def test_clash_config_field_descriptions():
    fields = ClashConfig.model_fields
    assert fields["port"].description
    assert fields["allow_lan"].description
    assert fields["dns"].description
    assert fields["unified_delay"].description
    assert fields["tcp_concurrent"].description
    assert fields["find_process_mode"].description
    assert fields["global_client_fingerprint"].description
