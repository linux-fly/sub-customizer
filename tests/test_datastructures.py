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
        "allow_lan": True,
        "bind_address": "0.0.0.0",
        "mode": "rule",
        "log_level": "info",
        "ipv6": True,
        "external_controller": "0.0.0.0:9090",
        "external_ui": "/path/to/ui",
        "secret": "mysecret",
        "interface_name": "eth0",
        "routing_mark": 100,
        "hosts": {"example.com": "1.2.3.4"},
        "profile": {"path": "/path/to/profile"},
        "dns": {
            "enable": True,
            "listen": "0.0.0.0",
            "default_nameserver": ["8.8.8.8", "8.8.4.4"],
            "fake_ip_range": "198.18.0.0/16",
            "nameserver": ["1.1.1.1"],
            "fallback": ["2.2.2.2"],
            "fallback_filter": {"geosite": "category-ads"},
            "nameserver_policy": {"geosite:category-ads": "1.1.1.1"},
        },
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
        "proxy_providers": [
            {
                "type": "http",
                "url": "http://example.com/providers",
                "interval": 3600,
                "path": "/path/to/providers",
                "health-check": {"url": "http://example.com/health"},
            }
        ],
        "tunnels": [
            {
                "network": ["tcp", "udp"],
                "address": "1.2.3.4",
                "target": "example.com:80",
                "proxy": "proxy1",
            }
        ],
        "rules": [{"type": "DOMAIN-SUFFIX", "value": "example.com", "proxy": "proxy1"}],
    }

    config = ClashConfig(**config_data)
    assert config.port == 7890
    # 更多断言...


# 测试ClashConfig模型的错误处理
def test_clash_config_invalid():
    invalid_data = {
        "port": "not_an_int",  # port字段应为整数
        # 其他无效数据...
    }

    with pytest.raises(ValidationError):
        ClashConfig(**invalid_data)
