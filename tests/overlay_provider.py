def get_overlay():
    return {
        "append_proxies": [
            {
                "name": "Webshare-From-Function",
                "type": "socks5",
                "server": "10.0.0.1",
                "port": 9001,
                "username": "user",
                "password": "pass",
                "udp": False,
                "dialer-proxy": "US",
            }
        ],
        "append_proxy_groups": [
            {
                "name": "Webshare",
                "type": "select",
                "proxies": ["Webshare-From-Function"],
            }
        ],
        "inject_group_proxies": [{"group": "Proxies", "proxies": ["Webshare"]}],
        "prepend_rules": ["AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"],
    }


def get_overlay_with_config(config):
    proxy_names = [proxy.get("name") for proxy in config.get("proxies", [])]
    group_name = "Google" if "US" in proxy_names else "Proxies"
    return {
        "inject_group_proxies": [{"group": group_name, "proxies": ["US"]}],
        "prepend_rules": ["RULE-SET,example,US"],
    }
