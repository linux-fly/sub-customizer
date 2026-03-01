from sub_customizer.customizer import RemoteConfigParser


def test_remote_config_parser_supports_new_override_options():
    ini_str = """
[custom]
port=7891
mode=rule
unified-delay=true
tcp-concurrent=true
find-process-mode=strict
global-client-fingerprint=chrome
keep-alive-idle=600
keep-alive-interval=15
geodata-mode=true
geodata-loader=standard
geosite-matcher=mph
"""

    parser = RemoteConfigParser(ini_str)
    options = parser.get_override_options()

    assert options["port"] == 7891
    assert options["mode"] == "rule"
    assert options["unified-delay"] is True
    assert options["tcp-concurrent"] is True
    assert options["find-process-mode"] == "strict"
    assert options["global-client-fingerprint"] == "chrome"
    assert options["keep-alive-idle"] == 600
    assert options["keep-alive-interval"] == 15
    assert options["geodata-mode"] is True
    assert options["geodata-loader"] == "standard"
    assert options["geosite-matcher"] == "mph"


def test_remote_config_parser_parses_structured_override_options():
    ini_str = """
[custom]
hosts={"example.com": "1.2.3.4"}
profile={"store-selected": true}
dns={"enable": true, "nameserver": ["1.1.1.1"]}
geox-url={"geoip": "https://example.com/geoip.dat"}
sniffer={"enable": true}
tun={"enable": true, "stack": "mixed"}
ntp={"enable": true, "server": "time.apple.com", "port": 123}
"""

    parser = RemoteConfigParser(ini_str)
    options = parser.get_override_options()

    assert options["hosts"] == {"example.com": "1.2.3.4"}
    assert options["profile"] == {"store-selected": True}
    assert options["dns"] == {"enable": True, "nameserver": ["1.1.1.1"]}
    assert options["geox-url"] == {"geoip": "https://example.com/geoip.dat"}
    assert options["sniffer"] == {"enable": True}
    assert options["tun"] == {"enable": True, "stack": "mixed"}
    assert options["ntp"] == {
        "enable": True,
        "server": "time.apple.com",
        "port": 123,
    }
