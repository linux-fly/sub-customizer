from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class ModeEnum(str, Enum):
    RULE = "rule"
    GLOBAL = "global"
    DIRECT = "direct"


class LogLevelEnum(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    DEBUG = "debug"
    SILENT = "silent"


class EnhancedModeEnum(str, Enum):
    FAKE_IP = "fake-ip"
    REDIR_HOST = "redir-host"


class ProxyTypeEnum(str, Enum):
    SS = "ss"
    VMESS = "vmess"
    SOCKS5 = "socks5"
    HTTP = "http"
    SNELL = "snell"
    TROJAN = "trojan"
    SSR = "ssr"
    HYSTERIA = "hysteria"
    HYSTERIA2 = "hysteria2"
    WIREGUARD = "wireguard"
    MASQUE = "masque"
    TUIC = "tuic"
    DNS = "dns"
    DIRECT = "direct"
    SSH = "ssh"
    MIERU = "mieru"
    SUDOKU = "sudoku"
    ANYTLS = "anytls"
    VLESS = "vless"


class NetworkEnum(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    WS = "ws"
    H2 = "h2"
    GRPC = "grpc"


class ProxyGroupTypeEnum(str, Enum):
    RELAY = "relay"
    URL_TEST = "url-test"
    FALLBACK = "fallback"
    LOAD_BALANCE = "load-balance"
    SELECT = "select"


class ProxyProviderTypeEnum(str, Enum):
    HTTP = "http"
    FILE = "file"
    INLINE = "inline"


class RuleTypeEnum(str, Enum):
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    DOMAIN_KEYWORD = "DOMAIN-KEYWORD"
    DOMAIN = "DOMAIN"
    SRC_IP_CIDR = "SRC-IP-CIDR"
    IP_CIDR = "IP-CIDR"
    GEOIP = "GEOIP"
    DST_PORT = "DST-PORT"
    SRC_PORT = "SRC-PORT"
    RULE_SET = "RULE-SET"
    MATCH = "MATCH"


class Proxy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str
    type: Union[ProxyTypeEnum, str]
    server: str
    port: int
    cipher: Optional[str] = None
    password: Optional[str] = None
    plugin: Optional[str] = None
    plugin_opts: Optional[dict] = Field(None, alias="plugin-opts")
    uuid: Optional[str] = None
    alterId: Optional[int] = None
    network: Optional[NetworkEnum] = None
    tls: Optional[bool] = None
    skip_cert_verify: Optional[bool] = Field(None, alias="skip-cert-verify")
    servername: Optional[str] = None
    ws_opts: Optional[dict] = Field(None, alias="ws-opts")
    h2_opts: Optional[dict] = Field(None, alias="h2-opts")
    grpc_opts: Optional[dict] = Field(None, alias="grpc-opts")
    obfs: Optional[str] = None
    protocol: Optional[str] = None
    obfs_param: Optional[str] = Field(None, alias="obfs-param")
    protocol_param: Optional[str] = Field(None, alias="protocol-param")
    udp: Optional[bool] = None


class ProxyGroup(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str
    type: ProxyGroupTypeEnum
    proxies: List[str]
    tolerance: Optional[int] = None
    lazy: Optional[bool] = None
    url: Optional[str] = None
    interval: Optional[int] = None
    strategy: Optional[str] = None
    interface_name: Optional[str] = Field(None, alias="interface-name")
    routing_mark: Optional[int] = Field(None, alias="routing-mark")
    use: Optional[List[str]] = None


class ProxyProvider(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    type: Union[ProxyProviderTypeEnum, str]
    url: Optional[str] = None
    interval: Optional[int] = None
    path: Optional[str] = None
    proxy: Optional[str] = None
    header: Optional[Dict[str, List[str]]] = None
    health_check: Optional[dict] = Field(None, alias="health-check")
    override: Optional[dict] = None
    payload: Optional[List[dict]] = None


class Tunnel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    network: List[NetworkEnum]
    address: str
    target: str
    proxy: str


class Rule(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    type: RuleTypeEnum
    value: str
    proxy: str


class DNS(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    enable: bool = Field(..., description="Enable built-in DNS server.")
    cache_algorithm: Optional[str] = Field(
        None,
        alias="cache-algorithm",
        description="DNS cache algorithm.",
    )
    prefer_h3: Optional[bool] = Field(
        None,
        alias="prefer-h3",
        description="Enable DoH HTTP/3 probing.",
    )
    listen: Optional[str] = Field(
        None, description="DNS listen address, e.g. 0.0.0.0:53."
    )
    ipv6: Optional[bool] = Field(None, description="Enable DNS AAAA response.")
    ipv6_timeout: Optional[int] = Field(
        None,
        alias="ipv6-timeout",
        description="AAAA query timeout in milliseconds.",
    )
    default_nameserver: Optional[List[str]] = Field(
        None,
        alias="default-nameserver",
        description="Bootstrap DNS servers used for resolving upstream DNS hosts.",
    )
    enhanced_mode: Optional[EnhancedModeEnum] = Field(
        None,
        alias="enhanced-mode",
        description="Enhanced DNS mode. Typically fake-ip.",
    )
    fake_ip_range: Optional[str] = Field(
        None,
        alias="fake-ip-range",
        description="CIDR for fake-ip allocation when enhanced-mode=fake-ip.",
    )
    fake_ip_filter: Optional[List[str]] = Field(
        None,
        alias="fake-ip-filter",
        description="Domains/rules that bypass fake-ip.",
    )
    fake_ip_filter_mode: Optional[str] = Field(
        None,
        alias="fake-ip-filter-mode",
        description="Mode for fake-ip filter matching.",
    )
    fake_ip_ttl: Optional[int] = Field(
        None,
        alias="fake-ip-ttl",
        description="TTL for fake-ip responses.",
    )
    respect_rules: Optional[bool] = Field(
        None,
        alias="respect-rules",
        description="Whether upstream DNS resolution follows traffic rules.",
    )
    nameserver: Optional[List[str]] = Field(
        None,
        description="Primary upstream DNS server list.",
    )
    fallback: Optional[List[str]] = Field(
        None,
        description="Fallback upstream DNS server list.",
    )
    fallback_filter: Optional[dict] = Field(
        None,
        alias="fallback-filter",
        description="Fallback DNS filter options.",
    )
    nameserver_policy: Optional[dict] = Field(
        None,
        alias="nameserver-policy",
        description="Per-domain DNS routing policy.",
    )
    proxy_server_nameserver: Optional[List[str]] = Field(
        None,
        alias="proxy-server-nameserver",
        description="DNS servers dedicated for resolving proxy server domains.",
    )
    proxy_server_nameserver_policy: Optional[Dict[str, Any]] = Field(
        None,
        alias="proxy-server-nameserver-policy",
        description="Per-domain policy for proxy server DNS resolution.",
    )
    direct_nameserver: Optional[List[str]] = Field(
        None,
        alias="direct-nameserver",
        description="DNS servers dedicated for direct outbound resolution.",
    )
    direct_nameserver_follow_policy: Optional[bool] = Field(
        None,
        alias="direct-nameserver-follow-policy",
        description="Whether direct-nameserver obeys nameserver-policy.",
    )


class TLSConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    certificate: Optional[str] = None
    private_key: Optional[str] = Field(None, alias="private-key")
    client_auth_type: Optional[str] = Field(None, alias="client-auth-type")
    client_auth_cert: Optional[str] = Field(None, alias="client-auth-cert")
    ech_key: Optional[str] = Field(None, alias="ech-key")
    custom_certificates: Optional[List[str]] = Field(None, alias="custom-certificates")
    custom_certifactes: Optional[List[str]] = Field(None, alias="custom-certifactes")


class ExternalControllerCORS(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    allow_origins: Optional[List[str]] = Field(None, alias="allow-origins")
    allow_private_network: Optional[bool] = Field(None, alias="allow-private-network")


class ProfileConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    store_selected: Optional[bool] = Field(None, alias="store-selected")
    store_fake_ip: Optional[bool] = Field(None, alias="store-fake-ip")


class TunConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    enable: Optional[bool] = None
    stack: Optional[str] = None
    dns_hijack: Optional[List[str]] = Field(None, alias="dns-hijack")
    auto_detect_interface: Optional[bool] = Field(None, alias="auto-detect-interface")
    auto_route: Optional[bool] = Field(None, alias="auto-route")
    auto_redirect: Optional[bool] = Field(None, alias="auto-redirect")
    route_address_set: Optional[List[str]] = Field(None, alias="route-address-set")
    route_exclude_address_set: Optional[List[str]] = Field(
        None, alias="route-exclude-address-set"
    )
    route_address: Optional[List[str]] = Field(None, alias="route-address")
    strict_route: Optional[bool] = Field(None, alias="strict-route")
    include_interface: Optional[List[str]] = Field(None, alias="include-interface")
    exclude_interface: Optional[List[str]] = Field(None, alias="exclude-interface")


class SnifferConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    enable: Optional[bool] = None
    force_dns_mapping: Optional[bool] = Field(None, alias="force-dns-mapping")
    parse_pure_ip: Optional[bool] = Field(None, alias="parse-pure-ip")
    override_destination: Optional[bool] = Field(None, alias="override-destination")
    sniff: Optional[Dict[str, Any]] = None
    force_domain: Optional[List[str]] = Field(None, alias="force-domain")
    skip_src_address: Optional[List[str]] = Field(None, alias="skip-src-address")
    skip_dst_address: Optional[List[str]] = Field(None, alias="skip-dst-address")
    skip_domain: Optional[List[str]] = Field(None, alias="skip-domain")
    sniffing: Optional[List[str]] = None
    port_whitelist: Optional[List[str]] = Field(None, alias="port-whitelist")


class RuleProvider(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    type: Optional[str] = None
    behavior: Optional[str] = None
    format: Optional[str] = None
    interval: Optional[int] = None
    path: Optional[str] = None
    url: Optional[str] = None
    proxy: Optional[str] = None
    payload: Optional[List[str]] = None


class Listener(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    name: str
    type: str
    port: Union[int, str]
    listen: Optional[str] = None


class ClashConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    port: int = Field(7890, description="HTTP proxy listen port.")
    socks_port: Optional[int] = Field(
        None,
        alias="socks-port",
        description="SOCKS5 proxy listen port.",
    )
    redir_port: Optional[int] = Field(
        None,
        alias="redir-port",
        description="redir proxy listen port (Linux/macOS).",
    )
    tproxy_port: Optional[int] = Field(
        None,
        alias="tproxy-port",
        description="tproxy listen port (Linux).",
    )
    mixed_port: Optional[int] = Field(
        None,
        alias="mixed-port",
        description="Mixed HTTP+SOCKS listen port.",
    )
    authentication: Optional[List[str]] = Field(
        None,
        description="Authentication list in `user:pass` format.",
    )
    skip_auth_prefixes: Optional[List[str]] = Field(
        None,
        alias="skip-auth-prefixes",
        description="CIDR ranges that bypass inbound auth.",
    )
    lan_allowed_ips: Optional[List[str]] = Field(
        None,
        alias="lan-allowed-ips",
        description="Allowed LAN source CIDR ranges.",
    )
    lan_disallowed_ips: Optional[List[str]] = Field(
        None,
        alias="lan-disallowed-ips",
        description="Denied LAN source CIDR ranges.",
    )
    allow_lan: Optional[bool] = Field(
        None,
        alias="allow-lan",
        description="Allow LAN access.",
    )
    bind_address: Optional[str] = Field(
        None,
        alias="bind-address",
        description="Bind address for local services.",
    )
    mode: ModeEnum = Field(ModeEnum.RULE, description="Proxy mode.")
    log_level: Optional[LogLevelEnum] = Field(
        None,
        alias="log-level",
        description="Runtime log level.",
    )
    ipv6: Optional[bool] = Field(None, description="Enable IPv6 stack.")
    unified_delay: Optional[bool] = Field(
        None,
        alias="unified-delay",
        description="Use unified latency test behavior for proxy groups.",
    )
    tcp_concurrent: Optional[bool] = Field(
        None,
        alias="tcp-concurrent",
        description="Enable concurrent TCP dialing.",
    )
    find_process_mode: Optional[str] = Field(
        None,
        alias="find-process-mode",
        description="Process lookup mode for rule matching (e.g. strict/off/always).",
    )
    global_client_fingerprint: Optional[str] = Field(
        None,
        alias="global-client-fingerprint",
        description="Global TLS client fingerprint for compatible outbound types.",
    )
    keep_alive_idle: Optional[int] = Field(
        None,
        alias="keep-alive-idle",
        description="TCP keepalive idle seconds.",
    )
    keep_alive_interval: Optional[int] = Field(
        None,
        alias="keep-alive-interval",
        description="TCP keepalive probe interval seconds.",
    )
    external_controller: Optional[str] = Field(
        None,
        alias="external-controller",
        description="External controller listen address.",
    )
    external_ui: Optional[str] = Field(
        None,
        alias="external-ui",
        description="Path to external UI assets.",
    )
    secret: Optional[str] = Field(
        None,
        description="Secret token for external controller.",
    )
    interface_name: Optional[str] = Field(
        None,
        alias="interface-name",
        description="Default outbound interface name.",
    )
    routing_mark: Optional[int] = Field(
        None,
        alias="routing-mark",
        description="Routing mark value for outbound traffic.",
    )
    hosts: Optional[dict] = Field(None, description="Static host mappings.")
    profile: Optional[dict] = Field(
        None,
        description="Profile options, such as store-selected/store-fake-ip.",
    )
    geodata_mode: Optional[bool] = Field(
        None,
        alias="geodata-mode",
        description="Enable geodata database mode.",
    )
    geodata_loader: Optional[str] = Field(
        None,
        alias="geodata-loader",
        description="Geodata loader strategy.",
    )
    geosite_matcher: Optional[str] = Field(
        None,
        alias="geosite-matcher",
        description="Geosite matcher implementation.",
    )
    geox_url: Optional[dict] = Field(
        None,
        alias="geox-url",
        description="Remote URLs for geodata resources.",
    )
    geo_auto_update: Optional[bool] = Field(
        None,
        alias="geo-auto-update",
        description="Whether to auto-update geodata resources.",
    )
    geo_update_interval: Optional[int] = Field(
        None,
        alias="geo-update-interval",
        description="Geodata update interval in hours.",
    )
    tls: Optional[TLSConfig] = Field(None, description="TLS server configuration.")
    external_controller_tls: Optional[str] = Field(
        None,
        alias="external-controller-tls",
        description="HTTPS external controller listen address.",
    )
    external_controller_cors: Optional[ExternalControllerCORS] = Field(
        None,
        alias="external-controller-cors",
        description="CORS options for external controller.",
    )
    external_controller_unix: Optional[str] = Field(
        None,
        alias="external-controller-unix",
        description="Unix socket path for external controller.",
    )
    external_controller_pipe: Optional[str] = Field(
        None,
        alias="external-controller-pipe",
        description="Windows named pipe for external controller.",
    )
    external_ui_name: Optional[str] = Field(
        None,
        alias="external-ui-name",
        description="External UI bundle name.",
    )
    external_ui_url: Optional[str] = Field(
        None,
        alias="external-ui-url",
        description="External UI bundle download URL.",
    )
    external_doh_server: Optional[str] = Field(
        None,
        alias="external-doh-server",
        description="DoH path exposed on controller port.",
    )
    experimental: Optional[dict] = Field(
        None,
        description="Experimental feature flags.",
    )
    dns: Optional[DNS] = Field(None, description="DNS configuration.")
    sniffer: Optional[SnifferConfig] = Field(
        None, description="Traffic sniffer configuration."
    )
    tun: Optional[TunConfig] = Field(None, description="TUN configuration.")
    ntp: Optional[dict] = Field(
        None,
        description="NTP configuration.",
    )
    proxies: Optional[List[Proxy]] = Field(
        None,
        description="Proxy node definitions.",
    )
    proxy_groups: Optional[List[ProxyGroup]] = Field(
        None,
        alias="proxy-groups",
        description="Proxy group definitions.",
    )
    proxy_providers: Optional[Dict[str, ProxyProvider]] = Field(
        None,
        alias="proxy-providers",
        description="Proxy provider definitions.",
    )
    rule_providers: Optional[Dict[str, RuleProvider]] = Field(
        None,
        alias="rule-providers",
        description="Rule provider definitions.",
    )
    tunnels: Optional[List[Union[Tunnel, str]]] = Field(
        None,
        description="Tunnel definitions.",
    )
    rules: Optional[List[str]] = Field(None, description="Rule list.")
    sub_rules: Optional[Dict[str, List[str]]] = Field(
        None, alias="sub-rules", description="Sub-rule definitions."
    )
    listeners: Optional[List[Listener]] = Field(
        None, description="Inbound listener definitions."
    )
