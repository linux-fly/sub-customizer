from enum import Enum
from typing import List, Optional, Union

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


class ProxyTypeEnum(str, Enum):
    SS = "ss"
    VMESS = "vmess"
    SOCKS5 = "socks5"
    HTTP = "http"
    SNELL = "snell"
    TROJAN = "trojan"
    SSR = "ssr"


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
    name: str
    type: ProxyTypeEnum
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
    name: str
    type: ProxyGroupTypeEnum
    proxies: List[Union[str, Proxy]]
    tolerance: Optional[int] = None
    lazy: Optional[bool] = None
    url: Optional[str] = None
    interval: Optional[int] = None
    strategy: Optional[str] = None
    interface_name: Optional[str] = Field(None, alias="interface-name")
    routing_mark: Optional[int] = Field(None, alias="routing-mark")
    use: Optional[List[str]] = None


class ProxyProvider(BaseModel):
    type: ProxyProviderTypeEnum
    url: Optional[str] = None
    interval: Optional[int] = None
    path: str
    health_check: Optional[dict] = Field(None, alias="health-check")


class Tunnel(BaseModel):
    network: List[NetworkEnum]
    address: str
    target: str
    proxy: str


class Rule(BaseModel):
    type: RuleTypeEnum
    value: str
    proxy: str


class DNS(BaseModel):
    enable: bool
    listen: str = None
    default_nameserver: List[str] = Field(None, alias="default-nameserver")
    fake_ip_range: str = Field(None, alias="fake-ip-range")
    nameserver: List[str] = None
    fallback: Optional[List[str]] = None
    fallback_filter: Optional[dict] = Field(None, alias="fallback-filter")
    nameserver_policy: Optional[dict] = Field(None, alias="nameserver-policy")


class ClashConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    port: int = 7890
    socks_port: int = Field(None, alias="socks-port")
    redir_port: Optional[int] = Field(None, alias="redir-port")
    tproxy_port: Optional[int] = Field(None, alias="tproxy-port")
    mixed_port: Optional[int] = Field(None, alias="mixed-port")
    authentication: Optional[List[str]] = None
    allow_lan: Optional[bool] = Field(None, alias="allow-lan")
    bind_address: Optional[str] = Field(None, alias="bind-address")
    mode: ModeEnum = ModeEnum.RULE
    log_level: Optional[LogLevelEnum] = Field(None, alias="log-level")
    ipv6: Optional[bool] = None
    external_controller: str = Field(None, alias="external-controller")
    external_ui: Optional[str] = Field(None, alias="external-ui")
    secret: Optional[str] = None
    interface_name: Optional[str] = Field(None, alias="interface-name")
    routing_mark: Optional[int] = Field(None, alias="routing-mark")
    hosts: Optional[dict] = None
    profile: Optional[dict] = None
    dns: Optional[DNS] = None
    proxies: List[Proxy] = None
    proxy_groups: List[ProxyGroup] = Field(None, alias="proxy-groups")
    proxy_providers: Optional[List[ProxyProvider]] = Field(
        None, alias="proxy-providers"
    )
    tunnels: Optional[List[Tunnel]] = None
    rules: List[Rule] = None
