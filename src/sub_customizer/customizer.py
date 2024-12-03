import configparser
import logging
import re
from collections import OrderedDict
from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, List, Literal, Optional, TypedDict
from urllib import parse

import requests
import yaml
from pydantic import ValidationError
from yaml import YAMLError

from .datastructures import ClashConfig

logger = logging.getLogger(__name__)


class CustomizerError(Exception):
    pass


class LoadSubscriptionError(CustomizerError):
    pass


@lru_cache(None)
def is_url(url: str) -> bool:
    try:
        result = parse.urlparse(url)
        return result.scheme in ["http", "https", "ftp"] and bool(result.netloc)
    except ValueError:
        return False


class ConfigParserMultiValues(OrderedDict):
    def __setitem__(self, key, value):
        if key in self and isinstance(value, list):
            self[key].extend(value)
        else:
            super().__setitem__(key, value)

    @staticmethod
    def getlist(value):
        return value.splitlines()


class ConfigParser(configparser.RawConfigParser):
    if TYPE_CHECKING:

        def getlist(self, section: str, option: str, **kwargs) -> list[str]:  # type: ignore
            ...

    def __init__(
        self, strict=False, dict_type=ConfigParserMultiValues, converters=None, **kwargs
    ):
        if converters is None:
            converters = {"list": ConfigParserMultiValues.getlist}
        super().__init__(
            strict=strict, dict_type=dict_type, converters=converters, **kwargs
        )


class RulesetParseResultT(TypedDict, total=False):
    group: str
    type: Literal["surge", "quanx", "clash-domain", "clash-ipcidr", "clash-classic"]
    rule: str
    is_url: bool
    interval: Optional[int]


class CustomProxyGroupParseResultT(TypedDict, total=False):
    name: str
    type: Literal["select", "url-test", "fallback", "load-balance"]
    rules: list[str]
    test_url: Optional[str]
    interval: Optional[int]
    timeout: Optional[int]
    tolerance: Optional[int]


class RulesetParser:
    # 定义支持的类型和前缀映射
    VALID_TYPES = ["surge", "quanx", "clash-domain", "clash-ipcidr", "clash-classic"]

    def __init__(self):
        self.ruleset_pattern = re.compile(
            r"^(?P<group>.+?),"
            r"(?:\[(?P<type>[a-zA-Z0-9\-]+)])?"  # 匹配类型（可选）
            r"(?P<rule>.*?)"  # 匹配规则部分
            r"(?:,(\d+))?$"  # 匹配可选的更新间隔（秒）
        )

    def parse(self, rulesets: List[str]) -> List[RulesetParseResultT]:
        """
        解析规则集，返回处理后的字典列表。
        """
        parsed_rules = []
        for ruleset in rulesets:
            ruleset = ruleset.strip()
            match = self.ruleset_pattern.match(ruleset)
            if match:
                group = match.group("group").strip()
                rule_content = match.group("rule").strip()
                interval = int(i) if (i := match.group(4)) else None

                # 获取类型和去除前缀后的规则内容
                rule_type, cleaned_rule_content = self._get_type_and_rule(rule_content)

                parsed_rules.append(
                    {
                        "group": group,
                        "type": rule_type,
                        "rule": cleaned_rule_content,
                        "interval": interval,
                        "is_url": is_url(cleaned_rule_content),
                    }
                )
        return parsed_rules

    def _get_type_and_rule(self, rule_content: str) -> (str, str):
        """
        根据规则内容获取对应的类型和去除前缀后的规则内容。
        """
        for rule_type in self.VALID_TYPES:
            prefix = f"{rule_type}:"
            if rule_content.startswith(prefix):
                return rule_type, rule_content[len(prefix) :]
        return "surge", rule_content  # 默认是 surge 类型


class CustomProxyGroupParser:
    support_types = {"select", "url-test", "fallback", "load-balance"}

    def _parse_rest(self, rest):
        rules = []
        test_url = interval = timeout = tolerance = None
        for i, item in enumerate(rest):
            item = item.strip()
            if not is_url(item):
                rules.append(item)
            else:
                test_url = item
                interval_params = rest[i + 1].split(",")
                interval = interval_params[0]
                timeout = interval_params[1] if len(interval_params) > 1 else None
                tolerance = interval_params[2] if len(interval_params) > 2 else None
                break
        r = {"rules": rules}
        if test_url:
            r["test_url"] = test_url
            r["interval"] = interval
            if timeout:
                r["timeout"] = timeout
            if tolerance:
                r["tolerance"] = tolerance
        return r

    def parse(self, groups: list[str]) -> list[CustomProxyGroupParseResultT]:
        """
        用于自定义组的选项 会覆盖 主程序目录中的配置文件 里的内容
        使用以下模式生成 Clash 代理组，带有 "[]" 前缀将直接添加
        Format: Group_Name`select`Rule_1`Rule_2`...
                Group_Name`url-test|fallback|load-balance`Rule_1`Rule_2`...`test_url`interval[,timeout][,tolerance]
        Rule with "[]" prefix will be added directly.
        """
        parsed_groups = []
        for group_str in groups:
            group_str = group_str.strip()
            parts = group_str.split("`")
            if len(parts) < 3:
                continue
            group_name, type_, *rest = parts
            if type_ not in self.support_types:
                continue
            try:
                r = self._parse_rest(rest)
            except Exception as e:
                logger.exception(e)
                continue
            group = {"name": group_name, "type": type_}
            group.update(r)
            parsed_groups.append(group)
        return parsed_groups


class RemoteConfigParser:
    sections = ["custom"]
    supported_options = [
        "ruleset",
        "custom_proxy_group",
        "overwrite_original_rules",
        "enable_rule_generator",
    ]
    supported_override_options = [
        "port",
        "socks-port",
        "redir-port",
        "tproxy-port",
        "mixed-port",
        "allow-lan",
        "bind-address",
        "mode",
        "log-level",
        "ipv6",
        "external-controller",
        "external-ui",
        "secret",
        "interface-name",
        "routing-mark",
        "hosts",
        "profile",
        "dns",
    ]

    def __init__(self, ini_str, clash_config: dict = None):
        self.ini_str = ini_str
        self.config = ConfigParser()
        self.config.read_string(ini_str)
        self.clash_config = clash_config or {}

    @classmethod
    def from_url(cls, url: str, **init_kws):
        res = requests.get(url)
        try:
            return cls(res.text, **init_kws)
        except configparser.Error as e:
            logger.exception(e)
            raise CustomizerError("解析远程配置错误") from e

    @cached_property
    def options(self):
        rulesets = []
        custom_proxy_groups = []
        overwrite_original_rules = False
        enable_rule_generator = True
        override_options = {}
        for section in self.sections:
            for option in self.supported_override_options:
                if (
                    opt_value := self.config.get(section, option, fallback=None)
                ) is not None:
                    override_options.setdefault(option, opt_value)
            overwrite_original_rules = self.config.getboolean(
                section, "overwrite_original_rules", fallback=overwrite_original_rules
            )
            enable_rule_generator = self.config.getboolean(
                section, "enable_rule_generator", fallback=enable_rule_generator
            )

            rulesets.extend(self.config.getlist(section, "ruleset", fallback=[]))
            custom_proxy_groups.extend(
                self.config.getlist(section, "custom_proxy_group", fallback=[])
            )
        return {
            "rulesets": rulesets,
            "custom_proxy_groups": custom_proxy_groups,
            "overwrite_original_rules": overwrite_original_rules,
            "enable_rule_generator": enable_rule_generator,
            "override_options": override_options,
        }

    @cached_property
    def all_clash_proxies(self) -> dict[str, str]:
        all_proxies = {p["name"]: p for p in self.clash_config.get("proxies") or []}
        return all_proxies

    def parse_rulesets(self):
        rulesets = self.options["rulesets"]
        parser = RulesetParser()
        return parser.parse(rulesets)

    def parse_custom_proxy_groups(self):
        custom_proxy_groups = self.options["custom_proxy_groups"]
        parser = CustomProxyGroupParser()
        return parser.parse(custom_proxy_groups)

    def _convert_rules_text(self, rules_text: str, group: str) -> list:
        lines = rules_text.strip().splitlines()
        results = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            parts.insert(2, group)
            results.append(",".join(parts))
        return results

    def extract_rules(self, rulesets: list[RulesetParseResultT]):
        session = requests.Session()
        rules = []
        for rule_set in rulesets:
            if rule_set["is_url"]:
                url = rule_set["rule"]
                try:
                    resp = session.get(url)
                    resp.raise_for_status()
                except requests.RequestException:
                    continue
                rules.extend(self._convert_rules_text(resp.text, rule_set["group"]))
            elif rule_set["rule"].startswith("[]"):
                rule = rule_set["rule"][2:]
                if rule.lower() == "final":
                    rule = "MATCH"
                rules.append(f"{rule},{rule_set['group']}")
        return rules

    @lru_cache(maxsize=128)
    def _get_proxies_by_regex(self, regex: str):
        proxies = []
        for proxy in self.all_clash_proxies:
            if re.search(regex, proxy):
                proxies.append(proxy)
        return proxies

    def extract_proxy_groups(self, proxy_groups: list[CustomProxyGroupParseResultT]):
        groups = []
        for proxy_group in proxy_groups:
            group = {"name": proxy_group["name"], "type": proxy_group["type"]}
            rules = proxy_group["rules"]
            proxies = []
            for rule in rules:
                if rule.startswith("[]"):
                    proxies.append(rule[2:])
                else:
                    proxies.extend(self._get_proxies_by_regex(rule))
            group["proxies"] = proxies
            for k in {
                "test_url": "url",
                "interval": "interval",
                "timeout": "timeout",
                "tolerance": "tolerance",
            }:
                if k in proxy_group:
                    group[k] = proxy_group[k]
            groups.append(group)
        return groups

    def get_rules(self):
        rulesets = self.parse_rulesets()
        return self.extract_rules(rulesets)

    def get_proxy_groups(self):
        groups = self.parse_custom_proxy_groups()
        return self.extract_proxy_groups(groups)

    def get_override_options(self):
        override_options = self.options["override_options"]
        try:
            inst = ClashConfig.model_validate(override_options)
            valid_options = inst.model_dump(
                mode="json", by_alias=True, exclude_unset=True
            )
            return valid_options
        except ValidationError as e:
            logger.exception(e)
            return {}


class ClashSubCustomizer:
    headers = {"User-Agent": "Clash"}

    def __init__(self, yaml_str):
        self.yaml_str = yaml_str
        self.config = yaml.safe_load(yaml_str)

    @classmethod
    def from_url(cls, url: str, no_proxy=False):
        proxies = None
        if no_proxy:
            parsed = parse.urlparse(url)
            proxies = {"no_proxy": parsed.hostname}
        res = requests.get(url, headers=cls.headers, proxies=proxies)
        try:
            return cls(res.text)
        except YAMLError as e:
            logger.exception(e)
            raise LoadSubscriptionError("解析订阅文件错误") from e

    def write_remote_config(self, remote_url) -> bytes:
        if not remote_url:
            return self.dump()
        parser = RemoteConfigParser.from_url(remote_url, clash_config=self.config)
        proxy_groups = parser.get_proxy_groups()
        if proxy_groups:
            self.config["proxy-groups"] = proxy_groups
        if parser.options["enable_rule_generator"]:
            rules = parser.get_rules()
            if rules:
                if parser.options["overwrite_original_rules"]:
                    self.config["rules"] = rules
                else:
                    # 这里扩展rules而不是覆盖，远程配置中的rules优先级更高
                    self.config["rules"] = rules + self.config.get("rules", [])
        else:
            self.config["rules"] = []
        override_options = parser.get_override_options()
        self.config.update(override_options)
        return self.dump()

    def dump(self) -> bytes:
        return yaml.dump(
            self.config,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            encoding="utf-8",
        )
