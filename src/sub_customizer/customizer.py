import configparser
import importlib.util
import inspect
import logging
import os
import re
from collections import OrderedDict
from functools import cached_property, lru_cache
from pathlib import Path
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


class OverlayConfigError(CustomizerError):
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
    default_overlay_file_dir = os.getenv(
        "SUB_CUSTOMIZER_OVERLAY_FILE_DIR", "overlay_configs"
    )
    default_overlay_function_dir = os.getenv(
        "SUB_CUSTOMIZER_OVERLAY_FUNCTION_DIR", "overlay_providers"
    )
    passthrough_header_keys = (
        "subscription-userinfo",
        "profile-update-interval",
        "profile-web-page",
        "content-disposition",
        "x-subscription-userinfo",
    )

    def __init__(self, yaml_str, source_headers: Optional[dict] = None):
        self.yaml_str = yaml_str
        self.config = yaml.safe_load(yaml_str)
        self.source_headers = {
            str(k).lower(): str(v)
            for k, v in (source_headers or {}).items()
            if v is not None
        }

    @classmethod
    def from_url(cls, url: str, no_proxy=False):
        proxies = None
        if no_proxy:
            parsed = parse.urlparse(url)
            proxies = {"no_proxy": parsed.hostname}
        res = requests.get(url, headers=cls.headers, proxies=proxies)
        try:
            return cls(res.text, source_headers=dict(res.headers))
        except YAMLError as e:
            logger.exception(e)
            raise LoadSubscriptionError("解析订阅文件错误") from e

    def get_passthrough_response_headers(self) -> dict[str, str]:
        passthrough = {}
        for key in self.passthrough_header_keys:
            if key in self.source_headers:
                passthrough[key] = self.source_headers[key]
        for key, value in self.source_headers.items():
            if key.startswith("x-clash-"):
                passthrough[key] = value
        return passthrough

    @staticmethod
    def _load_yaml_text(yaml_text: str) -> dict:
        try:
            data = yaml.safe_load(yaml_text) or {}
        except YAMLError as e:
            logger.exception(e)
            raise OverlayConfigError("解析补丁配置错误") from e
        if not isinstance(data, dict):
            raise OverlayConfigError("补丁配置必须是字典（mapping）")
        return data

    @classmethod
    def _resolve_overlay_file_dir(cls, overlay_file_dir: Optional[str] = None) -> Path:
        configured_dir = overlay_file_dir or cls.default_overlay_file_dir
        base_cwd = Path.cwd().resolve()
        candidate = Path(configured_dir).expanduser()
        if not candidate.is_absolute():
            candidate = base_cwd / candidate
        resolved_dir = candidate.resolve()
        if not resolved_dir.is_relative_to(base_cwd):
            raise OverlayConfigError(
                f"补丁文件目录必须位于当前运行目录下: {resolved_dir}"
            )
        if resolved_dir.exists() and not resolved_dir.is_dir():
            raise OverlayConfigError(f"补丁文件目录不是目录: {resolved_dir}")
        if not resolved_dir.exists():
            resolved_dir.mkdir(parents=True, exist_ok=True)
        return resolved_dir

    @staticmethod
    def _resolve_overlay_file_path(path: str, overlay_file_dir: Path) -> Path:
        candidate = Path(path).expanduser()
        if candidate.is_absolute():
            file_path = candidate.resolve()
        else:
            file_path = (overlay_file_dir / candidate).resolve()
        if not file_path.is_relative_to(overlay_file_dir):
            raise OverlayConfigError(f"补丁文件越界访问被拒绝: {path}")
        if not file_path.exists() or not file_path.is_file():
            raise OverlayConfigError(f"补丁配置文件不存在: {file_path}")
        return file_path

    @classmethod
    def _load_overlay_from_file(
        cls, path: str, overlay_file_dir: Optional[str] = None
    ) -> dict:
        resolved_dir = cls._resolve_overlay_file_dir(overlay_file_dir=overlay_file_dir)
        p = cls._resolve_overlay_file_path(path, overlay_file_dir=resolved_dir)
        try:
            content = p.read_text(encoding="utf-8")
        except OSError as e:
            raise OverlayConfigError(f"读取补丁配置文件失败: {p}") from e
        return cls._load_yaml_text(content)

    @classmethod
    def _load_overlay_from_url(cls, url: str) -> dict:
        try:
            res = requests.get(url, headers=cls.headers)
            res.raise_for_status()
        except requests.RequestException as e:
            raise OverlayConfigError(f"拉取补丁配置 URL 失败: {url}") from e
        return cls._load_yaml_text(res.text)

    @classmethod
    def _resolve_overlay_function_dir(cls, function_dir: Optional[str] = None) -> Path:
        configured_dir = function_dir or cls.default_overlay_function_dir
        base_cwd = Path.cwd().resolve()
        candidate = Path(configured_dir).expanduser()
        if not candidate.is_absolute():
            candidate = base_cwd / candidate
        resolved_dir = candidate.resolve()
        if not resolved_dir.is_relative_to(base_cwd):
            raise OverlayConfigError(f"函数目录必须位于当前运行目录下: {resolved_dir}")
        if resolved_dir.exists() and not resolved_dir.is_dir():
            raise OverlayConfigError(f"函数目录不是目录: {resolved_dir}")
        if not resolved_dir.exists():
            resolved_dir.mkdir(parents=True, exist_ok=True)
        return resolved_dir

    @staticmethod
    def _resolve_module_file(module_spec: str, function_dir: Path) -> Path:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\.]*", module_spec):
            raise OverlayConfigError(
                f"函数模块名不合法: {module_spec}，仅支持字母/数字/下划线/点号"
            )
        module_path = Path(*module_spec.split(".")).with_suffix(".py")
        file_path = (function_dir / module_path).resolve()
        if not file_path.is_relative_to(function_dir):
            raise OverlayConfigError(f"函数模块越界访问被拒绝: {module_spec}")
        if not file_path.exists() or not file_path.is_file():
            raise OverlayConfigError(f"函数模块文件不存在: {file_path}")
        return file_path

    @staticmethod
    def _load_module_from_file(module_file: Path):
        module_name = f"_sub_customizer_overlay_{abs(hash(str(module_file)))}"
        spec = importlib.util.spec_from_file_location(module_name, module_file)
        if spec is None or spec.loader is None:
            raise OverlayConfigError(f"无法加载函数模块: {module_file}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @classmethod
    def _load_overlay_from_function(
        cls,
        function_spec: str,
        clash_config: dict,
        function_dir: Optional[str] = None,
    ) -> dict:
        if ":" not in function_spec:
            raise OverlayConfigError("函数补丁配置格式错误，应为 func:module:function")

        module_spec, function_name = function_spec.rsplit(":", 1)
        module_spec = module_spec.strip()
        function_name = function_name.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", function_name):
            raise OverlayConfigError(
                f"函数名不合法: {function_name}，仅支持字母/数字/下划线"
            )

        try:
            resolved_dir = cls._resolve_overlay_function_dir(function_dir=function_dir)
            module_file = cls._resolve_module_file(
                module_spec, function_dir=resolved_dir
            )
            module = cls._load_module_from_file(module_file)
        except Exception as e:
            logger.exception(e)
            raise OverlayConfigError(f"导入函数模块失败: {module_spec}") from e

        func = getattr(module, function_name, None)
        if not callable(func):
            raise OverlayConfigError(f"函数不存在或不可调用: {function_spec}")

        try:
            signature = inspect.signature(func)
        except (TypeError, ValueError):
            signature = None

        try:
            if signature is None:
                result = func()
            else:
                positional_params = [
                    p
                    for p in signature.parameters.values()
                    if p.kind
                    in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                ]
                if len(positional_params) == 0:
                    result = func()
                elif len(positional_params) == 1:
                    # 允许函数根据当前配置动态生成补丁
                    result = func(clash_config)
                else:
                    raise OverlayConfigError(
                        f"补丁函数参数不受支持: {function_spec}，仅支持 0 或 1 个位置参数"
                    )
        except OverlayConfigError:
            raise
        except Exception as e:
            logger.exception(e)
            raise OverlayConfigError(f"执行补丁函数失败: {function_spec}") from e

        if result is None:
            return {}
        if isinstance(result, dict):
            return result
        if isinstance(result, bytes):
            return cls._load_yaml_text(result.decode("utf-8"))
        if isinstance(result, str):
            return cls._load_yaml_text(result)
        raise OverlayConfigError(
            f"补丁函数返回值不支持: {function_spec}，仅支持 dict/str/bytes/None"
        )

    @classmethod
    def load_overlay_config(
        cls,
        source: str,
        clash_config: dict,
        overlay_file_dir: Optional[str] = None,
        overlay_function_dir: Optional[str] = None,
    ) -> dict:
        if not source:
            return {}

        source = source.strip()
        if source.startswith("func:"):
            return cls._load_overlay_from_function(
                source[len("func:") :],
                clash_config=clash_config,
                function_dir=overlay_function_dir,
            )
        if is_url(source):
            return cls._load_overlay_from_url(source)
        return cls._load_overlay_from_file(source, overlay_file_dir=overlay_file_dir)

    @staticmethod
    def _validate_overlay_schema(overlay: dict):
        supported_keys = {
            "append_proxies",
            "append_proxy_groups",
            "inject_group_proxies",
            "prepend_rules",
        }
        unknown_keys = set(overlay) - supported_keys
        if unknown_keys:
            raise OverlayConfigError(
                f"补丁配置包含不支持的字段: {sorted(unknown_keys)}"
            )

        for key in {"append_proxies", "append_proxy_groups", "inject_group_proxies"}:
            value = overlay.get(key)
            if value is None:
                continue
            if not isinstance(value, list):
                raise OverlayConfigError(f"{key} 必须是列表")

        prepend_rules = overlay.get("prepend_rules")
        if prepend_rules is not None:
            if not isinstance(prepend_rules, list) or not all(
                isinstance(rule, str) for rule in prepend_rules
            ):
                raise OverlayConfigError("prepend_rules 必须是字符串列表")

    def _overlay_append_proxies(self, proxies_to_append: list[dict]):
        if not proxies_to_append:
            return
        proxies = self.config.setdefault("proxies", [])
        if not isinstance(proxies, list):
            raise OverlayConfigError("原始配置中的 proxies 不是列表")
        existing_names = {
            item.get("name")
            for item in proxies
            if isinstance(item, dict) and item.get("name")
        }
        for proxy in proxies_to_append:
            if not isinstance(proxy, dict):
                raise OverlayConfigError("append_proxies 中的每一项必须是字典")
            name = proxy.get("name")
            if not isinstance(name, str) or not name:
                raise OverlayConfigError("append_proxies 中的代理必须包含非空 name")
            if name in existing_names:
                continue
            proxies.append(proxy)
            existing_names.add(name)

    def _overlay_append_proxy_groups(self, groups_to_append: list[dict]):
        if not groups_to_append:
            return
        groups = self.config.setdefault("proxy-groups", [])
        if not isinstance(groups, list):
            raise OverlayConfigError("原始配置中的 proxy-groups 不是列表")
        existing_names = {
            item.get("name")
            for item in groups
            if isinstance(item, dict) and item.get("name")
        }
        for group in groups_to_append:
            if not isinstance(group, dict):
                raise OverlayConfigError("append_proxy_groups 中的每一项必须是字典")
            name = group.get("name")
            if not isinstance(name, str) or not name:
                raise OverlayConfigError(
                    "append_proxy_groups 中的分组必须包含非空 name"
                )
            if name in existing_names:
                continue
            groups.append(group)
            existing_names.add(name)

    def _overlay_inject_group_proxies(self, inject_specs: list[dict]):
        if not inject_specs:
            return
        groups = self.config.get("proxy-groups") or []
        if not isinstance(groups, list):
            raise OverlayConfigError("原始配置中的 proxy-groups 不是列表")
        group_map = {}
        for group in groups:
            if isinstance(group, dict) and group.get("name"):
                group_map[group["name"]] = group

        def resolve_anchor_index(
            anchor_value: str, current: list, field_name: str
        ) -> int:
            if anchor_value.startswith("re:"):
                pattern = anchor_value[3:]
                if not pattern:
                    raise OverlayConfigError(
                        f"inject_group_proxies[{group_name}] 的 {field_name} 正则不能为空"
                    )
                try:
                    regex = re.compile(pattern)
                except re.error as e:
                    raise OverlayConfigError(
                        f"inject_group_proxies[{group_name}] 的 {field_name} 正则错误: {pattern}"
                    ) from e
                for idx, proxy_name in enumerate(current):
                    if isinstance(proxy_name, str) and regex.search(proxy_name):
                        return idx
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 的 {field_name} 正则未匹配到节点: {pattern}"
                )
            try:
                return current.index(anchor_value)
            except ValueError as e:
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 的 {field_name} 目标不存在: {anchor_value}"
                ) from e

        for item in inject_specs:
            if not isinstance(item, dict):
                raise OverlayConfigError("inject_group_proxies 中的每一项必须是字典")
            supported_item_keys = {"group", "proxies", "position", "before", "after"}
            unknown_item_keys = set(item) - supported_item_keys
            if unknown_item_keys:
                raise OverlayConfigError(
                    f"inject_group_proxies 中存在不支持的字段: {sorted(unknown_item_keys)}"
                )
            group_name = item.get("group")
            proxies = item.get("proxies")
            if not isinstance(group_name, str) or not group_name:
                raise OverlayConfigError("inject_group_proxies 需要非空 group 字段")
            if not isinstance(proxies, list) or not all(
                isinstance(proxy_name, str) for proxy_name in proxies
            ):
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 的 proxies 必须是字符串列表"
                )
            position = item.get("position", "end")
            before = item.get("before")
            after = item.get("after")
            if position not in {"start", "end"}:
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 的 position 仅支持 start/end"
                )
            if before is not None and not isinstance(before, str):
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 的 before 必须是字符串"
                )
            if after is not None and not isinstance(after, str):
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 的 after 必须是字符串"
                )
            if before and after:
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 不能同时设置 before 和 after"
                )
            if (before or after) and "position" in item:
                raise OverlayConfigError(
                    f"inject_group_proxies[{group_name}] 设置 before/after 时不能同时设置 position"
                )

            group = group_map.get(group_name)
            if group is None:
                raise OverlayConfigError(f"目标分组不存在: {group_name}")
            current_proxies = group.setdefault("proxies", [])
            if not isinstance(current_proxies, list):
                raise OverlayConfigError(f"目标分组 proxies 不是列表: {group_name}")

            incoming = []
            for proxy_name in proxies:
                if proxy_name not in current_proxies and proxy_name not in incoming:
                    incoming.append(proxy_name)
            if not incoming:
                continue

            if before:
                idx = resolve_anchor_index(before, current_proxies, "before")
                current_proxies[idx:idx] = incoming
                continue

            if after:
                idx = resolve_anchor_index(after, current_proxies, "after")
                current_proxies[idx + 1 : idx + 1] = incoming
                continue

            if position == "start":
                current_proxies[0:0] = incoming
            else:
                current_proxies.extend(incoming)

    def _overlay_prepend_rules(self, prepend_rules: list[str]):
        if not prepend_rules:
            return
        rules = self.config.setdefault("rules", [])
        if not isinstance(rules, list):
            raise OverlayConfigError("原始配置中的 rules 不是列表")
        new_rules = []
        for rule in prepend_rules:
            if rule not in new_rules and rule not in rules:
                new_rules.append(rule)
        self.config["rules"] = new_rules + rules

    def apply_overlay_config(self, overlay: dict):
        if not overlay:
            return
        self._validate_overlay_schema(overlay)
        self._overlay_append_proxies(overlay.get("append_proxies") or [])
        self._overlay_append_proxy_groups(overlay.get("append_proxy_groups") or [])
        self._overlay_inject_group_proxies(overlay.get("inject_group_proxies") or [])
        self._overlay_prepend_rules(overlay.get("prepend_rules") or [])

    def write_remote_config(
        self,
        remote_url=None,
        overlay_config: Optional[str] = None,
        overlay_file_dir: Optional[str] = None,
        overlay_function_dir: Optional[str] = None,
    ) -> bytes:
        if remote_url:
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

        if overlay_config:
            overlay = self.load_overlay_config(
                overlay_config,
                clash_config=self.config,
                overlay_file_dir=overlay_file_dir,
                overlay_function_dir=overlay_function_dir,
            )
            self.apply_overlay_config(overlay)
        return self.dump()

    def dump(self) -> bytes:
        return yaml.dump(
            self.config,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            encoding="utf-8",
        )
