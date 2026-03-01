# Clash订阅定制器/Clash Subscription Customizer

![screenshot.jpg](https://raw.githubusercontent.com/linux-fly/sub-customizer/refs/heads/main/docs/static/screenshot.jpg)

## 支持的功能

- 自定义所有Clash配置项：

  port, socks-port, redir-port, tproxy-port, mixed-port, allow-lan, bind-address, mode, log-level, ipv6,
  unified-delay, tcp-concurrent, find-process-mode, global-client-fingerprint, keep-alive-idle,
  keep-alive-interval, external-controller, external-ui, secret, interface-name, routing-mark, hosts,
  profile, geodata-mode, geodata-loader, geosite-matcher, geox-url, dns, sniffer, tun, ntp等

- 支持远程配置，兼容subconverter远程配置中的`ruleset`, `custom_proxy_group`, `enable_rule_generator`和
  `overwrite_original_rules`
- 远程配置中的结构化覆盖项（如 `hosts`、`profile`、`dns`、`geox-url`、`sniffer`、`tun`、`ntp`）支持 JSON/YAML 字典字符串

## 使用

#### 通过pip安装

```sh
pip install -U sub-customizer
# 或者同时安装API依赖
pip install -U sub-customizer[api]
```

#### 启动http服务

```
sub-customizer serve  # 默认127.0.0.1:57890
sub-customizer serve --host 0.0.0.0 --port 5789  # 自定义地址和端口
```

#### 使用 overlay 补丁配置（文件 / URL / 函数）

`/customizer/sub_custom` 支持通过 query 参数 `overlay_config` 注入补丁配置。接口返回定制后的订阅内容，并透传原始订阅中的 Clash 常用响应头（如 `subscription-userinfo`）。

示例：

```text
/customizer/sub_custom?url=<订阅URL>&remote_config=<远程配置URL>&overlay_config=overlay.yaml&token=<管理员token>
```

`overlay_config` 支持三种来源：

- 文件：`overlay_config=overlay.yaml`（相对于补丁文件目录）
  - 目录环境变量：`OVERLAY_FILE_DIR`（默认 `overlay_configs`）
  - Python 调用可用：`write_remote_config(..., overlay_file_dir="...")` 或 `SUB_CUSTOMIZER_OVERLAY_FILE_DIR`
  - 目录不存在时自动创建，且目录需位于当前运行目录下
- URL：`overlay_config=https://example.com/overlay.yaml`
- 函数：`overlay_config=func:my_overlay_provider:get_overlay`
  - 目录环境变量：`OVERLAY_FUNCTION_DIR`（默认 `overlay_providers`）
  - Python 调用可用：`write_remote_config(..., overlay_function_dir="...")` 或 `SUB_CUSTOMIZER_OVERLAY_FUNCTION_DIR`
  - 目录不存在时自动创建，且目录需位于当前运行目录下
  - 函数签名支持 `def get_overlay()` 或 `def get_overlay(current_config)`
  - 返回值支持 `dict` / YAML 字符串 / YAML 字节串

访问控制：

- 匿名请求：可使用 URL 类型 `overlay_config`
- 管理员请求：携带 `?token=<token>` 且匹配 `ADMIN_TOKEN` 时，可使用文件/函数类型 `overlay_config`
- 配置或校验失败时，API 返回 `422`

URL 安全策略（对 `url`、`remote_config`、`overlay_config` 中的 URL 生效）：

- `URL_BLOCK_PRIVATE_NETWORK`：是否禁止内网/保留地址（默认 `true`）
- `URL_RESOLVE_HOST_IPS`：是否先解析域名再按解析结果做 IP 级校验（默认 `false`）
- `URL_ALLOWLIST`：URL 主机白名单（逗号分隔，可选）
- `URL_BLOCKLIST`：URL 主机黑名单（逗号分隔，可选）

overlay 配置示例：

```yaml
append_proxies:
  - name: "🇺🇸 Webshare-纽约"
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
      - "🇺🇸 Webshare-纽约"
inject_group_proxies:
  - group: "Proxies"
    proxies: ["Webshare"]
  - group: "Google"
    proxies: ["Webshare"]
prepend_rules:
  - "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
```

`inject_group_proxies` 支持可选定位字段：

- `position`: `start` 或 `end`（默认 `end`）
- `before`: 插入到某个现有节点前
- `after`: 插入到某个现有节点后
- `before`/`after` 支持正则：使用 `re:` 前缀，如 `before: "re:^US"`

示例（插到组头部）：

```yaml
inject_group_proxies:
  - group: "Google"
    position: "start"
    proxies: ["Webshare"]
```

示例（插到 `US` 后面）：

```yaml
inject_group_proxies:
  - group: "Proxies"
    after: "US"
    proxies: ["Webshare"]
```

#### docker

dockerfile在[docker](https://github.com/linux-fly/sub-customizer/tree/main/docker)目录下，内容如下：

```dockerfile
FROM python:3.12-slim

RUN apt-get update
RUN pip config set global.index-url https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple && \
    pip install -U sub-customizer[api]

WORKDIR /opt/sub-customizer

CMD ["sub-customizer", "serve", "--host", "0.0.0.0", "--port", "57890"]
```

```
# build镜像
docker build -t sub-customizer:latest -f Dockerfile .

# 运行
docker run --name sub-customizer -d -p 57890:57890 sub-customizer:latest
```

打开http://127.0.0.1:57890/customizer/sub_customizer 使用即可。

## TODO

- [ ] 支持聚合多个订阅中的节点

## 为什么不使用subconverter

*subconverter* 提供了很多功能，主要包括订阅转换、自定义规则等等。但是对于我或者很多人来说并不需要那些，我所需要的仅仅是能够**对多个机场订阅更新时自动应用同一套代理规则**（如对 oaifree 和 linuxdo 使用直连），并且**简单易配置**。

除了兼容subconverter远程配置中的`ruleset`, `custom_proxy_group`, `enable_rule_generator`和`overwrite_original_rules`
之外，其他项直接读取并覆盖原订阅配置文件。
