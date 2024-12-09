# Clash订阅定制器/Clash Subscription Customizer

![screenshot.jpg](https://raw.githubusercontent.com/linux-fly/sub-customizer/refs/heads/main/docs/static/screenshot.jpg)

## 支持的功能

- 自定义所有Clash配置项：

  port, socks-port, redir-port, tproxy-port, mixed-port, allow-lan, bind-address, mode, log-level, ipv6, external-controller, external-ui, secret, interface-name, routing-mark, hosts, profile, dns等

- 支持远程配置，兼容subconverter远程配置中的`ruleset`, `custom_proxy_group`, `enable_rule_generator`和`overwrite_original_rules`



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

*subconverter*提供了很多功能，主要包括订阅转换，自定义规则等等。但是对于我或者很多人来说并不需要那些，我所需要的仅仅是能够**对多个机场订阅更新时自动应用使同一套代理规则**（如对oaifree和linuxdo使用直连），并且**简单易配置**。

除了兼容subconverter远程配置中的`ruleset`, `custom_proxy_group`, `enable_rule_generator`和`overwrite_original_rules`之外，其他项直接读取并覆盖原订阅配置文件。
