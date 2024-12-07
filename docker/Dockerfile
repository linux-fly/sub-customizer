FROM python:3.12-slim

RUN apt-get update
RUN pip config set global.index-url https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple && \
    pip install -U sub-customizer[api]

WORKDIR /opt/sub-customizer
