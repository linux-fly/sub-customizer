FROM python:3.12-slim

RUN pip config set global.index-url https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple && \
    pip install -U sub-customizer[api]

WORKDIR /opt/sub-customizer

CMD ["sub-customizer", "serve", "--host", "0.0.0.0", "--port", "57890"]
