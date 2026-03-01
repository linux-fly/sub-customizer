# AGENTS 指南（sub-customizer）

## 1. 项目定位

`sub-customizer` 是一个 Clash 订阅定制工具，核心目标是：

- 读取原始 Clash 订阅（YAML）
- 读取远程配置（INI 风格，兼容 subconverter 的部分字段）
- 生成定制后的 Clash 配置（支持规则、代理组、基础配置覆盖）
- 通过 CLI/HTTP API 提供服务

## 2. 技术栈与运行环境

- 语言：Python（`>=3.9`）
- 打包：`setuptools`（`pyproject.toml`）
- 核心依赖：`requests`、`pydantic`、`pydantic-settings`、`pyyaml`
- 可选 API 依赖：`fastapi`、`jinja2`、`uvicorn`
- 代码质量工具：`ruff`、`pytest`、`tox`、`pre-commit`
- 本地执行约定：**优先使用项目虚拟环境**，例如 `.venv/bin/python`、`.venv/bin/pip`

## 3. 目录结构（关键路径）

- `src/sub_customizer/customizer.py`：核心订阅定制逻辑
- `src/sub_customizer/datastructures.py`：Clash 配置数据模型（Pydantic）
- `src/sub_customizer/__main__.py`：CLI 入口（`sub-customizer serve`）
- `src/sub_customizer/api/`：FastAPI 服务、配置、模板与路由
- `tests/`：单元测试
- `scripts/start_api.sh`：本地快速启动 API 脚本
- `README.md`：用户使用说明

## 4. 常用命令

```bash
# 创建虚拟环境（如不存在）
python -m venv .venv

# 安装开发依赖
.venv/bin/pip install -r requirements_dev.txt

# 安装 API 依赖（按需）
.venv/bin/pip install -r requirements_api.txt

# 运行测试
.venv/bin/pytest -vv tests/

# 使用 tox 跑测试环境
.venv/bin/tox

# 代码检查/格式化
.venv/bin/ruff check src tests
.venv/bin/ruff format src tests

# 启动 HTTP 服务（CLI）
.venv/bin/python -m sub_customizer serve
.venv/bin/python -m sub_customizer serve --host 0.0.0.0 --port 57890

# 启动 API（脚本）
sh scripts/start_api.sh
```

## 5. 核心逻辑说明（修改前必读）

1. 入口流程：
- `ClashSubCustomizer.from_url()` 拉取订阅并解析 YAML
- `write_remote_config()` 读取远程配置并合并：
  - 代理组：`custom_proxy_group`
  - 规则：`ruleset` + `enable_rule_generator` + `overwrite_original_rules`
  - 覆盖项：`port`、`mode`、`dns` 等（通过 `ClashConfig` 校验）

2. 远程配置解析：
- `RemoteConfigParser.supported_options`/`supported_override_options` 控制可识别字段
- `RulesetParser` 处理规则源（URL 或 `[]` 直接规则）
- `CustomProxyGroupParser` 处理自定义代理组表达式

3. API 入口：
- `GET /customizer/sub_custom`：返回定制后的订阅文本
- `GET /customizer/sub_customizer`：返回 Web 面板

## 6. 代码改动约束

- 如新增可覆盖配置项，必须同时更新：
  - `RemoteConfigParser.supported_override_options`
  - `datastructures.ClashConfig` 对应字段
  - 至少一个测试用例（`tests/`）
  - 必要时补充 `README.md`
- 保持 YAML 输出行为一致（`allow_unicode=True`、`sort_keys=False`）
- 现有 API 查询参数（`url`、`remote_config`、`no_proxy`）避免破坏兼容
- 优先做最小改动，不要重写核心解析流程

## 7. 测试与提交前检查清单

- 使用 `.venv/bin/python` 及 `.venv/bin/*` 工具链执行命令，避免污染系统环境
- 运行 `.venv/bin/pytest -vv tests/` 并通过
- 运行 `.venv/bin/ruff check src tests` 并通过
- 若格式有变动，执行 `.venv/bin/ruff format src tests`
- 若改动涉及 API，至少手动验证：
  - `/customizer/sub_custom` 能返回文本
  - `/customizer/sub_customizer` 页面可打开

## 8. 与用户协作要求
- 若无特别说明，默认使用简体中文沟通。
- 回复结构默认为：
  - 做了什么
  - 结果如何
  - 哪些未执行及原因
  - 可选下一步
