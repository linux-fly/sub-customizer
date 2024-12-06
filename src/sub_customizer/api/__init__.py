try:
    import fastapi
    import uvicorn
    import jinja2
except ModuleNotFoundError as e:
    raise ModuleNotFoundError("使用`pip install sub-customizer[api]`安装所需的软件包")
