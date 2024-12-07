# flake8: noqa: F401
try:
    import fastapi
    import jinja2
    import uvicorn
except ModuleNotFoundError as e:
    raise ModuleNotFoundError(
        "Use `pip install sub-customizer[api]` to install the required packages."
    ) from e
