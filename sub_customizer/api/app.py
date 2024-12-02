from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sub_customizer.api.endpoints import customizer
from sub_customizer.config import api_settings

app = FastAPI(title="Clash Subscription Customizer API", openapi_url=None)
if api_settings.debug:
    app = FastAPI(title="Clash Subscription Customizer API")

if api_settings.cors_all:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(customizer.router, prefix="/customizer", tags=["customizer"])


@app.get("/")
def index():
    return {"message": "Hello world."}
