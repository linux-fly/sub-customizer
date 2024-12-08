from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sub_customizer.api.config import settings
from sub_customizer.api.endpoints import customizer

app = FastAPI(title="Clash Subscription Customizer API", openapi_url=None)
if settings.debug:
    app = FastAPI(title="Clash Subscription Customizer API")

if settings.cors_all:
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


def serve(host, port):
    import uvicorn

    uvicorn.run(app, host=host, port=port)
