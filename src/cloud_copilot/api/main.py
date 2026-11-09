"""ASGI entrypoint: ``uvicorn cloud_copilot.api.main:app``."""

from cloud_copilot.api.app import create_app

app = create_app()
