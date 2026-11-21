"""Vercel Python runtime entrypoint for the SecureSign FastAPI application."""
from backend.app.main import app

__all__ = ["app"]
