"""Vercel serverless entry point for the FastAPI backend."""

from main import app  # noqa: F401 — Vercel discovers the ASGI app via this export

handler = app
