"""Vercel serverless entry point for the FastAPI backend."""

from mangum import Mangum
from main import app

handler = Mangum(app, lifespan="off")
