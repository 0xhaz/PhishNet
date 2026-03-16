"""Vercel serverless entry point — auto-discovered as api/index."""

import sys
from pathlib import Path

# Ensure the backend root is on sys.path so `main`, `database`, etc. are importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import app  # noqa: E402, F401
