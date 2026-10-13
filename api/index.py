"""
Vercel Serverless Function entry point.
Exposes the Flask WSGI `app` object to Vercel's Python runtime.

File layout on Vercel:
  /var/task/
    api/index.py          <- this file
    web_app.py
    config.py
    core/
    database/
    reports/
    templates/
    .fim_vault/
    fim_database.sqlite3
"""
import sys
import os
from pathlib import Path

# Make root project directory importable from api/index.py
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Vercel sets VERCEL=1 automatically; config.py reads this to enable /tmp paths
# (already handled in config.py IS_SERVERLESS check)

from web_app import app  # noqa: E402  — must come after sys.path setup

# Vercel looks for a module-level `app` WSGI callable
__all__ = ["app"]
