"""
Vercel Serverless Function entry point.
Exposes the Flask WSGI application instance `app` to Vercel's Python runtime.
"""
import sys
from pathlib import Path

# Ensure the root project directory is in the Python module search path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Import the existing Flask app from web_app
from web_app import app

# For local invocation / testing
if __name__ == "__main__":
    app.run(debug=True)
