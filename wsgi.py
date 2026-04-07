"""
WSGI entry point for Vercel deployment
"""
import os
import sys

# Add the app directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

# Export the app for Vercel
if __name__ == "__main__":
    app.run()
