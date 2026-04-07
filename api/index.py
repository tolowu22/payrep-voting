import sys
import os

# Add parent directory to path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# For Vercel serverless functions
def handler(request):
    return app(request.environ, request.start_response)

# Also export app directly for WSGI compatibility
__all__ = ['app', 'handler']
