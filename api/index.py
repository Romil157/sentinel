import os
import sys

# Ensure backend directory is in sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend'))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Set serverless database fallback to /tmp if not explicitly set
if not os.environ.get('DATABASE_URL'):
    os.environ['DATABASE_URL'] = 'sqlite:////tmp/sentinel.db'

from app import create_app, db

# Determine environment
env = os.environ.get('FLASK_ENV', 'prod')
app = create_app(env if env in ['dev', 'prod'] else 'prod')

# Ensure database tables exist in serverless environment
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        app.logger.warning(f"Auto db create_all warning: {e}")

# Vercel looks for the WSGI app instance
handler = app
