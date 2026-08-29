import os
import logging
import warnings
from flask import Flask, jsonify

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*unpickle estimator.*")

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config.settings import config_by_name

logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
jwt = JWTManager()
cors = CORS()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

def create_app(config_name='dev'):
    app = Flask(__name__)
    cfg = config_by_name.get(config_name, config_by_name['dev'])
    app.config.from_object(cfg)

    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": "*"}})
    limiter.init_app(app)

    # Global Error Handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad request", "details": str(error)}), 400

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({"error": "Rate limit exceeded. Please try again in a moment."}), 429

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error"}), 500

    # Register Blueprints
    from app.api.health import health_bp
    from app.api.auth import auth_bp
    from app.api.predict import predict_bp
    from app.api.history import history_bp
    from app.api.feed import feed_bp
    from app.api.analytics import analytics_bp
    from app.api.apikeys import apikeys_bp
    from app.api.settings import settings_bp

    app.register_blueprint(health_bp, url_prefix='/api/v1/health')
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(predict_bp, url_prefix='/api/v1/predict')
    app.register_blueprint(history_bp, url_prefix='/api/v1/history')
    app.register_blueprint(feed_bp, url_prefix='/api/v1/feed')
    app.register_blueprint(analytics_bp, url_prefix='/api/v1/analytics')
    app.register_blueprint(apikeys_bp, url_prefix='/api/v1/apikeys')
    app.register_blueprint(settings_bp, url_prefix='/api/v1/settings')

    # Auto-initialize database tables and default admin if not existing
    with app.app_context():
        try:
            db.create_all()
            from app.models.user import User
            if not User.query.filter_by(email='admin@sentinel.com').first():
                admin = User(email='admin@sentinel.com', username='admin', password='password123', role='admin')
                db.session.add(admin)
                db.session.commit()
        except Exception as e:
            logger.warning(f"Database auto-initialization notice: {e}")

    return app
