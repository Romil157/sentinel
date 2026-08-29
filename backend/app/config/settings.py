import os
from datetime import timedelta

def get_database_uri():
    db_url = os.environ.get('DATABASE_URL')
    if db_url:
        # SQLAlchemy 1.4+ / 2.0+ requires postgresql:// instead of postgres://
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        return db_url
    
    # In serverless environments, use /tmp/sentinel.db if /var/task is read-only
    if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
        return 'sqlite:////tmp/sentinel.db'
        
    return 'sqlite:///sentinel.db'

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-sentinel-fallback-key'
    SQLALCHEMY_DATABASE_URI = get_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-super-secret-sentinel-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    
    # Rate Limiting
    RATELIMIT_DEFAULT = "500 per day;100 per hour"
    RATELIMIT_STORAGE_URI = "memory://"
    
    # CORS
    CORS_HEADERS = 'Content-Type'

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    DEBUG = True

config_by_name = dict(
    dev=DevelopmentConfig,
    prod=ProductionConfig,
    test=TestingConfig
)

key = Config.SECRET_KEY
