from flask import Blueprint, jsonify
from app import db
from sqlalchemy import text
import datetime

health_bp = Blueprint('health', __name__)
START_TIME = datetime.datetime.now(datetime.timezone.utc)

@health_bp.route('/', methods=['GET'])
@health_bp.route('/health', methods=['GET'])
def health_check():
    db_status = "connected"
    try:
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        db_status = f"unavailable ({str(e)[:40]})"

    uptime_seconds = int((datetime.datetime.now(datetime.timezone.utc) - START_TIME).total_seconds())

    return jsonify({
        "status": "healthy",
        "service": "Sentinel Verify Intelligence Engine",
        "version": "2.0.0",
        "database": db_status,
        "uptime_seconds": uptime_seconds,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }), 200
