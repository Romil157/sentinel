from flask import Blueprint, jsonify
from app import db

health_bp = Blueprint('health', __name__)

@health_bp.route('/health', methods=['GET'])
def health_check():
    # Check DB connection
    db_status = "ok"
    try:
        db.session.execute('SELECT 1')
    except Exception as e:
        db_status = "error"

    return jsonify({
        "status": "ok",
        "service": "Sentinel Verify API",
        "database": db_status
    }), 200
