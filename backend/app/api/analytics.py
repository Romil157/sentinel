from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from app import db
from app.models.prediction import Prediction

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route('/analytics/summary', methods=['GET'])
@jwt_required()
def get_analytics_summary():
    # Placeholder for real analytics aggregation
    # In a real scenario, we'd query the DB with group_by and count
    return jsonify({
        "total_scanned": 1250,
        "threats_detected": 342,
        "safe_items": 908,
        "accuracy_rate": 94.2,
        "recent_threats": [
            {"type": "url", "threat": "Phishing", "date": "2024-05-12T10:30:00Z"},
            {"type": "text", "threat": "Scam", "date": "2024-05-12T11:15:00Z"}
        ]
    }), 200

@analytics_bp.route('/history', methods=['GET'])
@jwt_required()
def get_prediction_history():
    # Placeholder for user history
    return jsonify({
        "history": [
            {
                "id": 1,
                "input_type": "text",
                "input_data": "Urgent: Your account has been suspended. Click here to verify.",
                "prediction": "Phishing",
                "confidence": 0.98,
                "created_at": "2024-05-12T10:30:00Z"
            }
        ]
    }), 200
