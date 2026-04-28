from flask import Blueprint, jsonify
from app.models.prediction import Prediction
from app import db
import datetime
from sqlalchemy import func

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route('/overview', methods=['GET'])
def get_overview():
    total_scans = Prediction.query.count()
    threats_detected = Prediction.query.filter(Prediction.severity_level.in_(['Suspicious', 'High Risk', 'Critical Threat'])).count()
    
    accuracy_rate = 94.2 # Demo baseline
    
    return jsonify({
        "total_scanned": total_scans,
        "threats_detected": threats_detected,
        "accuracy_rate": accuracy_rate
    }), 200

@analytics_bp.route('/trends', methods=['GET'])
def get_trends():
    # Return mock last 7 days of scan data for chart.js
    import random
    
    labels = []
    data_safe = []
    data_threats = []
    
    for i in range(6, -1, -1):
        d = datetime.datetime.utcnow() - datetime.timedelta(days=i)
        labels.append(d.strftime("%a"))
        data_safe.append(random.randint(10, 50))
        data_threats.append(random.randint(2, 15))
        
    return jsonify({
        "labels": labels,
        "datasets": [
            {"label": "Safe Scans", "data": data_safe},
            {"label": "Threats Blocked", "data": data_threats}
        ]
    }), 200
