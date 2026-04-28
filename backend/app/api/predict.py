import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.prediction import Prediction
from app import limiter
from app.preprocessing.text_processor import text_processor
from app.preprocessing.url_processor import url_processor

predict_bp = Blueprint('predict', __name__)

def calculate_severity(confidence):
    if confidence < 0.2:
        return "Safe"
    elif confidence < 0.4:
        return "Low Risk"
    elif confidence < 0.6:
        return "Suspicious"
    elif confidence < 0.8:
        return "High Risk"
    else:
        return "Critical Threat"

def save_prediction(input_data, input_type, confidence, explain_dict, severity):
    # Retrieve our dummy admin user (or fallback to anonymous/None)
    from app.models.user import User
    user = User.query.filter_by(email='admin@sentinel.com').first()
    
    import json
    p = Prediction(
        user_id=user.id if user else None,
        input_data=input_data,
        input_type=input_type,
        prediction_result='Phishing' if confidence > 0.5 else 'Safe',
        severity_level=severity,
        confidence_score=confidence,
        explainability_json=json.dumps(explain_dict)
    )
    db.session.add(p)
    db.session.commit()

@predict_bp.route('/text', methods=['POST'])
@limiter.limit("10 per minute")
def predict_text():
    data = request.get_json()
    if not data or not data.get('text'):
        return jsonify({"error": "Missing text data"}), 400
        
    text = data.get('text')
    
    confidence, explain_dict = text_processor.predict(text)
    severity = calculate_severity(confidence)
    
    save_prediction(text, 'text', confidence, explain_dict, severity)
    
    return jsonify({
        "input_type": "text",
        "severity_level": severity,
        "confidence_score": confidence,
        "indicators": explain_dict.get("flags", []),
        "explainability": explain_dict
    }), 200

@predict_bp.route('/url', methods=['POST'])
@limiter.limit("10 per minute")
def predict_url():
    data = request.get_json()
    if not data or not data.get('url'):
        return jsonify({"error": "Missing url data"}), 400
        
    url = data.get('url')
    confidence, explain_dict = url_processor.analyze_url(url)
    severity = calculate_severity(confidence)
    
    save_prediction(url, 'url', confidence, explain_dict, severity)
    
    return jsonify({
        "input_type": "url",
        "severity_level": severity,
        "confidence_score": confidence,
        "indicators": explain_dict.get("flags", []),
        "explainability": explain_dict
    }), 200

