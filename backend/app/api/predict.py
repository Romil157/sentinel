import json
import logging
import datetime
from flask import Blueprint, request, jsonify
from app import db, bcrypt
from app.models.prediction import Prediction
from app.models.apikey import APIKey
from app import limiter
from app.preprocessing.text_processor import text_processor
from app.preprocessing.url_processor import url_processor

logger = logging.getLogger(__name__)
predict_bp = Blueprint('predict', __name__)

def verify_and_track_api_key():
    auth_header = request.headers.get('X-API-Key') or request.headers.get('Authorization')
    if not auth_header:
        return None
        
    raw_key = auth_header.replace('Bearer ', '').strip()
    if not raw_key.startswith('sv_'):
        return None
        
    try:
        keys = APIKey.query.filter_by(is_active=True).all()
        for k in keys:
            if bcrypt.check_password_hash(k.key_hash, raw_key):
                k.request_count += 1
                k.last_used_at = datetime.datetime.now(datetime.timezone.utc)
                db.session.commit()
                return k
    except Exception as e:
        logger.warning(f"API key tracking skipped: {e}")
    return None

def calculate_severity(confidence):
    if confidence < 0.20:
        return "Safe"
    elif confidence < 0.40:
        return "Low Risk"
    elif confidence < 0.60:
        return "Suspicious"
    elif confidence < 0.80:
        return "High Risk"
    else:
        return "Critical Threat"

def save_prediction(input_data, input_type, confidence, explain_dict, severity):
    try:
        from app.models.user import User
        user = User.query.filter_by(email='admin@sentinel.com').first()
        
        p = Prediction(
            user_id=user.id if user else None,
            input_data=input_data[:2000] if input_data else "",
            input_type=input_type,
            prediction_result='Phishing' if confidence > 0.50 else 'Safe',
            severity_level=severity,
            confidence_score=confidence,
            explainability_json=json.dumps(explain_dict)
        )
        db.session.add(p)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.warning(f"Prediction persistence skipped: {e}")

@predict_bp.route('/text', methods=['POST'])
@limiter.limit("120 per minute")
def predict_text():
    verify_and_track_api_key()
    data = request.get_json(silent=True)
    if not data or not data.get('text'):
        return jsonify({"error": "Missing 'text' in request body"}), 400
        
    text = str(data.get('text')).strip()
    if not text:
        return jsonify({"error": "Text content cannot be empty"}), 400
    
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
@limiter.limit("120 per minute")
def predict_url():
    verify_and_track_api_key()
    data = request.get_json(silent=True)
    if not data or not data.get('url'):
        return jsonify({"error": "Missing 'url' in request body"}), 400
        
    url = str(data.get('url')).strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400
        
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

@predict_bp.route('/batch', methods=['POST'])
@limiter.limit("30 per minute")
def predict_batch():
    verify_and_track_api_key()
    data = request.get_json(silent=True)
    if not data or 'items' not in data:
        return jsonify({"error": "Missing 'items' array in request body"}), 400
        
    items = data.get('items')
    if not isinstance(items, list):
        return jsonify({"error": "'items' must be a list"}), 400
        
    if len(items) > 50:
        return jsonify({"error": "Maximum 50 items per batch request"}), 400

    results = []
    threat_count = 0
    start_time = datetime.datetime.now(datetime.timezone.utc)

    for item in items:
        if isinstance(item, str):
            input_type = 'url' if item.startswith(('http://', 'https://', 'www.')) else 'text'
            content = item.strip()
        elif isinstance(item, dict):
            input_type = item.get('type', 'text').lower()
            content = str(item.get('content', '')).strip()
        else:
            continue

        if not content:
            continue

        if input_type == 'url':
            confidence, explain_dict = url_processor.analyze_url(content)
        else:
            confidence, explain_dict = text_processor.predict(content)

        severity = calculate_severity(confidence)
        if severity in ['Suspicious', 'High Risk', 'Critical Threat']:
            threat_count += 1

        results.append({
            "input_snippet": content[:80] + ("..." if len(content) > 80 else ""),
            "input_type": input_type,
            "severity_level": severity,
            "confidence_score": confidence,
            "indicators": explain_dict.get("flags", [])
        })

    duration_ms = int((datetime.datetime.now(datetime.timezone.utc) - start_time).total_seconds() * 1000)

    return jsonify({
        "total_processed": len(results),
        "threats_detected": threat_count,
        "processing_time_ms": duration_ms,
        "results": results
    }), 200
