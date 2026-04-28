import json
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.prediction import Prediction
from app import limiter
from app.preprocessing.text_processor import text_processor
from app.preprocessing.url_processor import url_processor

predict_bp = Blueprint('predict', __name__)

@predict_bp.route('/text', methods=['POST'])
@limiter.limit("10 per minute")
def predict_text():
    data = request.get_json()
    if not data or not data.get('text'):
        return jsonify({"error": "Missing text data"}), 400
        
    text = data.get('text')
    
    # Run prediction
    result, confidence, explain_dict = text_processor.predict(text)
    
    # Save to database if needed (optional implementation)
    
    return jsonify({
        "input_type": "text",
        "prediction": result,
        "confidence": confidence,
        "explainability": explain_dict
    }), 200

@predict_bp.route('/url', methods=['POST'])
@limiter.limit("10 per minute")
def predict_url():
    data = request.get_json()
    if not data or not data.get('url'):
        return jsonify({"error": "Missing url data"}), 400
        
    url = data.get('url')
    result, confidence, explain_dict = url_processor.analyze_url(url)
    
    return jsonify({
        "input_type": "url",
        "prediction": result,
        "confidence": confidence,
        "explainability": explain_dict
    }), 200

