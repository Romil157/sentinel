from flask import Blueprint, jsonify, request
from app.models.user import User
from app import db

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/profile', methods=['GET'])
def get_profile():
    user = User.query.filter_by(email='admin@sentinel.com').first()
    return jsonify(user.to_dict()), 200

@settings_bp.route('/profile', methods=['PUT'])
def update_profile():
    data = request.get_json()
    user = User.query.filter_by(email='admin@sentinel.com').first()
    
    if 'username' in data:
        user.username = data['username']
    if 'theme_preference' in data:
        user.theme_preference = data['theme_preference']
    if 'notifications_enabled' in data:
        user.notifications_enabled = data['notifications_enabled']
        
    db.session.commit()
    return jsonify({"message": "Settings updated successfully", "user": user.to_dict()}), 200
