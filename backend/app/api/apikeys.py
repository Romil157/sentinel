from flask import Blueprint, jsonify, request
from app.models.apikey import APIKey
from app.models.user import User
from app import db, bcrypt
import secrets

apikeys_bp = Blueprint('apikeys', __name__)

@apikeys_bp.route('/', methods=['GET'])
def get_keys():
    # Fallback to admin user for demo
    user = User.query.filter_by(email='admin@sentinel.com').first()
    keys = APIKey.query.filter_by(user_id=user.id).all()
    return jsonify([k.to_dict() for k in keys]), 200

@apikeys_bp.route('/', methods=['POST'])
def create_key():
    data = request.get_json() or {}
    name = data.get('name', 'New API Key')
    
    user = User.query.filter_by(email='admin@sentinel.com').first()
    
    # Generate secure key
    raw_key = "sv_" + secrets.token_urlsafe(32)
    prefix = raw_key[:12] + "..."
    key_hash = bcrypt.generate_password_hash(raw_key).decode('utf-8')
    
    new_key = APIKey(
        user_id=user.id,
        name=name,
        key_hash=key_hash,
        prefix=prefix
    )
    db.session.add(new_key)
    db.session.commit()
    
    # Only time we ever return the raw key!
    return jsonify({
        "message": "Key created successfully",
        "raw_key": raw_key,
        "key_details": new_key.to_dict()
    }), 201

@apikeys_bp.route('/<int:id>', methods=['DELETE'])
def revoke_key(id):
    key = APIKey.query.get(id)
    if not key:
        return jsonify({"error": "Key not found"}), 404
        
    db.session.delete(key)
    db.session.commit()
    return jsonify({"message": "Key revoked successfully"}), 200
