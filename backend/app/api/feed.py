from flask import Blueprint, jsonify
from app.models.feed import ThreatFeed

feed_bp = Blueprint('feed', __name__)

@feed_bp.route('/', methods=['GET'])
def get_feed():
    feeds = ThreatFeed.query.order_by(ThreatFeed.timestamp.desc()).limit(20).all()
    return jsonify([f.to_dict() for f in feeds]), 200
