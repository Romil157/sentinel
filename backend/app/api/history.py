from flask import Blueprint, jsonify, request
from app.models.prediction import Prediction
from app import db
import json

history_bp = Blueprint('history', __name__)

@history_bp.route('/', methods=['GET'])
def get_history():
    # In a real app with auth, filter by user.id
    # We will just return the most recent predictions globally for the demo.
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    pagination = Prediction.query.order_by(Prediction.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    items = []
    for item in pagination.items:
        data = item.to_dict()
        try:
            data['explainability'] = json.loads(data['explainability_json']) if data['explainability_json'] else {}
        except:
            data['explainability'] = {}
        items.append(data)
        
    return jsonify({
        "items": items,
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": page
    }), 200

@history_bp.route('/<int:id>', methods=['DELETE'])
def delete_history(id):
    prediction = Prediction.query.get(id)
    if not prediction:
        return jsonify({"error": "Not found"}), 404
        
    db.session.delete(prediction)
    db.session.commit()
    return jsonify({"message": "Deleted successfully"}), 200
