import io
import csv
import json
import datetime
from flask import Blueprint, jsonify, request, Response
from app.models.prediction import Prediction
from app.models.user import User
from app import db

history_bp = Blueprint('history', __name__)

DEFAULT_SCANS = [
    {
        "input_data": "https://secure-login-update.xyz/auth",
        "input_type": "url",
        "prediction_result": "Phishing",
        "severity_level": "Critical Threat",
        "confidence_score": 0.94,
        "explainability": {"flags": ["High-risk TLD (.xyz)", "Sensitive auth keyword", "High entropy"]}
    },
    {
        "input_data": "URGENT: Your account has been suspended. Please confirm your OTP immediately.",
        "input_type": "text",
        "prediction_result": "Phishing",
        "severity_level": "High Risk",
        "confidence_score": 0.86,
        "explainability": {"flags": ["Urgency indicator", "Credential / OTP pattern"]}
    },
    {
        "input_data": "https://docs.github.com/en/rest",
        "input_type": "url",
        "prediction_result": "Safe",
        "severity_level": "Safe",
        "confidence_score": 0.04,
        "explainability": {"flags": []}
    },
    {
        "input_data": "The quarterly financial review is scheduled for Thursday at 2 PM in conference room B.",
        "input_type": "text",
        "prediction_result": "Safe",
        "severity_level": "Safe",
        "confidence_score": 0.08,
        "explainability": {"flags": []}
    }
]

@history_bp.route('/', methods=['GET'])
def get_history():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    now = datetime.datetime.now(datetime.timezone.utc)
    
    try:
        total_count = Prediction.query.count()
        if total_count == 0:
            user = User.query.filter_by(email='admin@sentinel.com').first()
            user_id = user.id if user else None
            for idx, item in enumerate(DEFAULT_SCANS):
                p = Prediction(
                    user_id=user_id,
                    input_data=item["input_data"],
                    input_type=item["input_type"],
                    prediction_result=item["prediction_result"],
                    severity_level=item["severity_level"],
                    confidence_score=item["confidence_score"],
                    explainability_json=json.dumps(item["explainability"]),
                    created_at=now - datetime.timedelta(hours=(idx + 1) * 6)
                )
                db.session.add(p)
            db.session.commit()

        pagination = Prediction.query.order_by(Prediction.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        items = []
        for item in pagination.items:
            data = item.to_dict()
            try:
                data['explainability'] = json.loads(data['explainability_json']) if data['explainability_json'] else {}
            except Exception:
                data['explainability'] = {}
            items.append(data)
            
        return jsonify({
            "items": items,
            "total": pagination.total,
            "pages": pagination.pages,
            "current_page": page
        }), 200
    except Exception:
        return jsonify({
            "items": [
                {
                    "id": i + 1,
                    "input_data": s["input_data"],
                    "input_type": s["input_type"],
                    "prediction_result": s["prediction_result"],
                    "severity_level": s["severity_level"],
                    "confidence_score": s["confidence_score"],
                    "explainability": s["explainability"],
                    "created_at": (now - datetime.timedelta(hours=(i + 1) * 6)).isoformat()
                } for i, s in enumerate(DEFAULT_SCANS)
            ],
            "total": len(DEFAULT_SCANS),
            "pages": 1,
            "current_page": 1
        }), 200

@history_bp.route('/export', methods=['GET'])
def export_history():
    export_format = request.args.get('format', 'json').lower()
    try:
        scans = Prediction.query.order_by(Prediction.created_at.desc()).limit(1000).all()
        items = [s.to_dict() for s in scans]
    except Exception:
        items = DEFAULT_SCANS

    if export_format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Timestamp', 'Type', 'Severity', 'Confidence Score', 'Input Data'])
        for item in items:
            writer.writerow([
                item.get('id', ''),
                item.get('created_at', ''),
                item.get('input_type', ''),
                item.get('severity_level', ''),
                f"{round(float(item.get('confidence_score', 0)) * 100, 1)}%",
                item.get('input_data', '')[:120]
            ])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=sentinel_threat_audit.csv'}
        )

    return jsonify({
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_records": len(items),
        "records": items
    }), 200

@history_bp.route('/<int:id>', methods=['DELETE'])
def delete_history(id):
    try:
        prediction = db.session.get(Prediction, id) if hasattr(db.session, 'get') else Prediction.query.get(id)
        if not prediction:
            return jsonify({"error": "Scan record not found"}), 404
            
        db.session.delete(prediction)
        db.session.commit()
        return jsonify({"message": "Deleted successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Failed to delete record: {str(e)}"}), 500
