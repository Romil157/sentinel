import datetime
from app import db

class Prediction(db.Model):
    __tablename__ = 'predictions'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Nullable for anonymous predictions
    input_data = db.Column(db.Text, nullable=False)
    input_type = db.Column(db.String(50), nullable=False) # 'text' or 'url'
    
    # Model results
    prediction_result = db.Column(db.String(50), nullable=False) # 'Phishing', 'Safe', 'Scam', etc.
    confidence_score = db.Column(db.Float, nullable=False)
    explainability_json = db.Column(db.Text, nullable=True) # Serialized SHAP/LIME or keyword importance
    
    # Metadata
    ip_address = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'input_data': self.input_data,
            'input_type': self.input_type,
            'prediction_result': self.prediction_result,
            'confidence_score': self.confidence_score,
            'explainability_json': self.explainability_json,
            'created_at': self.created_at.isoformat()
        }
