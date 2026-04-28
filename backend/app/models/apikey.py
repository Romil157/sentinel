import datetime
from app import db

class APIKey(db.Model):
    __tablename__ = 'api_keys'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False, default="Default Key")
    
    # Store only the hash, not the actual key
    key_hash = db.Column(db.String(255), unique=True, nullable=False)
    # Store the first 8 characters to display in the UI (e.g., sv_test_...)
    prefix = db.Column(db.String(20), nullable=False)
    
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    request_count = db.Column(db.Integer, nullable=False, default=0)
    last_used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'prefix': self.prefix,
            'is_active': self.is_active,
            'request_count': self.request_count,
            'last_used_at': self.last_used_at.isoformat() if self.last_used_at else None,
            'created_at': self.created_at.isoformat()
        }
