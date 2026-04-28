import datetime
from app import db, bcrypt

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    role = db.Column(db.String(50), nullable=False, default='user')
    
    # Settings
    theme_preference = db.Column(db.String(20), nullable=False, default='light') # 'light', 'dark', 'system'
    notifications_enabled = db.Column(db.Boolean, nullable=False, default=True)
    
    # Relationships
    predictions = db.relationship('Prediction', backref='user', lazy=True)
    api_keys = db.relationship('APIKey', backref='user', lazy=True, cascade="all, delete-orphan")

    def __init__(self, email, username, password, role='user'):
        self.email = email
        self.username = username
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.role = role

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'role': self.role,
            'theme_preference': self.theme_preference,
            'notifications_enabled': self.notifications_enabled,
            'created_at': self.created_at.isoformat()
        }
