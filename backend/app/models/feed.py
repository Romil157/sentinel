import datetime
from app import db

class ThreatFeed(db.Model):
    __tablename__ = 'threat_feeds'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'risk_level': self.risk_level,
            'source': self.source,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }
