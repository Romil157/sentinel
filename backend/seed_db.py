import json
import random
from app import create_app, db
from app.models.user import User
from app.models.feed import ThreatFeed
from app.models.prediction import Prediction
from app.models.apikey import APIKey
import datetime

app = create_app()

def seed_database():
    with app.app_context():
        # Clear existing data for a clean slate
        db.session.query(APIKey).delete()
        db.session.query(Prediction).delete()
        db.session.query(ThreatFeed).delete()
        db.session.query(User).delete()
        
        # 1. Create a default user
        user = User(email='admin@sentinel.com', username='admin', password='password123', role='admin')
        db.session.add(user)
        db.session.commit()
        
        # 2. Seed Threat Feeds
        feeds = [
            {"title": "Global OTP Phishing Campaign", "desc": "Widespread SMS campaign asking for OTPs mimicking banking apps.", "cat": "Phishing", "risk": "Critical", "src": "CISA"},
            {"title": "Fake Subsidies Scheme", "desc": "URLs circulating promising government subsidies for clicking a link.", "cat": "Scam", "risk": "High", "src": "Sentinel Intel"},
            {"title": "Crypto Wallet Drainer", "desc": "New malvertising campaign targeting Web3 extensions.", "cat": "Malware", "risk": "Critical", "src": "Web3 Security"},
            {"title": "Suspicious .xyz Registrations", "desc": "Surge in newly registered .xyz domains used for credential harvesting.", "cat": "Phishing", "risk": "Medium", "src": "Sentinel Intel"},
            {"title": "Job Offer Fraud", "desc": "Fake recruiters on LinkedIn asking for upfront 'equipment' fees.", "cat": "Scam", "risk": "Low", "src": "User Reports"}
        ]
        
        for i, f in enumerate(feeds):
            feed = ThreatFeed(
                title=f['title'],
                description=f['desc'],
                category=f['cat'],
                risk_level=f['risk'],
                source=f['src'],
                timestamp=datetime.datetime.utcnow() - datetime.timedelta(hours=i*5)
            )
            db.session.add(feed)
            
        # 3. Seed Predictions (Scan History)
        severities = ['Safe', 'Low Risk', 'Suspicious', 'High Risk', 'Critical Threat']
        
        for i in range(25):
            is_threat = random.random() > 0.4
            sev = random.choice(['Suspicious', 'High Risk', 'Critical Threat']) if is_threat else random.choice(['Safe', 'Low Risk'])
            conf = random.uniform(0.6, 0.99) if is_threat else random.uniform(0.01, 0.3)
            
            p = Prediction(
                user_id=user.id,
                input_data=f"http://example-phish-{i}.xyz/login" if is_threat else f"http://legit-site-{i}.com",
                input_type='url',
                prediction_result='Phishing' if is_threat else 'Safe',
                severity_level=sev,
                confidence_score=conf,
                explainability_json=json.dumps({"flags": ["Suspicious TLD", "High Entropy"] if is_threat else []}),
                created_at=datetime.datetime.utcnow() - datetime.timedelta(days=random.randint(0, 10))
            )
            db.session.add(p)
            
        db.session.commit()
        print("Database seeded successfully with dummy user, feeds, and history!")

if __name__ == '__main__':
    seed_database()
