from flask import Blueprint, jsonify
from app.models.feed import ThreatFeed
from app import db
import datetime

feed_bp = Blueprint('feed', __name__)

DEFAULT_FEEDS = [
    {
        "title": "Electricity Board (Bijli Vibhag) APK Dropper Scam",
        "desc": "Fraudulent SMS campaign threatening same-day power cutoff at 9:30 PM, luring citizens to install malicious remote-access APKs.",
        "cat": "Public Services",
        "risk": "Critical",
        "src": "I4C Cyber Crime Cell"
    },
    {
        "title": "Fake e-Challan Traffic Fine Phishing Wave",
        "desc": "Spoofed Parivahan links on .xyz/.top domains sending fake vehicle seizure notices demanding urgent UPI payments.",
        "cat": "Public Services",
        "risk": "High",
        "src": "CERT-In Advisory"
    },
    {
        "title": "SBI YONO Reward Points Credential Harvester",
        "desc": "SMS wave targeting bank customers claiming ₹9,850 in expiring reward points to harvest NetBanking credentials and OTPs.",
        "cat": "Banking",
        "risk": "Critical",
        "src": "Sentinel Telemetry"
    },
    {
        "title": "PM-Kisan 17th Installment Subsidy Bait",
        "desc": "Deceptive WhatsApp forwards promising ₹2,000 direct benefit transfers linking to phishing surveys and ad-trackers.",
        "cat": "Public Services",
        "risk": "High",
        "src": "MoA&FW Security Alert"
    },
    {
        "title": "EPFO UAN / PAN Linkage Suspension Phishing",
        "desc": "Fake EPFO portals demanding immediate PAN card verification and biometric details to prevent account freezing.",
        "cat": "Public Services",
        "risk": "High",
        "src": "EPFO Cyber Wing"
    },
    {
        "title": "Crypto Wallet Drainer Infrastructure Targeting Telegram",
        "desc": "Malvertising campaigns promoting fake DEX airdrops with automated asset drainage smart contracts.",
        "cat": "Phishing",
        "risk": "Critical",
        "src": "Web3 Security Desk"
    }
]

@feed_bp.route('/', methods=['GET'])
def get_feed():
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        feeds = ThreatFeed.query.order_by(ThreatFeed.timestamp.desc()).limit(20).all()
        if not feeds:
            # Seed default feeds if empty
            for i, f in enumerate(DEFAULT_FEEDS):
                feed = ThreatFeed(
                    title=f['title'],
                    description=f['desc'],
                    category=f['cat'],
                    risk_level=f['risk'],
                    source=f['src'],
                    timestamp=now - datetime.timedelta(hours=i*3)
                )
                db.session.add(feed)
            db.session.commit()
            feeds = ThreatFeed.query.order_by(ThreatFeed.timestamp.desc()).limit(20).all()
        return jsonify([f.to_dict() for f in feeds]), 200
    except Exception:
        # Fallback in-memory response if DB error
        return jsonify([
            {
                "id": i + 1,
                "title": f["title"],
                "description": f["desc"],
                "category": f["cat"],
                "risk_level": f["risk"],
                "source": f["src"],
                "timestamp": (now - datetime.timedelta(hours=i*3)).isoformat()
            } for i, f in enumerate(DEFAULT_FEEDS)
        ]), 200
