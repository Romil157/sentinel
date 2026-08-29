import os
import pickle
import logging
import re
import json
import warnings
from bs4 import BeautifulSoup

# Suppress minor scikit-learn version mismatch warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
warnings.filterwarnings("ignore", message=".*unpickle estimator.*")


logger = logging.getLogger(__name__)

# Attempt to load SpaCy if available
try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
except (OSError, ImportError):
    logger.warning("Spacy model 'en_core_web_sm' not found. Using optimized regex/heuristic tokenizer.")
    nlp = None

class TextProcessor:
    def __init__(self):
        self.models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../ai_models/trained'))
        self.rf_model = None
        self._load_models()
        
        # General Urgency & Coercion Keywords (English + Hinglish)
        self.urgency_keywords = [
            'urgent', 'immediately', 'suspended', 'locked', 'within 24 hours',
            'action required', 'unauthorized access', 'account terminated',
            'security alert', 'final notice', 'overdue', 'deactivation', 'compromised',
            'power will be disconnected', 'disconnected tonight', 'vehicle impound',
            'court summons', 'legal action', 'police complaint', 'warrant issued',
            # Hinglish Urgency
            'turant', 'aaj raat', '24 ghante', 'antim avsar', 'jald se jald', 'kat diya jayega',
            'band ho jayega', 'sampark kare'
        ]
        
        # Financial & Reward Bait (English + Hinglish)
        self.financial_keywords = [
            'winner', 'lottery', 'claim your prize', 'bank account', 'credit card',
            'refund', 'payment', 'bitcoin', 'crypto', 'wallet drain', 'wire transfer',
            'invoice unpaid', 'gift card', 'compensation', 'inheritance', 'cash prize',
            'pm-kisan', 'pm kisan installment', 'income tax refund', 'it refund approved',
            'subsidy grant', 'cashback credited', 'scratch card won',
            # Hinglish Bait
            'inam jeeta', 'kist aa gayi', 'kist claim', 'khata block', 'shulk bhare',
            'bina shulk', 'yojana labh', 'muft'
        ]
        
        # OTP / Credential Harvesting Patterns
        self.otp_patterns = [
            r'\bOTP\b', r'one[\s-]?time[\s-]?password', r'verification code',
            r'security code', r'confirm password', r'reset credentials',
            r'validate your account', r'two[\s-]?factor', r'share your 6-digit',
            r'enter mpim', r'debit card pin', r'otp share kare', r'pin darj kare'
        ]
        
        # Global & Indian Public Service / Brand Keywords
        self.brand_keywords = [
            'paypal', 'netflix', 'amazon', 'microsoft', 'apple', 'google',
            'chase', 'wells fargo', 'binance', 'coinbase', 'metamask', 'dhl', 'fedex',
            # Indian Public Services & Banking
            'echallan', 'parivahan', 'mparivahan', 'epfo', 'uan', 'uidai', 'aadhaar',
            'incometax', 'digilocker', 'sbi', 'yono', 'hdfc', 'icici', 'pnb',
            'bijli', 'electricity board', 'bescom', 'mseb', 'tneb', 'discom',
            'paytm', 'phonepe', 'gpay', 'irctc'
        ]
        
        # Indian Public Service & Hinglish Scam Signatures
        self.indian_scam_signatures = [
            {
                "pattern": r"(electricity|bijli|power|connection).*(disconnect|unpaid|update bill|officer|kat diya|kat jayega|sampark)",
                "flag": "Electricity Bill (Bijli Vibhag) Disconnection Scam Signature",
                "advisory": "Electricity distribution companies never threaten same-day disconnection via random mobile SMS or personal contact numbers."
            },
            {
                "pattern": r"(echallan|challan|parivahan|traffic|gadi).*(pending|impound|fine|court|seize|bhare|jurmana)",
                "flag": "Fake e-Challan / Parivahan Traffic Fine Scam",
                "advisory": "Traffic police official challans are only issued via official parivahan.gov.in portals, never on .xyz/.top links."
            },
            {
                "pattern": r"(pm[\s-]?kisan|subsidy|yojana|kist).*(installment|approved|claim|credit|aa gayi|labh)",
                "flag": "PM-Kisan / Government Direct Benefit Subsidy Bait",
                "advisory": "Government welfare subsidies are directly transferred via DBT to your Aadhaar-linked bank account without requiring external links."
            },
            {
                "pattern": r"(epfo|uan|pf|khata).*(block|suspend|pan link|kyc|band ho)",
                "flag": "EPFO / Bank KYC Account Freeze Threat",
                "advisory": "Banks and EPFO will never freeze accounts via WhatsApp/SMS links demanding immediate online KYC."
            },
            {
                "pattern": r"(income[\s-]?tax|itr|refund).*(refund|credited|approve|vapasi)",
                "flag": "Income Tax Department Refund Scam",
                "advisory": "Income Tax refunds are processed directly into pre-validated bank accounts without SMS verification links."
            }
        ]
        
        self.stopwords = {
            'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and',
            'any', 'are', 'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below',
            'between', 'both', 'but', 'by', 'could', 'did', 'do', 'does', 'doing', 'down',
            'during', 'each', 'few', 'for', 'from', 'further', 'had', 'has', 'have', 'having',
            'he', 'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how', 'i', 'if',
            'in', 'into', 'is', 'it', 'its', 'itself', 'just', 'me', 'more', 'most', 'my',
            'myself', 'no', 'nor', 'not', 'now', 'of', 'off', 'on', 'once', 'only', 'or',
            'other', 'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same', 'she', 'should',
            'so', 'some', 'such', 'than', 'that', 'the', 'their', 'theirs', 'them', 'themselves',
            'then', 'there', 'these', 'they', 'this', 'those', 'through', 'to', 'too', 'under',
            'until', 'up', 'very', 'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while',
            'who', 'whom', 'why', 'with', 'would', 'you', 'your', 'yours', 'yourself', 'yourselves',
            'hai', 'ki', 'ke', 'ka', 'ko', 'se', 'par', 'aur', 'kare', 'aap'
        }

    def _load_models(self):
        try:
            rf_path = os.path.join(self.models_dir, 'rf_model.pkl')
            if os.path.exists(rf_path):
                with open(rf_path, 'rb') as f:
                    self.rf_model = pickle.load(f)
                logger.info("Loaded RandomForest text model.")
        except Exception as e:
            logger.warning(f"RF model load skipped: {e}")

    def clean_text(self, text):
        if not text:
            return ""
        try:
            text = BeautifulSoup(text, "html.parser").get_text()
        except Exception:
            pass
        text = re.sub(r'http[s]?://\S+', '', text)
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        
        if nlp:
            try:
                doc = nlp(text.lower())
                text = " ".join([token.lemma_ for token in doc if not token.is_stop and not token.is_punct])
            except Exception:
                text = " ".join([w for w in text.lower().split() if w not in self.stopwords])
        else:
            text = " ".join([w for w in text.lower().split() if w not in self.stopwords])
            
        return text

    def extract_heuristics(self, raw_text):
        if not raw_text:
            return 0.0, [], None
            
        lower_text = raw_text.lower()
        flags = []
        heuristic_score = 0.0
        custom_advisory = None
        
        # 1. Check Indian Public Service & Hinglish Scam Signatures
        for sig in self.indian_scam_signatures:
            if re.search(sig["pattern"], lower_text, re.IGNORECASE):
                heuristic_score += 0.50
                flags.append(sig["flag"])
                if not custom_advisory:
                    custom_advisory = sig["advisory"]
                break

        # 2. Check Urgency
        for kw in self.urgency_keywords:
            if kw in lower_text:
                heuristic_score += 0.25
                flags.append(f"Urgency indicator: '{kw}'")
                break
                
        # 3. Check Financial
        for kw in self.financial_keywords:
            if kw in lower_text:
                heuristic_score += 0.30
                flags.append(f"Financial bait trigger: '{kw}'")
                break
                
        # 4. Check OTP/Credentials
        for pattern in self.otp_patterns:
            if re.search(pattern, raw_text, re.IGNORECASE):
                heuristic_score += 0.40
                flags.append("Credential / OTP Harvesting Pattern")
                break
                
        # 5. Check Brand Spoofing
        for brand in self.brand_keywords:
            if brand in lower_text and (heuristic_score > 0.15 or 'verify' in lower_text or 'account' in lower_text or 'link' in lower_text or 'kare' in lower_text):
                heuristic_score += 0.20
                flags.append(f"Targeting service / brand: '{brand.upper()}'")
                break
                
        return heuristic_score, flags, custom_advisory

    def predict(self, raw_text):
        if not raw_text or not raw_text.strip():
            return 0.0, {"flags": [], "model": "Heuristic-NLP", "ml_base_score": 0.0, "keyword_heatmap": {}, "citizen_advisory": None}
            
        cleaned_text = self.clean_text(raw_text)
        heuristic_score, flags, advisory = self.extract_heuristics(raw_text)
        
        ml_prob = 0.0
        if self.rf_model:
            try:
                prob = self.rf_model.predict_proba([cleaned_text])[0]
                ml_prob = float(prob[1])
            except Exception:
                try:
                    prob = self.rf_model.predict_proba([raw_text])[0]
                    ml_prob = float(prob[1])
                except Exception as e:
                    logger.warning(f"Model prediction exception: {e}")
        
        # Ensemble ML + Heuristics
        final_confidence = min(max(ml_prob + heuristic_score, 0.04), 0.99)
        
        # Keyword extraction for Explainable AI (XAI) heatmap
        words = cleaned_text.split()
        heat_map = {}
        for word in words:
            if len(word) > 2:
                base_heat = 0.15
                if any(k in word for k in self.urgency_keywords):
                    base_heat = 0.85
                elif any(k in word for k in self.financial_keywords):
                    base_heat = 0.75
                elif any(k in word for k in self.brand_keywords):
                    base_heat = 0.65
                elif len(word) > 5 and final_confidence > 0.4:
                    base_heat = 0.35
                heat_map[word] = round(min(0.95, base_heat + (words.count(word) * 0.1)), 2)

        # Default citizen safety advisory if none matched
        if not advisory and final_confidence > 0.50:
            advisory = "Do not share OTPs, click suspicious links, or make advance payments. Official public portals will never demand urgent payments on unofficial domains."

        return round(final_confidence, 2), {
            "flags": flags,
            "model": "Ensemble (RandomForest + Indian Public Service Heuristics)" if self.rf_model else "Indian Public Service Threat Engine",
            "ml_base_score": round(ml_prob, 2),
            "keyword_heatmap": heat_map,
            "citizen_advisory": advisory
        }

text_processor = TextProcessor()
