import os
import pickle
import logging
import re
from bs4 import BeautifulSoup
import spacy

logger = logging.getLogger(__name__)

try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logger.warning("Spacy model 'en_core_web_sm' not found. Fallback to basic processing.")
    nlp = None

class TextProcessor:
    def __init__(self):
        self.models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../ai_models/trained'))
        self.rf_model = None
        self._load_models()
        
        self.urgency_keywords = ['urgent', 'immediately', 'suspended', 'locked', 'within 24 hours', 'action required']
        self.financial_keywords = ['winner', 'lottery', 'claim your prize', 'bank account', 'credit card', 'refund', 'payment']
        self.otp_patterns = [r'\bOTP\b', r'one time password', r'verification code', r'security code']

    def _load_models(self):
        try:
            rf_path = os.path.join(self.models_dir, 'rf_model.pkl')
            if os.path.exists(rf_path):
                with open(rf_path, 'rb') as f:
                    self.rf_model = pickle.load(f)
                logger.info("Loaded RandomForest text model.")
        except Exception as e:
            logger.error(f"Failed to load RF model: {e}")

    def clean_text(self, text):
        text = BeautifulSoup(text, "html.parser").get_text()
        text = re.sub(r'http[s]?://\S+', '', text)
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        
        if nlp:
            doc = nlp(text.lower())
            text = " ".join([token.lemma_ for token in doc if not token.is_stop and not token.is_punct])
        else:
            text = text.lower()
            
        return text

    def extract_heuristics(self, raw_text):
        lower_text = raw_text.lower()
        flags = []
        heuristic_score = 0.0
        
        # Check Urgency
        for kw in self.urgency_keywords:
            if kw in lower_text:
                heuristic_score += 0.2
                flags.append(f"Urgency indicator: '{kw}'")
                break
                
        # Check Financial
        for kw in self.financial_keywords:
            if kw in lower_text:
                heuristic_score += 0.3
                flags.append(f"Financial bait: '{kw}'")
                break
                
        # Check OTP/Credentials
        for pattern in self.otp_patterns:
            if re.search(pattern, raw_text, re.IGNORECASE):
                heuristic_score += 0.4
                flags.append("Requesting OTP/Security Code")
                break
                
        return heuristic_score, flags

    def predict(self, raw_text):
        cleaned_text = self.clean_text(raw_text)
        heuristic_score, flags = self.extract_heuristics(raw_text)
        
        ml_prob = 0.0
        if self.rf_model:
            prob = self.rf_model.predict_proba([cleaned_text])[0]
            ml_prob = prob[1]
        
        # Ensemble ML + Heuristics
        final_confidence = min(ml_prob + heuristic_score, 0.99)
        
        # Keyword extraction for XAI map
        words = cleaned_text.split()
        heat_map = {}
        for word in words:
            if len(word) > 4:
                heat_map[word] = round(min(0.9, (words.count(word) * 0.2) + ml_prob * 0.1), 2)
        
        return final_confidence, {
            "flags": flags,
            "model": "Ensemble (RF + Heuristics)",
            "ml_base_score": round(ml_prob, 2),
            "keyword_heatmap": heat_map
        }

text_processor = TextProcessor()
