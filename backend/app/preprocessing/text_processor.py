import os
import pickle
import logging
import re
from bs4 import BeautifulSoup
import spacy

logger = logging.getLogger(__name__)

# Load SpaCy model safely
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    logger.warning("Spacy model 'en_core_web_sm' not found. Fallback to basic processing.")
    nlp = None

class TextProcessor:
    def __init__(self):
        self.models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../ai_models/trained'))
        self.rf_model = None
        self.lr_model = None
        self._load_models()

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
        # Remove HTML
        text = BeautifulSoup(text, "html.parser").get_text()
        # Remove URLs
        text = re.sub(r'http[s]?://\S+', '', text)
        # Remove special characters
        text = re.sub(r'[^a-zA-Z0-9\s]', '', text)
        
        # Lemmatization & lowercasing if spacy is loaded
        if nlp:
            doc = nlp(text.lower())
            text = " ".join([token.lemma_ for token in doc if not token.is_stop and not token.is_punct])
        else:
            text = text.lower()
            
        return text

    def predict(self, raw_text):
        cleaned_text = self.clean_text(raw_text)
        
        if self.rf_model:
            prob = self.rf_model.predict_proba([cleaned_text])[0]
            scam_prob = prob[1]
            
            result = "Scam/Phishing" if scam_prob > 0.5 else "Safe"
            
            # Simple keyword explainability (mock LIME/SHAP for now)
            keywords = ["urgent", "click", "claim", "free", "suspended"]
            found_keywords = [kw for kw in keywords if kw in cleaned_text]
            
            return result, float(scam_prob), {"keywords": found_keywords, "model": "RandomForest-TFIDF"}
            
        else:
            # Fallback mock logic
            score = 0.1
            if "urgent" in raw_text.lower() or "click here" in raw_text.lower():
                score = 0.85
            return "Scam" if score > 0.5 else "Safe", score, {"keywords": ["urgent"], "model": "Mock-Fallback"}

text_processor = TextProcessor()
