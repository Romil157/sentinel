import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dummy Data for Initial Model Building
# In a real scenario, this would load datasets from ../datasets/cleaned/
train_texts = [
    "You have won a free iPhone. Click here to claim your prize.",
    "Dear user, your bank account is suspended. Update your details.",
    "Hello, let's meet tomorrow for the project discussion.",
    "The weather is nice today, let's go for a walk.",
    "Urgent! Claim your $500 Amazon gift card now.",
    "Meeting agenda for Q3 review is attached."
]
train_labels = [1, 1, 0, 0, 1, 0] # 1: Scam/Phishing, 0: Safe

def train_and_save():
    logger.info("Initializing TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    
    logger.info("Training Logistic Regression (Baseline)...")
    lr_model = LogisticRegression(random_state=42)
    lr_pipeline = Pipeline([('tfidf', vectorizer), ('clf', lr_model)])
    lr_pipeline.fit(train_texts, train_labels)

    logger.info("Training Random Forest (Ensemble Component)...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_pipeline = Pipeline([('tfidf', vectorizer), ('clf', rf_model)])
    rf_pipeline.fit(train_texts, train_labels)

    # Save Models
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ai_models/trained'))
    os.makedirs(models_dir, exist_ok=True)
    
    lr_path = os.path.join(models_dir, 'lr_model.pkl')
    rf_path = os.path.join(models_dir, 'rf_model.pkl')
    
    with open(lr_path, 'wb') as f:
        pickle.dump(lr_pipeline, f)
    logger.info(f"Saved Logistic Regression model to {lr_path}")

    with open(rf_path, 'wb') as f:
        pickle.dump(rf_pipeline, f)
    logger.info(f"Saved Random Forest model to {rf_path}")
    
    logger.info("Model training pipeline completed successfully.")

if __name__ == "__main__":
    train_and_save()
