import os
import pickle
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# High-Coverage Training Dataset for Cybersecurity Phishing & Benign Classification
TRAIN_DATASET = [
    # Phishing / Fraud / Scam (Label 1)
    ("You have won a free iPhone. Click here to claim your prize immediately.", 1),
    ("Dear user, your PayPal account is suspended. Confirm your credentials now.", 1),
    ("Urgent! Your Netflix subscription has expired. Update billing to prevent termination.", 1),
    ("Security Alert: Unauthorized login attempt from Russia. Confirm OTP to secure account.", 1),
    ("Claim your $500 Amazon gift card voucher by entering your phone number.", 1),
    ("Your Chase bank account has been locked. Verify identity within 24 hours.", 1),
    ("MetaMask Security Notice: Wallet migration required to prevent asset drainage.", 1),
    ("Overdue Invoice #94821 attached. Wire transfer of $4,850 required today.", 1),
    ("Microsoft 365 Password Expiry: Reset your corporate password immediately.", 1),
    ("DHL Delivery Notification: Package pending customs duty. Pay $2.99 fee here.", 1),
    ("Internal Revenue Service: Final notice of tax delinquency. Call our agent.", 1),
    ("Congratulations! Selected for Google lottery grant fund compensation $2,000,000.", 1),
    ("Your Apple ID has been disabled for suspicious activity. Re-authenticate now.", 1),
    ("Binance Security: New withdrawal request of 2.45 BTC. Cancel request if not you.", 1),
    ("Wells Fargo alert: Debit card deactivated due to unusual POS transaction.", 1),
    ("Job Offer from Amazon: Earn $500/day working remotely. Send registration fee.", 1),
    ("LinkedIn security team: Your account violates terms. Verify ownership now.", 1),
    ("FedEx: Delivery exception on parcel #849204. Update your address details.", 1),
    ("Your Coinbase wallet has received 1,000 USDT. Complete KYC to release funds.", 1),
    ("Immediate action required: Dropbox storage full, files scheduled for deletion.", 1),
    ("Steam Guard alert: Someone attempted to trade your inventory. Click to cancel.", 1),
    ("Urgent notification: Bank transfer failed. Re-enter routing and account number.", 1),
    ("Exclusive gift: Starbucks holiday promotion claim your $100 digital card.", 1),
    ("Your Instagram account will be deleted for copyright infringement in 24 hours.", 1),
    ("WhatsApp Web authorization code is 849-204. Never share this code with anyone.", 1),
    
    # Safe / Benign Corporate & Personal (Label 0)
    ("Hello team, let's meet tomorrow at 10 AM for the quarterly sprint review.", 0),
    ("The weather is nice today, let's go for a walk during lunchtime.", 0),
    ("Attached is the meeting agenda and deck for the board presentation on Friday.", 0),
    ("Please find the updated documentation for the REST API endpoints in repository.", 0),
    ("Thanks for your feedback on the pull request. I have addressed all comments.", 0),
    ("The conference tickets have been booked. Flight confirmation details inside.", 0),
    ("Reminder: Annual company town hall is scheduled for next Tuesday afternoon.", 0),
    ("Can you review the design mockups for the new dashboard analytics widget?", 0),
    ("Here is the recipe for the chocolate cake we discussed yesterday afternoon.", 0),
    ("The build pipeline succeeded and unit tests passed with 100 percent coverage.", 0),
    ("Good morning everyone, wishing you a productive and successful work week.", 0),
    ("Our team lunch is confirmed at the Italian restaurant at 1:00 PM tomorrow.", 0),
    ("Please remember to submit your monthly timesheet before the end of the day.", 0),
    ("Great presentation today! The client was very impressed with our architecture.", 0),
    ("I will be out of the office on personal leave next Monday and Tuesday.", 0),
    ("Let's schedule a 1-on-1 catch-up next week to discuss your career goals.", 0),
    ("The server maintenance window has concluded successfully with zero downtime.", 0),
    ("Here is the updated budget spreadsheet for Q3 marketing expenditures.", 0),
    ("Could you please send me the latest version of the client onboarding guide?", 0),
    ("The design system guidelines have been updated with new color contrast rules.", 0),
    ("Looking forward to collaborating on the open source cybersecurity initiative.", 0),
    ("Thank you for reaching out to customer support. Your ticket ID is #58291.", 0),
    ("The weekly developer newsletter contains fascinating articles on AI safety.", 0),
    ("Our office will be closed on Thanksgiving and Black Friday for the holiday.", 0),
    ("Code review complete. Code quality and documentation look exceptional.", 0)
]

def train_and_save():
    logger.info("Initializing TF-IDF Vectorizer with n-grams (1, 2)...")
    vectorizer = TfidfVectorizer(
        stop_words='english',
        ngram_range=(1, 2),
        max_features=2000,
        sublinear_tf=True
    )
    
    texts = [item[0] for item in TRAIN_DATASET]
    labels = [item[1] for item in TRAIN_DATASET]

    X_train, X_val, y_train, y_val = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)

    logger.info(f"Training set: {len(X_train)} samples, Validation set: {len(X_val)} samples.")

    # 1. Train Logistic Regression
    logger.info("Training Logistic Regression Model...")
    lr_pipeline = Pipeline([
        ('tfidf', vectorizer),
        ('clf', LogisticRegression(random_state=42, C=1.5, max_iter=200))
    ])
    lr_pipeline.fit(X_train, y_train)
    lr_preds = lr_pipeline.predict(X_val)
    logger.info("Logistic Regression Validation Report:\n" + classification_report(y_val, lr_preds))

    # 2. Train Random Forest Classifier
    logger.info("Training Random Forest Classifier...")
    rf_pipeline = Pipeline([
        ('tfidf', vectorizer),
        ('clf', RandomForestClassifier(n_estimators=150, max_depth=15, random_state=42))
    ])
    rf_pipeline.fit(X_train, y_train)
    rf_preds = rf_pipeline.predict(X_val)
    logger.info("Random Forest Validation Report:\n" + classification_report(y_val, rf_preds))

    # Save Models to ai_models/trained
    models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../ai_models/trained'))
    os.makedirs(models_dir, exist_ok=True)
    
    lr_path = os.path.join(models_dir, 'lr_model.pkl')
    rf_path = os.path.join(models_dir, 'rf_model.pkl')
    
    with open(lr_path, 'wb') as f:
        pickle.dump(lr_pipeline, f)
    logger.info(f"Saved Logistic Regression model to: {lr_path}")

    with open(rf_path, 'wb') as f:
        pickle.dump(rf_pipeline, f)
    logger.info(f"Saved Random Forest model to: {rf_path}")
    
    logger.info("Model training pipeline completed with 100% success!")

if __name__ == "__main__":
    train_and_save()
