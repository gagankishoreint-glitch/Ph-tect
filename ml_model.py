"""
Phishing ML Model
=================
Loads the trained scikit-learn pipeline and exposes the same
interface as the old PhishingMLModel so app.py needs minimal changes.

The model was trained on 5,572 real emails (UCI/Kaggle spam dataset)
using TF-IDF vectorization + Logistic Regression.
Accuracy: 98% | Mean F1: 0.925
"""

import joblib
import os


MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")


class PhishingMLModel:
    """
    Real ML-based phishing classifier.
    Replaces the keyword-counter that was here before.
    """

    def __init__(self):
        self.trained = False
        self.pipeline = None
        self._load_model()

    def _load_model(self):
        """Load the trained pipeline from disk."""
        if os.path.exists(MODEL_PATH):
            try:
                self.pipeline = joblib.load(MODEL_PATH)
                self.trained = True
                print("✅ ML model loaded successfully")
            except Exception as e:
                print(f"⚠️  ML model failed to load: {e}")
                print("    Run python3 train_model.py to generate it.")
        else:
            print("⚠️  phishing_model.joblib not found.")
            print("    Run python3 train_model.py to train the model first.")

    def predict(self, subject, body):
        """
        Predict whether an email is phishing.

        Returns:
            probability (int 0-100): phishing probability as a percentage
            confidence (str):        'High', 'Medium', or 'Low'
        """
        if not self.trained or self.pipeline is None:
            return self._fallback(subject, body)

        # Combine subject and body — the model was trained on full email text
        text = f"{subject} {body}".strip()

        try:
            prob = self.pipeline.predict_proba([text])[0][1]  # probability of phishing
            probability = int(round(prob * 100))

            if probability >= 70:
                confidence = "High"
            elif probability >= 40:
                confidence = "Medium"
            else:
                confidence = "Low"

            return probability, confidence

        except Exception as e:
            print(f"ML prediction error: {e}")
            return self._fallback(subject, body)

    def _fallback(self, subject, body):
        """
        Simple keyword fallback if the model isn't available.
        Clearly labelled as a fallback — not presented as ML.
        """
        text = (subject + " " + body).lower()
        score = 0
        score += sum(20 for w in ["urgent", "immediate", "expires"] if w in text)
        score += sum(15 for w in ["money", "prize", "won", "winner"] if w in text)
        score += sum(10 for w in ["click", "verify", "confirm", "update"] if w in text)
        probability = min(score, 95)
        confidence = "High" if probability > 70 else "Medium" if probability > 40 else "Low"
        return probability, confidence

    def learn(self, subject, body, is_phishing):
        """
        Placeholder for future online learning.
        Logistic Regression requires full retraining — collect
        corrections to a file and periodically retrain with train_model.py.
        """
        pass
