"""
URL Machine Learning Inference Engine
Loads url_phishing_model.joblib and computes real-time ML risk predictions for URLs.
"""

import os
import joblib
import pandas as pd
from url_features import extract_url_features, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "url_phishing_model.joblib")


class URLPhishingMLModel:
    def __init__(self):
        self.trained = False
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
                self.trained = True
                print("✅ URL ML model loaded successfully")
            except Exception as e:
                print(f"⚠️ URL ML model failed to load: {e}")
        else:
            print("⚠️ url_phishing_model.joblib not found. Run python3 train_url_model.py")

    def predict(self, url):
        """
        Analyze a URL using the trained Random Forest classifier.
        Returns:
            probability (int 0-100): phishing probability score
            confidence (str): 'High', 'Medium', or 'Low'
            top_factors (list): human-readable explanations of top extracted features
            features (dict): raw extracted feature values
        """
        features = extract_url_features(url)
        top_factors = []

        if features['brand_spoofed']:
            top_factors.append("Brand name detected in subdomain/path mimicking legitimate service")
        if features['is_ip']:
            top_factors.append("Host is a raw numerical IP address instead of registered domain")
        if features['suspicious_tld']:
            top_factors.append("Domain uses a high-abuse / high-risk Top-Level Domain")
        if features['count_hyphens'] >= 2:
            top_factors.append(f"Excessive hyphens in hostname ({features['count_hyphens']})")
        if features['domain_entropy'] >= 3.8:
            top_factors.append(f"High hostname entropy ({features['domain_entropy']}), indicating randomized or DGA domain")
        if features['suspicious_keyword_count'] >= 1:
            top_factors.append(f"Contains security/credential lure keywords ({features['suspicious_keyword_count']} detected)")
        if not features['has_https']:
            top_factors.append("Transmitted over insecure plain HTTP without TLS encryption")

        if not self.trained or self.model is None:
            # Heuristic fallback
            heur_score = min(len(top_factors) * 20, 95)
            confidence = "High" if heur_score >= 60 else "Medium" if heur_score >= 30 else "Low"
            return heur_score, confidence, top_factors, features

        try:
            # Construct DataFrame with column names to prevent UserWarning
            row_df = pd.DataFrame([[features[k] for k in FEATURE_NAMES]], columns=FEATURE_NAMES)
            prob = self.model.predict_proba(row_df)[0][1]
            probability = int(round(prob * 100))

            if probability >= 70:
                confidence = "High"
            elif probability >= 40:
                confidence = "Medium"
            else:
                confidence = "Low"

            return probability, confidence, top_factors, features

        except Exception as e:
            print(f"URL ML prediction error: {e}")
            heur_score = min(len(top_factors) * 20, 95)
            return heur_score, "Low", top_factors, features
