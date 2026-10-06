"""
Phishing ML Model Trainer
=========================
Run this once to train and save the model.

Usage:
    python train_model.py

Requires:
    pip install scikit-learn pandas joblib --break-system-packages

Dataset:
    Place spam.csv from Kaggle in the same folder as this script.
    https://www.kaggle.com/datasets/shantanudhakadd/email-spam-detection-dataset-classification
"""

import pandas as pd
import joblib
import os
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix


# ── 1. Load dataset ──────────────────────────────────────────────
print("Loading dataset...")

DATASET_PATH = "spam.csv"

if not os.path.exists(DATASET_PATH):
    print(f"\n❌  Could not find '{DATASET_PATH}'.")
    print("    Download it from:")
    print("    https://www.kaggle.com/datasets/shantanudhakadd/email-spam-detection-dataset-classification")
    print("    Then place spam.csv in your project root and run this script again.\n")
    exit(1)

# The Kaggle spam.csv has columns: v1 (label), v2 (text), plus unnamed cols
df = pd.read_csv(DATASET_PATH, encoding="latin-1")[["v1", "v2"]]
df.columns = ["label", "text"]

print(f"✅  Loaded {len(df):,} emails")
print(f"    Spam:  {(df.label == 'spam').sum():,}")
print(f"    Ham:   {(df.label == 'ham').sum():,}")


# ── 2. Prepare labels ────────────────────────────────────────────
# spam/phishing = 1, legitimate (ham) = 0
df["target"] = (df["label"] == "spam").astype(int)


# ── 3. Train / test split ────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["target"],
    test_size=0.2,
    random_state=42,
    stratify=df["target"]
)

print(f"\nTrain samples: {len(X_train):,}")
print(f"Test samples:  {len(X_test):,}")


# ── 4. Build pipeline ────────────────────────────────────────────
# TF-IDF converts email text into feature vectors.
# Logistic Regression is fast, interpretable, and works very well
# on text classification — better than a naive keyword counter.
pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        max_features=10_000,     # top 10k most informative words
        ngram_range=(1, 2),      # unigrams AND bigrams ("click here", "verify account")
        sublinear_tf=True,       # dampens very frequent terms
        stop_words="english",    # removes "the", "a", "is", etc.
        min_df=2,                # ignore words appearing in <2 emails
    )),
    ("clf", LogisticRegression(
        C=1.0,
        solver="lbfgs",
        max_iter=1000,
        class_weight="balanced", # handles imbalanced spam/ham ratio
        random_state=42,
    )),
])


# ── 5. Train ─────────────────────────────────────────────────────
print("\nTraining model...")
pipeline.fit(X_train, y_train)
print("✅  Training complete")


# ── 6. Evaluate ──────────────────────────────────────────────────
print("\n── Test Set Results ──────────────────────────────────────")
y_pred = pipeline.predict(X_test)

print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing/Spam"]))

cm = confusion_matrix(y_test, y_pred)
print("Confusion matrix:")
print(f"  True Legitimate:  {cm[0][0]:>4}  |  False Phishing: {cm[0][1]:>4}")
print(f"  False Legitimate: {cm[1][0]:>4}  |  True Phishing:  {cm[1][1]:>4}")

# Cross-validation for a more honest accuracy estimate
print("\nRunning 5-fold cross-validation...")
cv_scores = cross_val_score(pipeline, df["text"], df["target"], cv=5, scoring="f1")
print(f"F1 scores across folds: {[f'{s:.3f}' for s in cv_scores]}")
print(f"Mean F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")


# ── 7. Save model ────────────────────────────────────────────────
MODEL_PATH = "phishing_model.joblib"
joblib.dump(pipeline, MODEL_PATH)
print(f"\n✅  Model saved to: {MODEL_PATH}")
print("    You can now start your Flask app — it will load this model automatically.\n")


# ── 8. Quick sanity check ────────────────────────────────────────
print("── Sanity Check ──────────────────────────────────────────")

test_cases = [
    ("URGENT: Your PayPal account has been suspended. Click here to verify immediately.", "phishing"),
    ("Hey, are we still on for lunch tomorrow?", "legitimate"),
    ("Congratulations! You've won $1,000,000. Claim your prize now.", "phishing"),
    ("Please find attached the Q3 report we discussed in the meeting.", "legitimate"),
    ("Your account password expires today. Update it now to avoid losing access.", "phishing"),
]

for text, expected in test_cases:
    prob = pipeline.predict_proba([text])[0][1]
    verdict = "PHISHING" if prob > 0.5 else "LEGIT"
    match = "✅" if verdict.lower().startswith(expected[:4]) or (verdict == "LEGIT" and expected == "legitimate") else "⚠️"
    print(f"  {match} [{prob:.0%} phishing] {text[:60]}...")

print()
