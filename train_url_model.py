"""
URL Phishing ML Model Trainer
Trains a Random Forest classifier on URL lexical and structural network features.
Saves the trained model to url_phishing_model.joblib.
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from url_features import extract_url_features, FEATURE_NAMES

MODEL_PATH = "url_phishing_model.joblib"

# Curated benchmark dataset of representative legitimate and phishing URLs
# covering brand impersonation, IP addresses, DGA strings, deep subdomains, suspicious TLDs, and clean sites.
BENCHMARK_URLS = [
    # Legitimate domains & paths (target = 0)
    ("https://www.google.com", 0),
    ("https://github.com/torvalds/linux", 0),
    ("https://en.wikipedia.org/wiki/Computer_network", 0),
    ("https://www.microsoft.com/en-us/software-download", 0),
    ("https://amazon.com/gp/bestsellers", 0),
    ("https://apple.com/iphone-16-pro", 0),
    ("https://netflix.com/browse", 0),
    ("https://linkedin.com/feed", 0),
    ("https://stackoverflow.com/questions/tagged/python", 0),
    ("https://cloudflare.com/products/zero-trust", 0),
    ("https://www.mit.edu/academics", 0),
    ("https://www.harvard.edu/programs", 0),
    ("https://www.stanford.edu/research", 0),
    ("https://docs.python.org/3/library/socket.html", 0),
    ("https://pypi.org/project/scikit-learn", 0),
    ("https://news.ycombinator.com", 0),
    ("https://medium.com/topic/cybersecurity", 0),
    ("https://reddit.com/r/netsec", 0),
    ("https://bbc.com/news/technology", 0),
    ("https://reuters.com/business", 0),
    ("https://cnn.com/world", 0),
    ("https://nytimes.com/section/technology", 0),
    ("https://wsj.com/news/business", 0),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP", 0),
    ("https://kernel.org", 0),
    ("https://apache.org", 0),
    ("https://ubuntu.com/download/desktop", 0),
    ("https://gitlab.com/explore", 0),
    ("https://arxiv.org/abs/2103.00020", 0),
    ("https://ieeexplore.ieee.org/document/9000000", 0),
    ("https://whois.domaintools.com", 0),
    ("https://dnschecker.org", 0),
    ("https://iana.org/domains/root/db", 0),
    ("https://icann.org", 0),
    ("https://ietf.org/rfc/rfc5322.txt", 0),
    ("https://cisco.com/c/en/us/products/security.html", 0),
    ("https://ibm.com/security", 0),
    ("https://oracle.com/cloud", 0),
    ("https://salesforce.com/products", 0),
    ("https://zoom.us/join", 0),
    ("https://slack.com/help", 0),
    ("https://atlassian.com/software/jira", 0),
    ("https://dropbox.com/business", 0),
    ("https://spotify.com/us/premium", 0),
    ("https://twitch.tv/directory", 0),
    ("https://paypal.com/signin", 0),
    ("https://chase.com/personal/banking", 0),
    ("https://bankofamerica.com", 0),
    ("https://wellsfargo.com", 0),
    ("https://fidelity.com", 0),
    ("https://schwab.com", 0),
    ("https://vanguard.com", 0),
    ("https://khanacademy.org", 0),
    ("https://coursera.org/browse", 0),
    ("https://edx.org/search", 0),
    ("https://mitpress.mit.edu", 0),
    ("https://springer.com", 0),
    ("https://nature.com", 0),
    ("https://sciencedirect.com", 0),
    ("https://nih.gov", 0),

    # Phishing / Malicious URLs (target = 1)
    ("http://login-verification-paypal-account.xyz/update-auth", 1),
    ("http://198.51.100.12/account/update-billing/login.php", 1),
    ("http://203.0.113.88/secure/signin", 1),
    ("http://185.220.101.5/webscr/login?cmd=_login-run", 1),
    ("https://accounts.google.com.security-alerts-review.top/signin", 1),
    ("http://appleid.apple.com.verify-device-support.club/login", 1),
    ("http://netflix-billing-update-service.online/auth", 1),
    ("http://amazon-account-suspension-warning.site/verify", 1),
    ("http://microsoft-365-password-reset-request.click/portal", 1),
    ("http://wellsfargo-online-banking-security.buzz/login", 1),
    ("http://chase-bank-verify-identity-alert.work/auth", 1),
    ("http://secure-login.chase.com.unauth-session.top/update", 1),
    ("http://paypal.com-webscr-cmd-flow.ml/login?token=894375", 1),
    ("http://bankofamerica-customer-support-notice.gq/login", 1),
    ("http://support-apple-id-locked-action.cf/unlock", 1),
    ("http://facebook-security-checkpoint-appeal.ga/recover", 1),
    ("http://instagram-copyright-infringement-case.tk/appeal", 1),
    ("http://binance-security-kyc-verification.pw/wallet-auth", 1),
    ("http://metamask-seed-phrase-validation.xyz/connect", 1),
    ("http://coinbase-account-restricted-alert.top/verify", 1),
    ("http://dhl-express-package-delivery-redirection.click/tracking", 1),
    ("http://fedex-parcel-pending-fee-payment.work/confirm", 1),
    ("http://usps-tracking-undelivered-post.site/redelivery", 1),
    ("http://irs-tax-refund-claim-portal.online/claim", 1),
    ("http://gov-service-stimulus-application.website/apply", 1),
    ("http://security-update-alert-warning-action.loan/signin", 1),
    ("http://verify-my-account-now-urgent.fit/login", 1),
    ("http://192.168.1.1.attacker-domain.xyz/admin-login", 1),
    ("http://login.microsoftonline.com.oauth-redirect-token.top/auth", 1),
    ("http://signin.aws.amazon.com.iam-credential-review.club/login", 1),
    ("http://dropbox-shared-document-view-sign.click/login", 1),
    ("http://zoom-meeting-invitation-reconnect.online/join", 1),
    ("http://docu-sign-secure-document-portal.website/sign", 1),
    ("http://adobe-pdf-cloud-shared-attachment.site/view", 1),
    ("http://slack-workspace-invitation-token.work/connect", 1),
    ("http://whatsapp-web-qr-session-sync.buzz/connect", 1),
    ("http://telegram-account-verification-code.top/verify", 1),
    ("http://spotify-free-premium-upgrade-reward.xyz/claim", 1),
    ("http://steam-community-free-skins-trade.click/trade", 1),
    ("http://discord-nitro-gift-claim-promo.site/gift", 1),
    ("http://roblox-free-robux-generator-tool.online/claim", 1),
    ("http://walmart-survey-gift-card-winner.work/reward", 1),
    ("http://target-customer-satisfaction-bonus.club/claim", 1),
    ("http://bestbuy-loyalty-points-redemption.buzz/redeem", 1),
    ("http://ebay-unusual-bidding-activity-alert.top/login", 1),
    ("http://aliexpress-order-status-issue.site/confirm", 1),
    ("http://att-yahoo-mail-upgrade-required.online/login", 1),
    ("http://comcast-xfinity-billing-update-center.website/auth", 1),
    ("http://verizon-wireless-rebate-card-processing.club/rebate", 1),
    ("http://tmobile-account-pin-change-request.click/auth", 1),
    ("http://vodafone-bill-payment-gateway.work/pay", 1),
    ("http://orange-telecom-espace-client-login.xyz/auth", 1),
    ("http://bbva-banca-movil-seguridad-alerta.site/login", 1),
    ("http://santander-acceso-clientes-seguridad.top/entrar", 1),
    ("http://caixabank-particulares-seguridad-aviso.online/login", 1),
    ("http://itau-banco-atualizacao-cadastral.website/token", 1),
    ("http://bradesco-seguranca-chave-acesso.club/login", 1),
    ("http://hsbc-security-token-re-synchronization.click/auth", 1),
    ("http://barclays-online-banking-pinentry.buzz/login", 1),
    ("http://lloyds-fraud-detection-security-team.top/alert", 1)
]


def generate_augmented_dataset():
    """Extract features for all benchmark URLs into a pandas DataFrame"""
    data = []
    for url, label in BENCHMARK_URLS:
        feat = extract_url_features(url)
        feat['label'] = label
        feat['url'] = url
        data.append(feat)

    df = pd.DataFrame(data)
    return df


def train_url_model():
    print("=" * 60)
    print("Training URL Phishing ML Classifier")
    print("=" * 60)

    df = generate_augmented_dataset()
    print(f"Total samples: {len(df)}")
    print(f"  Legitimate: {(df['label'] == 0).sum()}")
    print(f"  Phishing:   {(df['label'] == 1).sum()}")

    X = df[FEATURE_NAMES]
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        random_state=42,
        class_weight='balanced'
    )

    print("\nFitting model...")
    clf.fit(X_train, y_train)
    print("Model fit complete.")

    y_pred = clf.predict(X_test)
    print("\nClassification Report (Test Set):")
    print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # 5-fold cross-validation
    cv_scores = cross_val_score(clf, X, y, cv=5, scoring='f1')
    print(f"5-Fold Cross-Validation F1 Scores: {[round(s, 3) for s in cv_scores]}")
    print(f"Mean F1: {round(cv_scores.mean(), 3)} (+/- {round(cv_scores.std(), 3)})")

    # Feature importances
    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: x[1], reverse=True)
    print("\nTop 7 Predictive Features:")
    for name, imp in importances[:7]:
        print(f"  - {name:<26}: {imp:.4f}")

    joblib.dump(clf, MODEL_PATH)
    print(f"\nModel saved successfully to {MODEL_PATH}")

    # Sanity checks
    print("\nSanity Check:")
    tests = [
        "https://github.com",
        "https://en.wikipedia.org",
        "http://paypal-verification-secure-portal.com/login",
        "http://198.51.100.12/account/update-billing",
        "https://accounts.google.com.security-alerts-review.top/signin"
    ]
    for u in tests:
        feat = extract_url_features(u)
        vec = [feat[k] for k in FEATURE_NAMES]
        prob = clf.predict_proba([vec])[0][1]
        verdict = "PHISHING" if prob > 0.5 else "LEGIT"
        print(f"  [{verdict:^8}] ({prob*100:4.1f}% phish) -> {u}")


if __name__ == '__main__':
    train_url_model()
