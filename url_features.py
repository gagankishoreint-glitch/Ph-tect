"""
URL Feature Extraction Engine for Machine Learning
Extracts lexical, structural, and network-related characteristics from URLs.
"""

import re
import math
from urllib.parse import urlparse
import ipaddress


SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'work', 'click', 'link', 'info',
    'online', 'site', 'website', 'tk', 'ml', 'ga', 'cf',
    'gq', 'pw', 'buzz', 'loan', 'zip', 'fit'
}

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'update', 'account', 'banking', 'secure',
    'signin', 'security', 'wallet', 'password', 'confirm', 'auth',
    'recover', 'billing', 'support', 'service'
]

POPULAR_BRANDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'whatsapp', 'chase', 'wellsfargo', 'binance'
]


def calculate_entropy(text):
    """Calculate Shannon entropy of a string (measures randomness)"""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 3)


def is_ip_host(netloc):
    """Check if the host is an IPv4 or IPv6 literal"""
    host = netloc.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def extract_url_features(url):
    """
    Extract a dictionary of numerical features from a given URL.
    Returns: dict of feature_name -> float/int
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full_url = url.lower()

    # Hostname without port
    host = netloc.split(':')[0]

    # Domain parts
    domain_parts = host.split('.')
    tld = domain_parts[-1] if domain_parts else ''

    # Brand impersonation check
    brand_spoofed = 0
    if len(domain_parts) > 2:
        registered_apex = domain_parts[-2]
        for brand in POPULAR_BRANDS:
            if brand in host and brand != registered_apex:
                brand_spoofed = 1
                break

    # Suspicious keywords count in URL
    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url)

    # Digit counts
    digit_count = sum(c.isdigit() for c in full_url)
    digit_ratio = round(digit_count / max(len(full_url), 1), 3)

    features = {
        'url_length': len(url),
        'domain_length': len(host),
        'path_length': len(path),
        'count_dots': full_url.count('.'),
        'count_hyphens': host.count('-'),
        'count_underscores': full_url.count('_'),
        'count_slashes': full_url.count('/'),
        'count_question': full_url.count('?'),
        'count_equal': full_url.count('='),
        'count_at': 1 if '@' in full_url else 0,
        'count_percent': full_url.count('%'),
        'subdomain_depth': max(0, len(domain_parts) - 2),
        'is_ip': is_ip_host(host),
        'has_https': 1 if parsed.scheme == 'https' else 0,
        'digit_ratio': digit_ratio,
        'domain_entropy': calculate_entropy(host),
        'suspicious_tld': 1 if tld in SUSPICIOUS_TLDS else 0,
        'suspicious_keyword_count': kw_count,
        'brand_spoofed': brand_spoofed
    }

    return features


FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'count_dots',
    'count_hyphens', 'count_underscores', 'count_slashes', 'count_question',
    'count_equal', 'count_at', 'count_percent', 'subdomain_depth',
    'is_ip', 'has_https', 'digit_ratio', 'domain_entropy',
    'suspicious_tld', 'suspicious_keyword_count', 'brand_spoofed'
]
