"""
URL Analyzer Module
Deep analysis of suspicious URLs for phishing detection
"""

import re
import ssl
import socket
import requests
import datetime
import json
from urllib.parse import urlparse, parse_qs, unquote
import dns.resolver
import whois

# ============================================
# DOMAIN INTELLIGENCE
# ============================================

def analyze_domain_info(url):
    """Get comprehensive domain information via WHOIS"""
    result = {
        'success': False,
        'domain': None,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'domain_age_days': None,
        'registrant_country': None,
        'name_servers': [],
        'risk_factors': []
    }
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove www. prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        result['domain'] = domain
        
        # WHOIS lookup
        w = whois.whois(domain)
        
        if w:
            result['success'] = True
            result['registrar'] = w.registrar if hasattr(w, 'registrar') else None
            
            # Handle creation date (can be list or single value)
            if hasattr(w, 'creation_date') and w.creation_date:
                creation = w.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                result['creation_date'] = creation.strftime('%Y-%m-%d') if creation else None
                
                # Calculate domain age
                if creation:
                    age = (datetime.datetime.now() - creation).days
                    result['domain_age_days'] = age
                    
                    # Risk assessment based on age
                    if age < 30:
                        result['risk_factors'].append(f"Domain is very new ({age} days old) - HIGH RISK")
                    elif age < 90:
                        result['risk_factors'].append(f"Domain is relatively new ({age} days old) - MEDIUM RISK")
            
            # Expiration date
            if hasattr(w, 'expiration_date') and w.expiration_date:
                expiration = w.expiration_date
                if isinstance(expiration, list):
                    expiration = expiration[0]
                result['expiration_date'] = expiration.strftime('%Y-%m-%d') if expiration else None
            
            # Registrant country
            if hasattr(w, 'country') and w.country:
                result['registrant_country'] = w.country
            
            # Name servers
            if hasattr(w, 'name_servers') and w.name_servers:
                ns = w.name_servers
                if isinstance(ns, list):
                    result['name_servers'] = [str(n).lower() for n in ns[:4]]
                else:
                    result['name_servers'] = [str(ns).lower()]
                    
    except Exception as e:
        result['error'] = str(e)
        result['risk_factors'].append("WHOIS lookup failed - domain may be protected or suspicious")
    
    return result


def check_domain_reputation(domain):
    """Check domain against various reputation indicators"""
    risk_score = 0
    findings = []
    
    # Suspicious TLDs commonly used in phishing
    suspicious_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link', 
                       '.info', '.online', '.site', '.website', '.tk', '.ml', 
                       '.ga', '.cf', '.gq', '.pw']
    
    for tld in suspicious_tlds:
        if domain.endswith(tld):
            risk_score += 20
            findings.append(f"Uses suspicious TLD: {tld}")
            break
    
    # Check for brand impersonation patterns
    brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 
              'netflix', 'bank', 'chase', 'wellsfargo', 'citibank', 'hsbc',
              'instagram', 'whatsapp', 'linkedin', 'twitter', 'dropbox']
    
    for brand in brands:
        if brand in domain and brand not in domain.split('.')[-2]:
            # Brand name appears but isn't the main domain
            risk_score += 35
            findings.append(f"Possible brand impersonation: Contains '{brand}' in suspicious context")
            break
    
    # Check for typosquatting patterns (character substitution)
    typosquat_patterns = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        'rn': 'm', 'vv': 'w', 'cl': 'd'
    }
    
    for fake, real in typosquat_patterns.items():
        if fake in domain:
            risk_score += 15
            findings.append(f"Possible typosquatting: '{fake}' may be mimicking '{real}'")
    
    # Excessive hyphens or numbers (common in phishing domains)
    hyphen_count = domain.count('-')
    if hyphen_count >= 3:
        risk_score += 25
        findings.append(f"Excessive hyphens in domain ({hyphen_count}) - common phishing pattern")
    elif hyphen_count >= 2:
        risk_score += 10
        findings.append(f"Multiple hyphens in domain ({hyphen_count})")
    
    # Numbers in domain (excluding normal ones)
    digit_count = sum(c.isdigit() for c in domain.split('.')[0])
    if digit_count >= 4:
        risk_score += 15
        findings.append(f"Many numbers in domain ({digit_count} digits)")
    
    # Very long subdomain chains
    parts = domain.split('.')
    if len(parts) > 4:
        risk_score += 20
        findings.append(f"Suspicious subdomain chain ({len(parts)} levels)")
    
    return risk_score, findings


# ============================================
# SSL/TLS CERTIFICATE ANALYSIS
# ============================================

def analyze_ssl_certificate(url):
    """Deep SSL certificate analysis"""
    result = {
        'success': False,
        'has_ssl': False,
        'issuer': None,
        'issuer_org': None,
        'subject': None,
        'valid_from': None,
        'valid_until': None,
        'days_until_expiry': None,
        'san_domains': [],
        'certificate_version': None,
        'risk_factors': []
    }
    
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                result['success'] = True
                result['has_ssl'] = True
                
                # Parse issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer_dict.get('commonName', 'Unknown')
                result['issuer_org'] = issuer_dict.get('organizationName', 'Unknown')
                
                # Parse subject
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                result['subject'] = subject_dict.get('commonName', 'Unknown')
                
                # Validity dates
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                
                if not_before:
                    valid_from = datetime.datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                    result['valid_from'] = valid_from.strftime('%Y-%m-%d')
                    
                    # Check if certificate is very new (issued recently)
                    cert_age = (datetime.datetime.now() - valid_from).days
                    if cert_age < 7:
                        result['risk_factors'].append(f"Certificate issued very recently ({cert_age} days ago)")
                
                if not_after:
                    valid_until = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    result['valid_until'] = valid_until.strftime('%Y-%m-%d')
                    
                    days_left = (valid_until - datetime.datetime.now()).days
                    result['days_until_expiry'] = days_left
                    
                    if days_left < 0:
                        result['risk_factors'].append("Certificate has EXPIRED - CRITICAL")
                    elif days_left < 14:
                        result['risk_factors'].append(f"Certificate expires very soon ({days_left} days)")
                    elif days_left < 30:
                        result['risk_factors'].append(f"Certificate expires soon ({days_left} days)")
                
                # Subject Alternative Names
                san = cert.get('subjectAltName', [])
                result['san_domains'] = [x[1] for x in san if x[0] == 'DNS'][:10]
                
                # Check for free/automated certificate issuers (not inherently bad, but notable)
                free_issuers = ["let's encrypt", "zerossl", "buypass", "ssl.com"]
                issuer_lower = result['issuer_org'].lower() if result['issuer_org'] else ''
                
                for free_issuer in free_issuers:
                    if free_issuer in issuer_lower:
                        result['risk_factors'].append(f"Uses free SSL certificate ({result['issuer_org']})")
                        break
                
                # Check certificate version
                result['certificate_version'] = cert.get('version', 'Unknown')
                
    except ssl.SSLCertVerificationError as e:
        result['risk_factors'].append(f"SSL Certificate verification FAILED: {str(e)[:100]}")
        result['has_ssl'] = False
    except ssl.SSLError as e:
        result['risk_factors'].append(f"SSL Error: {str(e)[:100]}")
    except socket.timeout:
        result['risk_factors'].append("Connection timed out - server may be slow or blocking")
    except socket.gaierror:
        result['risk_factors'].append("Could not resolve hostname")
    except ConnectionRefusedError:
        result['risk_factors'].append("Connection refused on port 443 - no HTTPS")
    except Exception as e:
        result['error'] = str(e)
        result['risk_factors'].append(f"SSL check failed: {str(e)[:50]}")
    
    return result


# ============================================
# REDIRECT CHAIN ANALYSIS
# ============================================

def analyze_redirect_chain(url):
    """Follow and analyze redirect chain"""
    result = {
        'success': False,
        'redirect_count': 0,
        'chain': [],
        'final_url': url,
        'crosses_domains': False,
        'uses_shortener': False,
        'risk_factors': []
    }
    
    # Known URL shorteners
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
                  'buff.ly', 'short.link', 'rebrand.ly', 'cutt.ly', 'shorturl.at']
    
    try:
        current_url = url
        visited = set()
        original_domain = urlparse(url).netloc.lower()
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for i in range(10):  # Max 10 redirects
            if current_url in visited:
                result['risk_factors'].append("Redirect loop detected!")
                break
            
            visited.add(current_url)
            parsed = urlparse(current_url)
            current_domain = parsed.netloc.lower()
            
            # Check for URL shorteners
            for shortener in shorteners:
                if shortener in current_domain:
                    result['uses_shortener'] = True
                    result['risk_factors'].append(f"Uses URL shortener: {shortener}")
            
            result['chain'].append({
                'url': current_url,
                'domain': current_domain
            })
            
            try:
                response = requests.head(current_url, allow_redirects=False, 
                                        timeout=10, headers=headers)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    result['redirect_count'] += 1
                    next_url = response.headers.get('Location', '')
                    
                    if next_url:
                        # Handle relative URLs
                        if next_url.startswith('/'):
                            next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                        elif not next_url.startswith('http'):
                            next_url = f"{parsed.scheme}://{parsed.netloc}/{next_url}"
                        
                        current_url = next_url
                    else:
                        break
                else:
                    break
                    
            except requests.exceptions.RequestException:
                # Try GET if HEAD fails
                try:
                    response = requests.get(current_url, allow_redirects=False,
                                           timeout=10, headers=headers)
                    if response.status_code not in [301, 302, 303, 307, 308]:
                        break
                except:
                    break
        
        result['success'] = True
        result['final_url'] = current_url
        
        # Check if redirects cross domains
        domains_visited = set(item['domain'] for item in result['chain'])
        if len(domains_visited) > 1:
            result['crosses_domains'] = True
            result['risk_factors'].append(f"Redirects across {len(domains_visited)} different domains")
        
        # Risk assessment based on redirect count
        if result['redirect_count'] >= 5:
            result['risk_factors'].append(f"Excessive redirects ({result['redirect_count']}) - HIGH RISK")
        elif result['redirect_count'] >= 3:
            result['risk_factors'].append(f"Multiple redirects ({result['redirect_count']}) - SUSPICIOUS")
        
        # Check if final domain differs significantly from original
        final_domain = urlparse(result['final_url']).netloc.lower()
        if final_domain != original_domain:
            result['risk_factors'].append(f"Final destination ({final_domain}) differs from original URL")
            
    except Exception as e:
        result['error'] = str(e)
        result['risk_factors'].append(f"Redirect analysis failed: {str(e)[:50]}")
    
    return result


# ============================================
# DNS ANALYSIS
# ============================================

def get_safe_dns_resolver():
    """Create a DNS resolver with fallback nameservers and strict timeout"""
    try:
        resolver = dns.resolver.Resolver()
    except Exception:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.timeout = 2.0
    resolver.lifetime = 2.5
    return resolver


def analyze_dns_records(url):
    """Analyze DNS records (A, AAAA, MX, TXT, NS) with timeout protection"""
    result = {
        'success': False,
        'a_records': [],
        'aaaa_records': [],
        'mx_records': [],
        'txt_records': [],
        'ns_records': [],
        'risk_factors': []
    }
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if ':' in domain:
            domain = domain.split(':')[0]
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        resolver = get_safe_dns_resolver()

        # A Records (IPv4)
        try:
            answers = resolver.resolve(domain, 'A')
            result['a_records'] = [str(r) for r in answers]
        except Exception:
            result['risk_factors'].append("No A records found")
        
        # AAAA Records (IPv6)
        try:
            answers = resolver.resolve(domain, 'AAAA')
            result['aaaa_records'] = [str(r) for r in answers]
        except Exception:
            pass

        # MX Records
        try:
            answers = resolver.resolve(domain, 'MX')
            result['mx_records'] = [str(r.exchange).rstrip('.') for r in answers]
        except Exception:
            pass
        
        # TXT Records (SPF / verification)
        try:
            answers = resolver.resolve(domain, 'TXT')
            result['txt_records'] = [
                b''.join(r.strings).decode('utf-8', errors='ignore') if hasattr(r, 'strings') else str(r).strip('"')
                for r in answers
            ][:5]
        except Exception:
            pass
        
        # NS Records
        try:
            answers = resolver.resolve(domain, 'NS')
            result['ns_records'] = [str(r).rstrip('.') for r in answers]
        except Exception:
            result['risk_factors'].append("No NS records found - unusual")
        
        result['success'] = True
        
        # Check for suspicious parked/free DNS providers
        suspicious_ns = ['parkingcrew', 'sedoparking', 'bodis', 'above.com']
        for ns in result['ns_records']:
            for sus in suspicious_ns:
                if sus in ns.lower():
                    result['risk_factors'].append(f"Uses parking/suspicious DNS: {ns}")
        
    except Exception as e:
        result['error'] = str(e)
        result['risk_factors'].append(f"DNS lookup failed: {str(e)[:50]}")
    
    return result


# ============================================
# CONTENT ANALYSIS
# ============================================

def analyze_page_content(url):
    """Analyze the actual page content for phishing indicators"""
    result = {
        'success': False,
        'has_login_form': False,
        'has_password_field': False,
        'requests_sensitive_info': False,
        'external_form_action': False,
        'page_title': None,
        'suspicious_elements': [],
        'risk_factors': []
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, timeout=15, headers=headers, allow_redirects=True)
        content = response.text.lower()
        
        result['success'] = True
        
        # Check for login forms
        if '<form' in content and ('password' in content or 'login' in content):
            result['has_login_form'] = True
            result['risk_factors'].append("Page contains login form")
        
        # Check for password fields
        if 'type="password"' in content or "type='password'" in content:
            result['has_password_field'] = True
            result['risk_factors'].append("Page has password input field")
        
        # Check for sensitive information requests
        sensitive_terms = ['ssn', 'social security', 'credit card', 'cvv', 'pin', 
                          'bank account', 'routing number', 'mother\'s maiden']
        
        for term in sensitive_terms:
            if term in content:
                result['requests_sensitive_info'] = True
                result['suspicious_elements'].append(f"Requests: {term}")
                result['risk_factors'].append(f"Page asks for sensitive info: {term}")
        
        # Check for external form actions
        import re
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', content)
        current_domain = urlparse(url).netloc.lower()
        
        for action in form_actions:
            if action.startswith('http'):
                action_domain = urlparse(action).netloc.lower()
                if action_domain != current_domain:
                    result['external_form_action'] = True
                    result['risk_factors'].append(f"Form submits to external domain: {action_domain}")
        
        # Extract page title
        title_match = re.search(r'<title[^>]*>([^<]*)</title>', content)
        if title_match:
            result['page_title'] = title_match.group(1).strip()[:100]
        
        # Check for brand impersonation in content
        brands = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
                  'netflix', 'bank of america', 'chase', 'wells fargo']
        
        domain = urlparse(url).netloc.lower()
        for brand in brands:
            brand_clean = brand.replace(' ', '')
            if brand in content and brand_clean not in domain:
                result['risk_factors'].append(f"Page mentions '{brand}' but domain doesn't match")
                break
        
        # Check for urgency tactics in content
        urgency_phrases = ['account suspended', 'verify immediately', 'act now',
                          'limited time', 'expires today', 'unauthorized access']
        
        for phrase in urgency_phrases:
            if phrase in content:
                result['risk_factors'].append(f"Uses urgency tactic: '{phrase}'")
        
    except requests.exceptions.Timeout:
        result['risk_factors'].append("Page load timed out")
    except requests.exceptions.ConnectionError:
        result['risk_factors'].append("Could not connect to server")
    except Exception as e:
        result['error'] = str(e)
        result['risk_factors'].append(f"Content analysis failed: {str(e)[:50]}")
    
    return result


# ============================================
# THREAT DATABASE CHECKS
# ============================================

def check_google_safe_browsing(url, api_key=None):
    """Check URL against Google Safe Browsing (requires API key)"""
    result = {
        'success': False,
        'is_malicious': False,
        'threat_types': [],
        'risk_factors': []
    }
    
    if not api_key:
        result['note'] = "Google Safe Browsing API key not configured"
        return result
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            "client": {
                "clientId": "phishing-analyzer",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=payload, timeout=10)
        data = response.json()
        
        result['success'] = True
        
        if 'matches' in data and data['matches']:
            result['is_malicious'] = True
            for match in data['matches']:
                threat_type = match.get('threatType', 'Unknown')
                result['threat_types'].append(threat_type)
                result['risk_factors'].append(f"Google Safe Browsing: {threat_type}")
                
    except Exception as e:
        result['error'] = str(e)
    
    return result


def check_phishtank(url):
    """Check URL against PhishTank database (simplified)"""
    result = {
        'success': False,
        'in_database': False,
        'verified_phish': False,
        'risk_factors': []
    }
    
    # Note: Full PhishTank API requires registration
    # This is a simplified check
    result['note'] = "PhishTank check requires API registration"
    
    return result


# ============================================
# MAIN ANALYSIS FUNCTION
# ============================================

def analyze_url_comprehensive(url, google_api_key=None):
    """Perform comprehensive URL analysis"""
    
    # Normalize URL
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    
    results = {
        'url': url,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'overall_risk_score': 0,
        'risk_level': 'Unknown',
        'domain_info': {},
        'ssl_info': {},
        'redirect_info': {},
        'dns_info': {},
        'content_info': {},
        'threat_check': {},
        'all_risk_factors': [],
        'summary': ''
    }
    
    total_risk = 0
    all_factors = []
    
    # 1. Domain Intelligence
    print("🔍 Analyzing domain...")
    results['domain_info'] = analyze_domain_info(url)
    domain_risk, domain_factors = check_domain_reputation(urlparse(url).netloc)
    total_risk += domain_risk
    all_factors.extend(domain_factors)
    all_factors.extend(results['domain_info'].get('risk_factors', []))
    
    # Age-based risk
    if results['domain_info'].get('domain_age_days'):
        age = results['domain_info']['domain_age_days']
        if age < 30:
            total_risk += 30
        elif age < 90:
            total_risk += 15
    
    # 2. SSL Certificate Analysis
    print("🔒 Checking SSL certificate...")
    results['ssl_info'] = analyze_ssl_certificate(url)
    all_factors.extend(results['ssl_info'].get('risk_factors', []))
    
    if not results['ssl_info'].get('has_ssl'):
        total_risk += 25
        all_factors.append("No valid SSL certificate")
    
    # 3. Redirect Chain Analysis
    print("↪️ Following redirects...")
    results['redirect_info'] = analyze_redirect_chain(url)
    all_factors.extend(results['redirect_info'].get('risk_factors', []))
    
    if results['redirect_info'].get('uses_shortener'):
        total_risk += 20
    if results['redirect_info'].get('redirect_count', 0) >= 3:
        total_risk += 15
    
    # 4. DNS Analysis
    print("📡 Analyzing DNS...")
    results['dns_info'] = analyze_dns_records(url)
    all_factors.extend(results['dns_info'].get('risk_factors', []))
    
    # 5. Content Analysis
    print("📄 Analyzing page content...")
    results['content_info'] = analyze_page_content(url)
    all_factors.extend(results['content_info'].get('risk_factors', []))
    
    if results['content_info'].get('has_password_field'):
        total_risk += 20
    if results['content_info'].get('requests_sensitive_info'):
        total_risk += 30
    if results['content_info'].get('external_form_action'):
        total_risk += 25
    
    # 6. Threat Database Check
    print("🛡️ Checking threat databases...")
    results['threat_check'] = check_google_safe_browsing(url, google_api_key)
    all_factors.extend(results['threat_check'].get('risk_factors', []))
    
    if results['threat_check'].get('is_malicious'):
        total_risk += 50
    
    # Calculate final score
    results['overall_risk_score'] = min(total_risk, 100)
    results['all_risk_factors'] = list(set(all_factors))  # Remove duplicates
    
    # Determine risk level
    score = results['overall_risk_score']
    if score >= 80:
        results['risk_level'] = 'CRITICAL'
        results['summary'] = 'This URL shows strong indicators of being a phishing or malicious site. Do NOT visit or enter any information.'
    elif score >= 60:
        results['risk_level'] = 'HIGH'
        results['summary'] = 'This URL has multiple suspicious characteristics. Exercise extreme caution.'
    elif score >= 40:
        results['risk_level'] = 'MEDIUM'
        results['summary'] = 'This URL has some concerning elements. Verify legitimacy before proceeding.'
    elif score >= 20:
        results['risk_level'] = 'LOW'
        results['summary'] = 'Minor concerns detected. The URL appears mostly legitimate but verify if unsure.'
    else:
        results['risk_level'] = 'SAFE'
        results['summary'] = 'No significant threats detected. The URL appears to be legitimate.'
    
    return results
