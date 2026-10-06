"""
Phishing Intelligence Platform v5.0
Complete Email and URL Analysis Suite
"""

from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import datetime, os, re, requests, socket, ssl, json, base64
from urllib.parse import urlparse
from url_analyzer import analyze_url_comprehensive
from attachment_analyzer import get_attachment_analyzer
from webhook_alerts import get_webhook_alerter
from header_analyzer import EmailHeaderAnalyzer
from history_feeds import ScanHistory, ThreatFeed, LearningCenter

# API Integrations
try:
    from api_integrations import get_threat_intelligence, VirusTotalAPI, GoogleSafeBrowsingAPI, AbuseIPDBAPI
    threat_intel = get_threat_intelligence()
    API_INTEGRATIONS_ENABLED = True
except Exception as e:
    print(f"API Integrations disabled: {e}")
    API_INTEGRATIONS_ENABLED = False
    threat_intel = None

try:
    from report_generator import PhishingReportGenerator
    REPORTS_ENABLED = True
except: REPORTS_ENABLED = False

try:
    from qr_scanner import get_qr_scanner
    qr_scanner = get_qr_scanner()
    QR_ENABLED = True
except Exception as e:
    print(f"QR Scanner disabled: {e}")
    QR_ENABLED = False

try:
    from screenshot_capture import get_screenshot_capture
    screenshot_capture = get_screenshot_capture()
    SCREENSHOT_ENABLED = True
except Exception as e:
    print(f"Screenshot disabled: {e}")
    SCREENSHOT_ENABLED = False

try:
    from share_report import get_share_report
    share_report = get_share_report()
    SHARE_ENABLED = True
except Exception as e:
    print(f"Share disabled: {e}")
    SHARE_ENABLED = False

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# API Keys from environment variables
GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY')
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

scan_history = ScanHistory()
attachment_analyzer_instance = get_attachment_analyzer()
webhook_alerter = get_webhook_alerter()
threat_feed = ThreatFeed()
header_analyzer = EmailHeaderAnalyzer()
if REPORTS_ENABLED: report_generator = PhishingReportGenerator()

# ============================================
# EMAIL ANALYSIS
# ============================================
def check_live_url_safety(body):
    danger_score, reasons, urls = 0, [], []
    found = re.findall(r'http[s]?://[^\s<>"]+', body)
    for url in found[:3]:
        urls.append(url)
        domain = urlparse(url).netloc.lower()
        for p in ['phishing','scam','verify-','account-','login-','secure-']:
            if p in url.lower(): danger_score += 15; reasons.append(f"Suspicious pattern: {p}")
        try:
            r = requests.head(url, timeout=5, allow_redirects=False)
            if r.status_code in [301,302,307,308] and urlparse(r.headers.get('Location','')).netloc != domain:
                danger_score += 25; reasons.append("Redirects to different domain")
        except: pass
    return danger_score, reasons, urls

from ml_model import PhishingMLModel
ml_model = PhishingMLModel()

from url_ml_model import URLPhishingMLModel
url_ml_model = URLPhishingMLModel()

from prevention_tools import PreventionExporter
prevention_exporter = PreventionExporter()

def analyze_email(subject, sender, body):
    score, reasons = 0, []
    for word in ["urgent","winner","verify","suspended","confirm","security","password","login"]:
        if word in subject.lower(): score += 12; reasons.append(f"'{word}' in subject")
        if word in body.lower(): score += 6; reasons.append(f"'{word}' in body")
    for company in ["bank","paypal","amazon","microsoft","apple"]:
        if company in sender.lower():
            for free in ["gmail.com","yahoo.com","hotmail.com"]:
                if free in sender.lower(): score += 35; reasons.append(f"Claims {company} but uses {free}")
    url_score, url_reasons, urls = check_live_url_safety(body)
    score += url_score; reasons.extend(url_reasons)
    
    # Evaluate embedded URLs using dedicated URL ML model
    for u in urls:
        u_prob, u_conf, u_factors, _ = url_ml_model.predict(u)
        if u_prob >= 60:
            score += int(u_prob * 0.3)
            reasons.append(f"AI URL Classifier flagged link ({u_prob}% risk): {u[:45]}...")
            reasons.extend(u_factors[:2])

    ml_prob, ml_conf = ml_model.predict(subject, body)
    if ml_prob > 60: score += int(ml_prob * 0.3)
    return min(score, 100), list(set(reasons)), ml_prob, ml_conf, urls

# ============================================
# ROUTES
# ============================================
@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/app')
def dashboard():
    return render_template('index.html')

@limiter.limit("30 per hour")
@app.route('/analyze', methods=['POST'])
def analyze_email_route():
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400
        sender  = str(d.get('sender',  '') or '').strip()[:200]
        subject = str(d.get('subject', '') or '').strip()[:300]
        body    = str(d.get('body',    '') or '').strip()[:10000]
        if not sender or not subject:
            return jsonify({'success': False, 'error': 'Provide sender and subject'}), 400
        score, reasons, ml_prob, ml_conf, urls = analyze_email(subject, sender, body)
        
        if score >= 80: level, color, icon, advice = "CRITICAL", "#991b1b", "🚨", "Extreme danger"
        elif score >= 60: level, color, icon, advice = "HIGH RISK", "#dc2626", "⚠️", "High threat"
        elif score >= 40: level, color, icon, advice = "MEDIUM", "#d97706", "⚡", "Suspicious"
        elif score >= 20: level, color, icon, advice = "LOW-MEDIUM", "#0891b2", "💡", "Minor concerns"
        else: level, color, icon, advice = "LOW", "#10b981", "✅", "Appears safe"
        
        result = {'success': True, 'danger_score': score, 'risk_level': level, 'risk_color': color, 'risk_icon': icon,
                  'advice': advice, 'reasons': reasons, 'ml_probability': ml_prob, 'ml_confidence': ml_conf,
                  'extracted_urls': urls, 'sender': sender, 'subject': subject, 'timestamp': datetime.datetime.now().isoformat()}
        scan_history.add_scan('email', f"{sender[:30]} - {subject[:30]}", result)
        return jsonify(result)
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@limiter.limit("20 per hour")
@app.route('/analyze-url', methods=['POST'])
def analyze_url_route():
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400
        url = str(d.get('url', '') or '').strip()[:2000]
        if not url:
            return jsonify({'success': False, 'error': 'Provide a URL'}), 400
        if not url.startswith('http'):
            url = 'https://' + url
        if len(url) > 2000:
            return jsonify({'success': False, 'error': 'URL too long'}), 400
        if not url.startswith('http'): url = 'https://' + url
        
        # Basic analysis
        results = analyze_url_comprehensive(url, GOOGLE_SAFE_BROWSING_KEY)
        score = results['overall_risk_score']
        
        # Enhanced analysis with APIs if available
        api_results = None
        if API_INTEGRATIONS_ENABLED and threat_intel:
            try:
                api_results = threat_intel.full_url_check(url)
                
                # Boost score if APIs found threats
                if api_results.get('overall_threat_score', 0) > score:
                    score = api_results['overall_threat_score']
                
                # Add API threats to reasons
                for threat in api_results.get('threats_found', []):
                    results['all_risk_factors'].append(threat)
                    
            except Exception as e:
                print(f"API check failed: {e}")
        
        if score >= 80: color, icon = "#991b1b", "🚨"
        elif score >= 60: color, icon = "#dc2626", "⚠️"
        elif score >= 40: color, icon = "#ea580c", "🔴"
        elif score >= 20: color, icon = "#d97706", "💡"
        else: color, icon = "#10b981", "✅"
        
        # Determine risk level
        if score >= 80: risk_level = "CRITICAL"
        elif score >= 60: risk_level = "HIGH RISK"
        elif score >= 40: risk_level = "MEDIUM"
        elif score >= 20: risk_level = "LOW"
        else: risk_level = "SAFE"
        
        response = {'success': True, 'url': url, 'danger_score': score, 'risk_level': risk_level,
                   'risk_color': color, 'risk_icon': icon, 'summary': results['summary'], 'reasons': results['all_risk_factors'],
                   'domain_info': results['domain_info'], 'ssl_info': results['ssl_info'], 'redirect_info': results['redirect_info'],
                   'dns_info': results['dns_info'], 'content_info': results['content_info'], 'timestamp': results['timestamp']}
        
        # Add API results if available
        if api_results:
            response['api_results'] = {
                'apis_checked': api_results.get('apis_checked', []),
                'threats_found': api_results.get('threats_found', []),
                'details': api_results.get('details', {})
            }
        
        scan_history.add_scan('url', url[:50], response)
        return jsonify(response)
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/quick-url-check', methods=['POST'])
def quick_check():
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400
        url = str(d.get('url', '') or '').strip()[:2000]
        if not url:
            return jsonify({'success': False, 'error': 'Provide a URL'}), 400
        if not url.startswith('http'):
            url = 'https://' + url
        domain = urlparse(url).netloc.lower()
        score, findings = 0, []
        
        for tld in ['.xyz','.top','.tk','.ml','.ga','.cf']:
            if domain.endswith(tld): score += 25; findings.append(f"Suspicious TLD: {tld}"); break
        for brand in ['paypal','amazon','apple','microsoft','google','bank']:
            if brand in domain and brand+'.' not in domain: score += 30; findings.append(f"Possible {brand} impersonation"); break
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname=domain): pass
        except: score += 20; findings.append("No valid SSL")
        
        verdict = "SUSPICIOUS" if score >= 50 else "CAUTION" if score >= 25 else "LIKELY SAFE"
        color = "#dc2626" if score >= 50 else "#d97706" if score >= 25 else "#10b981"
        return jsonify({'success': True, 'url': url, 'verdict': verdict, 'risk_score': score, 'color': color, 'findings': findings, 'note': 'Use full analysis for details'})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/bulk-url-check', methods=['POST'])
def bulk_check():
    try:
        urls = request.get_json().get('urls', [])[:10]
        results = []
        for url in urls:
            url = url.strip()
            if not url: continue
            if not url.startswith('http'): url = 'https://' + url
            try:
                r = analyze_url_comprehensive(url, GOOGLE_SAFE_BROWSING_KEY)
                results.append({'url': url, 'risk_score': r['overall_risk_score'], 'risk_level': r['risk_level'], 'success': True})
            except: results.append({'url': url, 'success': False, 'error': 'Failed'})
        return jsonify({'success': True, 'results': results})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/expand-url', methods=['POST'])
def expand_url():
    try:
        url = request.get_json().get('url', '').strip()
        if not url.startswith('http'): url = 'https://' + url
        chain, current = [], url
        for _ in range(10):
            try:
                r = requests.head(current, allow_redirects=False, timeout=5)
                chain.append({'url': current, 'status': r.status_code})
                if r.status_code in [301,302,303,307,308]:
                    loc = r.headers.get('Location', '')
                    if loc:
                        if not loc.startswith('http'): loc = urlparse(current).scheme + '://' + urlparse(current).netloc + loc
                        current = loc
                    else: break
                else: break
            except: break
        return jsonify({'success': True, 'original_url': url, 'final_url': current, 'redirect_count': len(chain)-1, 'chain': chain})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if not QR_ENABLED: return jsonify({'success': False, 'error': 'QR scanning unavailable'}), 400
    try:
        img = request.get_json().get('image', '')
        return jsonify(qr_scanner.decode_qr_from_base64(img))
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/analyze-headers', methods=['POST'])
def analyze_headers():
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400
        headers = str(d.get('headers', '') or '').strip()[:50000]
        if not headers:
            return jsonify({'success': False, 'error': 'Provide email headers'}), 400
        return jsonify(header_analyzer.analyze_headers(headers))
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/generate-report', methods=['POST'])
def generate_report():
    if not REPORTS_ENABLED: return jsonify({'success': False, 'error': 'PDF reports unavailable'}), 400
    try:
        d = request.get_json()
        pdf = report_generator.generate_email_report(d['data']) if d.get('type') == 'email' else report_generator.generate_url_report(d['data'])
        return send_file(pdf, mimetype='application/pdf', as_attachment=True, download_name=f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/history')
def get_history():
    try:
        return jsonify({'success': True, 'scans': scan_history.get_recent_scans(limit=request.args.get('limit', 20, type=int), scan_type=request.args.get('type')), 'stats': scan_history.get_stats()})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/history/search')
def search_history():
    return jsonify({'success': True, 'results': scan_history.search_scans(request.args.get('q', ''))})

@app.route('/history/clear', methods=['POST'])
def clear_history():
    scan_history.clear_history()
    return jsonify({'success': True})

@app.route('/threat-feed')
def get_threat_feed():
    return jsonify({'success': True, 'feed': threat_feed.get_combined_feed(limit=30)})

@app.route('/learning/tips')
def get_tips(): return jsonify({'success': True, 'tips': LearningCenter.get_phishing_tips()})

@app.route('/learning/types')
def get_types(): return jsonify({'success': True, 'types': LearningCenter.get_common_phishing_types()})

@app.route('/learning/actions')
def get_actions(): return jsonify({'success': True, 'actions': LearningCenter.get_what_to_do()})

@app.route('/feedback', methods=['POST'])
def feedback():
    d = request.get_json()
    ml_model.learn(d.get('subject',''), d.get('body',''), d.get('is_phishing', False))
    return jsonify({'success': True})

@app.route('/features')
def features():
    enabled_apis = []
    if API_INTEGRATIONS_ENABLED and threat_intel:
        enabled_apis = threat_intel.get_enabled_apis()
    
    return jsonify({
        'success': True,
        'features': {
            'pdf_reports': REPORTS_ENABLED,
            'qr_scanner': QR_ENABLED,
            'screenshots': SCREENSHOT_ENABLED,
            'sharing': SHARE_ENABLED,
            'api_integrations': API_INTEGRATIONS_ENABLED
        },
        'apis': enabled_apis
    })

# ============================================
# API INTEGRATION ROUTES
# ============================================
@app.route('/api/virustotal', methods=['POST'])
def check_virustotal():
    """Check URL with VirusTotal"""
    if not API_INTEGRATIONS_ENABLED or not threat_intel:
        return jsonify({'success': False, 'error': 'API integrations not available'}), 400
    
    try:
        url = request.get_json().get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'Provide URL'}), 400
        
        result = threat_intel.virustotal.scan_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/google-safe-browsing', methods=['POST'])
def check_google_safe_browsing():
    """Check URL with Google Safe Browsing"""
    if not API_INTEGRATIONS_ENABLED or not threat_intel:
        return jsonify({'success': False, 'error': 'API integrations not available'}), 400
    
    try:
        url = request.get_json().get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'Provide URL'}), 400
        
        result = threat_intel.google.check_url(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/abuseipdb', methods=['POST'])
def check_abuseipdb():
    """Check IP with AbuseIPDB"""
    if not API_INTEGRATIONS_ENABLED or not threat_intel:
        return jsonify({'success': False, 'error': 'API integrations not available'}), 400
    
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        url = data.get('url', '').strip()
        
        if ip:
            result = threat_intel.abuseipdb.check_ip(ip)
        elif url:
            result = threat_intel.abuseipdb.check_url_ip(url)
        else:
            return jsonify({'success': False, 'error': 'Provide IP or URL'}), 400
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@limiter.limit("10 per hour")
@app.route('/api/full-threat-check', methods=['POST'])
def full_threat_check():
    """Run URL through all threat intelligence APIs"""
    if not API_INTEGRATIONS_ENABLED or not threat_intel:
        return jsonify({'success': False, 'error': 'API integrations not available'}), 400
    
    try:
        url = request.get_json().get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'Provide URL'}), 400
        
        if not url.startswith('http'):
            url = 'https://' + url
        
        result = threat_intel.full_url_check(url)
        result['success'] = True
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status')
def api_status():
    """Get status of all API integrations"""
    status = {
        'virustotal': {'enabled': False, 'name': 'VirusTotal'},
        'google_safe_browsing': {'enabled': False, 'name': 'Google Safe Browsing'},
        'abuseipdb': {'enabled': False, 'name': 'AbuseIPDB'}
    }
    
    if API_INTEGRATIONS_ENABLED and threat_intel:
        status['virustotal']['enabled'] = threat_intel.virustotal.enabled
        status['google_safe_browsing']['enabled'] = threat_intel.google.enabled
        status['abuseipdb']['enabled'] = threat_intel.abuseipdb.enabled
    
    return jsonify({'success': True, 'apis': status})

# ============================================
# SCREENSHOT ROUTES
# ============================================
@app.route('/screenshot', methods=['POST'])
def capture_screenshot():
    if not SCREENSHOT_ENABLED:
        return jsonify({'success': False, 'error': 'Screenshots unavailable'}), 400
    try:
        url = request.get_json().get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'Provide URL'}), 400
        
        # Safety check first
        safety = screenshot_capture.analyze_screenshot_safety(url)
        result = screenshot_capture.capture(url)
        result['safety'] = safety
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/screenshot/thumbnail')
def get_thumbnail():
    if not SCREENSHOT_ENABLED:
        return jsonify({'success': False, 'error': 'Screenshots unavailable'}), 400
    try:
        url = request.args.get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'Provide URL'}), 400
        
        thumbnail_url = screenshot_capture.get_thumbnail_url(url)
        return jsonify({'success': True, 'thumbnail_url': thumbnail_url})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# SHARE & REPORT ROUTES
# ============================================
@app.route('/share', methods=['POST'])
def create_share():
    if not SHARE_ENABLED:
        return jsonify({'success': False, 'error': 'Sharing unavailable'}), 400
    try:
        d = request.get_json()
        report_type = d.get('type', 'url')
        data = d.get('data', {})
        
        result = share_report.save_report(report_type, data)
        
        # Generate share text
        base_url = request.host_url.rstrip('/')
        share_text = share_report.generate_share_text(report_type, data, base_url)
        
        result['share_text'] = share_text
        result['twitter_url'] = share_report.generate_twitter_share_url(share_text[:200])
        result['email_url'] = share_report.generate_email_share_url(
            'Phishing Analysis Report',
            share_text
        )
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/share/<report_id>')
def get_shared_report(report_id):
    if not SHARE_ENABLED:
        return jsonify({'success': False, 'error': 'Sharing unavailable'}), 400
    try:
        result = share_report.get_report(report_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/report-phishing', methods=['POST'])
def report_phishing():
    """Get links to report a URL to various security services"""
    try:
        url = request.get_json().get('url', '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'Provide URL'}), 400
        
        if SHARE_ENABLED:
            report_urls = share_report.get_all_report_urls(url)
        else:
            from urllib.parse import quote
            encoded_url = quote(url)
            report_urls = {
                'google_safe_browsing': f'https://safebrowsing.google.com/safebrowsing/report_phish/?url={encoded_url}',
                'phishtank': 'https://phishtank.org/add_web_phish.php',
                'microsoft': 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site',
            }
        
        return jsonify({'success': True, 'report_urls': report_urls})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api') or request.is_json:
        return jsonify({'success': False, 'error': 'Endpoint not found'}), 404
    return render_template('landing.html'), 404

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({'success': False, 'error': 'Too many requests. Please slow down and try again shortly.'}), 429

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api') or request.is_json:
        return jsonify({'success': False, 'error': 'Internal server error'}), 500
    return render_template('landing.html'), 500

# ============================================================
# ADD THESE IMPORTS at the top of app.py with other imports
# ============================================================

# from attachment_analyzer import get_attachment_analyzer
# from webhook_alerts import get_webhook_alerter

# ADD THESE after scan_history and threat_feed initialization:
# attachment_analyzer_instance = get_attachment_analyzer()
# webhook_alerter = get_webhook_alerter()


# ============================================================
# ADD THESE ROUTES to app.py
# ============================================================

# ── ATTACHMENT ANALYSIS ──────────────────────────────────────

@app.route('/analyze-attachment', methods=['POST'])
@limiter.limit("20 per hour")
def analyze_attachment():
    """Analyze an email attachment for phishing indicators."""
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400

        filename = str(d.get('filename', '') or '').strip()[:255]
        file_data = str(d.get('file_data', '') or '').strip()

        if not filename:
            return jsonify({'success': False, 'error': 'Provide a filename'}), 400
        if not file_data:
            return jsonify({'success': False, 'error': 'Provide file data'}), 400

        result = attachment_analyzer_instance.analyze_base64(filename, file_data)

        # Save to history
        if result.get('success'):
            scan_history.add_scan('attachment', filename, {
                'danger_score': result.get('risk_score', 0),
                'risk_level': result.get('risk_level', 'unknown'),
                'reasons': result.get('risk_factors', []),
                'summary': result.get('summary', '')
            })

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── WEBHOOK ALERTS ───────────────────────────────────────────

@app.route('/webhook/test', methods=['POST'])
@limiter.limit("10 per hour")
def test_webhook():
    """Test a webhook URL by sending a test message."""
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400

        webhook_url = str(d.get('webhook_url', '') or '').strip()
        if not webhook_url:
            return jsonify({'success': False, 'error': 'Provide a webhook URL'}), 400
        if not webhook_url.startswith('https://'):
            return jsonify({'success': False, 'error': 'Webhook URL must start with https://'}), 400

        result = webhook_alerter.test_webhook(webhook_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/webhook/alert', methods=['POST'])
@limiter.limit("30 per hour")
def send_webhook_alert():
    """Send a threat alert to a webhook URL."""
    try:
        d = request.get_json(silent=True)
        if not d:
            return jsonify({'success': False, 'error': 'Invalid JSON body'}), 400

        webhook_url = str(d.get('webhook_url', '') or '').strip()
        scan_type   = str(d.get('scan_type', 'unknown') or 'unknown').strip()
        target      = str(d.get('target', '') or '').strip()[:200]
        risk_level  = str(d.get('risk_level', '') or '').strip()
        risk_score  = int(d.get('risk_score', 0) or 0)
        risk_factors = d.get('risk_factors', [])

        if not webhook_url:
            return jsonify({'success': False, 'error': 'Provide a webhook URL'}), 400
        if not webhook_url.startswith('https://'):
            return jsonify({'success': False, 'error': 'Webhook URL must start with https://'}), 400

        result = webhook_alerter.send_slack_alert(
            webhook_url, scan_type, target,
            risk_level, risk_score, risk_factors
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# PREVENTION & NETWORK DEFENSE EXPORTS
# ============================================
@app.route('/api/ml-url-predict', methods=['POST'])
def api_ml_url_predict():
    """Predict phishing probability using trained URL Machine Learning model"""
    try:
        d = request.get_json(silent=True) or {}
        url = str(d.get('url', '') or '').strip()
        if not url:
            return jsonify({'success': False, 'error': 'Provide a URL'}), 400
        prob, conf, factors, features = url_ml_model.predict(url)
        return jsonify({
            'success': True,
            'url': url,
            'probability': prob,
            'confidence': conf,
            'risk_factors': factors,
            'features': features
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/export/dns-sinkhole', methods=['GET', 'POST'])
def export_dns_sinkhole():
    """Download DNS Sinkhole blocklist (Pi-hole / Unbound format)"""
    try:
        items = []
        if request.method == 'POST':
            d = request.get_json(silent=True) or {}
            items = d.get('targets', [])
        if not items:
            recent = scan_history.get_recent_scans(limit=50)
            items = [s.get('target', '') for s in recent if s.get('data', {}).get('danger_score', 0) >= 40]
            if not items:
                items = [
                    'http://login-verification-paypal-account.xyz',
                    'http://paypal-verification-secure-portal.com',
                    'http://198.51.100.12',
                    'http://accounts.google.com.security-alerts-review.top'
                ]
        content = prevention_exporter.generate_dns_sinkhole(items)
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=phtect_dns_sinkhole.txt"}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/export/hosts-blocklist', methods=['GET', 'POST'])
def export_hosts_blocklist():
    """Download OS Hosts loopback blocklist (/etc/hosts format)"""
    try:
        items = []
        if request.method == 'POST':
            d = request.get_json(silent=True) or {}
            items = d.get('targets', [])
        if not items:
            recent = scan_history.get_recent_scans(limit=50)
            items = [s.get('target', '') for s in recent if s.get('data', {}).get('danger_score', 0) >= 40]
            if not items:
                items = [
                    'http://login-verification-paypal-account.xyz',
                    'http://paypal-verification-secure-portal.com',
                    'http://accounts.google.com.security-alerts-review.top'
                ]
        content = prevention_exporter.generate_hosts_blocklist(items)
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=hosts_blocklist.txt"}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/export/snort-rules', methods=['GET', 'POST'])
def export_snort_rules():
    """Download Network IDS rules (Snort/Suricata format)"""
    try:
        items = []
        if request.method == 'POST':
            d = request.get_json(silent=True) or {}
            items = d.get('targets', [])
        if not items:
            recent = scan_history.get_recent_scans(limit=50)
            items = [s.get('target', '') for s in recent if s.get('data', {}).get('danger_score', 0) >= 40]
            if not items:
                items = [
                    'http://login-verification-paypal-account.xyz',
                    'http://paypal-verification-secure-portal.com',
                    '185.220.101.5',
                    '198.51.100.12'
                ]
        content = prevention_exporter.generate_snort_suricata_rules(items)
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment;filename=phtect_suricata.rules"}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/export/firewall-rules', methods=['GET', 'POST'])
def export_firewall_rules():
    """Download Linux packet filter drop script (iptables format)"""
    try:
        items = []
        if request.method == 'POST':
            d = request.get_json(silent=True) or {}
            items = d.get('targets', [])
        if not items:
            items = ['185.220.101.5', '198.51.100.12', '203.0.113.88']
        content = prevention_exporter.generate_firewall_rules(items)
        return Response(
            content,
            mimetype="text/x-sh",
            headers={"Content-Disposition": "attachment;filename=block_threats_iptables.sh"}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 50)
    print("🛡️ PHISHING INTELLIGENCE PLATFORM v5.0")
    print("=" * 50)
    print(f"📄 PDF Reports: {'✅' if REPORTS_ENABLED else '❌'}")
    print(f"📱 QR Scanner: {'✅' if QR_ENABLED else '❌'}")
    print(f"📸 Screenshots: {'✅' if SCREENSHOT_ENABLED else '❌'}")
    print(f"📤 Sharing: {'✅' if SHARE_ENABLED else '❌'}")
    print("-" * 50)
    print("🔌 API Integrations:")
    if API_INTEGRATIONS_ENABLED and threat_intel:
        print(f"   VirusTotal: {'✅' if threat_intel.virustotal.enabled else '❌ (add VIRUSTOTAL_API_KEY)'}")
        print(f"   Google Safe Browsing: {'✅' if threat_intel.google.enabled else '❌ (add GOOGLE_SAFE_BROWSING_KEY)'}")
        print(f"   AbuseIPDB: {'✅' if threat_intel.abuseipdb.enabled else '❌ (add ABUSEIPDB_API_KEY)'}")
    else:
        print("   ❌ API module not loaded")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
