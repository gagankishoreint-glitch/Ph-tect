"""
API Integrations Module
Connects to external threat intelligence APIs for enhanced detection

APIs Supported:
- VirusTotal: Scans URLs against 70+ antivirus engines
- Google Safe Browsing: Checks Google's malware/phishing database
- AbuseIPDB: Checks if IP addresses are reported for abuse
"""

import requests
import os
import hashlib
import base64
from urllib.parse import urlparse
import socket


class VirusTotalAPI:
    """
    VirusTotal API Integration
    Free tier: 500 requests/day, 4 requests/minute
    """
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.enabled = bool(self.api_key)
    
    def scan_url(self, url):
        """
        Submit URL for scanning and get results
        Returns: dict with scan results
        """
        if not self.enabled:
            return {'success': False, 'error': 'VirusTotal API key not configured'}
        
        try:
            # First, get URL ID (base64 encoded URL without padding)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            
            # Try to get existing analysis first
            headers = {'x-apikey': self.api_key}
            response = requests.get(
                f'{self.base_url}/urls/{url_id}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_url_report(data)
            
            elif response.status_code == 404:
                # URL not in database, submit for scanning
                return self._submit_url_for_scan(url)
            
            else:
                return {
                    'success': False,
                    'error': f'VirusTotal API error: {response.status_code}'
                }
                
        except requests.Timeout:
            return {'success': False, 'error': 'VirusTotal request timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _submit_url_for_scan(self, url):
        """Submit URL for new scan"""
        try:
            headers = {
                'x-apikey': self.api_key,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            response = requests.post(
                f'{self.base_url}/urls',
                headers=headers,
                data={'url': url},
                timeout=10
            )
            
            if response.status_code == 200:
                return {
                    'success': True,
                    'status': 'submitted',
                    'message': 'URL submitted for scanning. Results will be available shortly.',
                    'malicious': 0,
                    'suspicious': 0,
                    'clean': 0
                }
            else:
                return {'success': False, 'error': 'Failed to submit URL for scanning'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _parse_url_report(self, data):
        """Parse VirusTotal URL report"""
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            clean = stats.get('harmless', 0) + stats.get('undetected', 0)
            total = malicious + suspicious + clean
            
            # Calculate threat score (0-100)
            if total > 0:
                threat_score = int((malicious * 100 + suspicious * 50) / total)
            else:
                threat_score = 0
            
            return {
                'success': True,
                'status': 'completed',
                'malicious': malicious,
                'suspicious': suspicious,
                'clean': clean,
                'total_engines': total,
                'threat_score': min(threat_score, 100),
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {}),
                'last_analysis_date': attributes.get('last_analysis_date')
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Failed to parse report: {str(e)}'}


class GoogleSafeBrowsingAPI:
    """
    Google Safe Browsing API Integration
    Free tier: 10,000 requests/day
    """
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('GOOGLE_SAFE_BROWSING_KEY')
        self.base_url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        self.enabled = bool(self.api_key)
    
    def check_url(self, url):
        """
        Check URL against Google Safe Browsing database
        Returns: dict with threat info
        """
        if not self.enabled:
            return {'success': False, 'error': 'Google Safe Browsing API key not configured'}
        
        try:
            payload = {
                'client': {
                    'clientId': 'phishing-intelligence-platform',
                    'clientVersion': '5.0'
                },
                'threatInfo': {
                    'threatTypes': [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes': ['ANY_PLATFORM'],
                    'threatEntryTypes': ['URL'],
                    'threatEntries': [{'url': url}]
                }
            }
            
            response = requests.post(
                f'{self.base_url}?key={self.api_key}',
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
                
                if matches:
                    threats = []
                    for match in matches:
                        threat_type = match.get('threatType', 'UNKNOWN')
                        threats.append(self._format_threat_type(threat_type))
                    
                    return {
                        'success': True,
                        'is_safe': False,
                        'threats': threats,
                        'threat_count': len(matches),
                        'message': f'⚠️ Google detected {len(matches)} threat(s)'
                    }
                else:
                    return {
                        'success': True,
                        'is_safe': True,
                        'threats': [],
                        'threat_count': 0,
                        'message': '✅ Not found in Google Safe Browsing database'
                    }
            
            elif response.status_code == 400:
                return {'success': False, 'error': 'Invalid request to Google Safe Browsing'}
            else:
                return {'success': False, 'error': f'Google API error: {response.status_code}'}
                
        except requests.Timeout:
            return {'success': False, 'error': 'Google Safe Browsing request timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _format_threat_type(self, threat_type):
        """Convert threat type to readable format"""
        types = {
            'MALWARE': '🦠 Malware',
            'SOCIAL_ENGINEERING': '🎣 Phishing/Social Engineering',
            'UNWANTED_SOFTWARE': '⚠️ Unwanted Software',
            'POTENTIALLY_HARMFUL_APPLICATION': '🚫 Potentially Harmful App'
        }
        return types.get(threat_type, threat_type)


class AbuseIPDBAPI:
    """
    AbuseIPDB API Integration
    Free tier: 1,000 requests/day
    """
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('ABUSEIPDB_API_KEY')
        self.base_url = 'https://api.abuseipdb.com/api/v2'
        self.enabled = bool(self.api_key)
    
    def check_ip(self, ip_address):
        """
        Check IP address for abuse reports
        Returns: dict with abuse info
        """
        if not self.enabled:
            return {'success': False, 'error': 'AbuseIPDB API key not configured'}
        
        try:
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = requests.get(
                f'{self.base_url}/check',
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                abuse_score = data.get('abuseConfidenceScore', 0)
                total_reports = data.get('totalReports', 0)
                
                return {
                    'success': True,
                    'ip_address': ip_address,
                    'abuse_score': abuse_score,
                    'total_reports': total_reports,
                    'is_public': data.get('isPublic', True),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country': data.get('countryCode', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'domain': data.get('domain', ''),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'is_tor': data.get('isTor', False),
                    'risk_level': self._calculate_risk_level(abuse_score, total_reports)
                }
            
            elif response.status_code == 422:
                return {'success': False, 'error': 'Invalid IP address'}
            else:
                return {'success': False, 'error': f'AbuseIPDB error: {response.status_code}'}
                
        except requests.Timeout:
            return {'success': False, 'error': 'AbuseIPDB request timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def check_url_ip(self, url):
        """
        Resolve URL to IP and check it
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Resolve domain to IP
            ip_address = socket.gethostbyname(domain)
            
            result = self.check_ip(ip_address)
            result['domain'] = domain
            result['resolved_ip'] = ip_address
            
            return result
            
        except socket.gaierror:
            return {'success': False, 'error': 'Could not resolve domain to IP'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _calculate_risk_level(self, abuse_score, total_reports):
        """Calculate risk level based on abuse data"""
        if abuse_score >= 80 or total_reports >= 50:
            return 'CRITICAL'
        elif abuse_score >= 50 or total_reports >= 20:
            return 'HIGH'
        elif abuse_score >= 25 or total_reports >= 5:
            return 'MEDIUM'
        elif abuse_score > 0 or total_reports > 0:
            return 'LOW'
        else:
            return 'CLEAN'


class ThreatIntelligence:
    """
    Combined threat intelligence from all APIs
    """
    
    def __init__(self, virustotal_key=None, google_key=None, abuseipdb_key=None):
        self.virustotal = VirusTotalAPI(virustotal_key)
        self.google = GoogleSafeBrowsingAPI(google_key)
        self.abuseipdb = AbuseIPDBAPI(abuseipdb_key)
    
    def get_enabled_apis(self):
        """Get list of enabled APIs"""
        enabled = []
        if self.virustotal.enabled:
            enabled.append('VirusTotal')
        if self.google.enabled:
            enabled.append('Google Safe Browsing')
        if self.abuseipdb.enabled:
            enabled.append('AbuseIPDB')
        return enabled
    
    def full_url_check(self, url):
        """
        Run URL through all available threat intelligence APIs
        Returns: combined results
        """
        results = {
            'url': url,
            'apis_checked': [],
            'overall_threat_score': 0,
            'overall_risk_level': 'UNKNOWN',
            'threats_found': [],
            'details': {}
        }
        
        threat_scores = []
        
        # Check VirusTotal
        if self.virustotal.enabled:
            vt_result = self.virustotal.scan_url(url)
            results['details']['virustotal'] = vt_result
            results['apis_checked'].append('VirusTotal')
            
            if vt_result.get('success') and vt_result.get('status') == 'completed':
                threat_scores.append(vt_result.get('threat_score', 0))
                if vt_result.get('malicious', 0) > 0:
                    results['threats_found'].append(
                        f"VirusTotal: {vt_result['malicious']} engines detected as malicious"
                    )
        
        # Check Google Safe Browsing
        if self.google.enabled:
            google_result = self.google.check_url(url)
            results['details']['google_safe_browsing'] = google_result
            results['apis_checked'].append('Google Safe Browsing')
            
            if google_result.get('success') and not google_result.get('is_safe', True):
                threat_scores.append(90)  # High score for Google flagged URLs
                for threat in google_result.get('threats', []):
                    results['threats_found'].append(f"Google: {threat}")
        
        # Check AbuseIPDB (resolve URL to IP first)
        if self.abuseipdb.enabled:
            abuse_result = self.abuseipdb.check_url_ip(url)
            results['details']['abuseipdb'] = abuse_result
            results['apis_checked'].append('AbuseIPDB')
            
            if abuse_result.get('success'):
                abuse_score = abuse_result.get('abuse_score', 0)
                if abuse_score > 0:
                    threat_scores.append(abuse_score)
                    results['threats_found'].append(
                        f"AbuseIPDB: IP has {abuse_score}% abuse confidence score"
                    )
        
        # Calculate overall threat score
        if threat_scores:
            results['overall_threat_score'] = max(threat_scores)  # Use highest score
        
        # Determine risk level
        score = results['overall_threat_score']
        if score >= 80:
            results['overall_risk_level'] = 'CRITICAL'
        elif score >= 60:
            results['overall_risk_level'] = 'HIGH'
        elif score >= 40:
            results['overall_risk_level'] = 'MEDIUM'
        elif score >= 20:
            results['overall_risk_level'] = 'LOW'
        else:
            results['overall_risk_level'] = 'CLEAN'
        
        return results


# Singleton instances
_threat_intel = None

def get_threat_intelligence():
    """Get or create ThreatIntelligence instance"""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel
