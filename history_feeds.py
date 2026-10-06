"""
Scan History and Threat Feed Module
Store scan history and fetch real phishing threat data
"""

import json
import os
import datetime
import hashlib
import requests
from collections import defaultdict
import xml.etree.ElementTree as ET


class ScanHistory:
    """Manage scan history with local storage"""
    
    def __init__(self, storage_file='scan_history.json'):
        self.storage_file = storage_file
        self.history = self._load_history()
    
    def _load_history(self):
        """Load history from file"""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            except:
                return {'scans': [], 'stats': {}}
        return {'scans': [], 'stats': {}}
    
    def _save_history(self):
        """Save history to file"""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(self.history, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving history: {e}")
    
    def add_scan(self, scan_type, target, result):
        """Add a new scan to history"""
        scan_id = hashlib.md5(
            f"{scan_type}{target}{datetime.datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]
        
        scan_entry = {
            'id': scan_id,
            'type': scan_type,  # 'email' or 'url'
            'target': target[:100],  # Truncate for storage
            'timestamp': datetime.datetime.now().isoformat(),
            'risk_score': result.get('danger_score', 0),
            'risk_level': result.get('risk_level', 'unknown'),
            'findings_count': len(result.get('reasons', [])),
            'summary': result.get('summary', result.get('advice', ''))[:200]
        }
        
        # Add to beginning of list (most recent first)
        self.history['scans'].insert(0, scan_entry)
        
        # Keep only last 100 scans
        self.history['scans'] = self.history['scans'][:100]
        
        # Update stats
        self._update_stats(scan_entry)
        
        self._save_history()
        
        return scan_id
    
    def _update_stats(self, scan_entry):
        """Update statistics"""
        if 'stats' not in self.history:
            self.history['stats'] = {}
        
        stats = self.history['stats']
        
        # Total scans
        stats['total_scans'] = stats.get('total_scans', 0) + 1
        
        # Scans by type
        if 'by_type' not in stats:
            stats['by_type'] = {}
        scan_type = scan_entry['type']
        stats['by_type'][scan_type] = stats['by_type'].get(scan_type, 0) + 1
        
        # Scans by risk level
        if 'by_risk' not in stats:
            stats['by_risk'] = {}
        risk_level = scan_entry['risk_level'].lower()
        stats['by_risk'][risk_level] = stats['by_risk'].get(risk_level, 0) + 1
        
        # High risk count
        if risk_level in ['high', 'critical', 'very high risk', 'critical threat']:
            stats['high_risk_count'] = stats.get('high_risk_count', 0) + 1
        
        # Last scan timestamp
        stats['last_scan'] = scan_entry['timestamp']
    
    def get_recent_scans(self, limit=20, scan_type=None):
        """Get recent scans"""
        scans = self.history.get('scans', [])
        
        if scan_type:
            scans = [s for s in scans if s['type'] == scan_type]
        
        return scans[:limit]
    
    def get_stats(self):
        """Get scan statistics"""
        return self.history.get('stats', {})
    
    def search_scans(self, query):
        """Search scans by target"""
        query = query.lower()
        return [
            s for s in self.history.get('scans', [])
            if query in s.get('target', '').lower()
        ]
    
    def get_scan_by_id(self, scan_id):
        """Get specific scan by ID"""
        for scan in self.history.get('scans', []):
            if scan.get('id') == scan_id:
                return scan
        return None
    
    def get_high_risk_scans(self, limit=10):
        """Get recent high-risk scans"""
        high_risk_levels = ['high', 'critical', 'very high risk', 'critical threat']
        high_risk = [
            s for s in self.history.get('scans', [])
            if s.get('risk_level', '').lower() in high_risk_levels
        ]
        return high_risk[:limit]
    
    def clear_history(self):
        """Clear all history"""
        self.history = {'scans': [], 'stats': {}}
        self._save_history()


class ThreatFeed:
    """Fetch real-time threat intelligence feeds"""
    
    def __init__(self):
        self.cache = {}
        self.cache_duration = 3600  # 1 hour
    
    def _is_cache_valid(self, key):
        """Check if cache is still valid"""
        if key not in self.cache:
            return False
        
        cached_time = self.cache[key].get('timestamp', 0)
        return (datetime.datetime.now().timestamp() - cached_time) < self.cache_duration
    
    def get_phishtank_feed(self, limit=20):
        """Get recent phishing URLs from PhishTank (requires API key for full access)"""
        cache_key = 'phishtank'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        # Note: Full PhishTank API requires registration
        # This returns sample/demo data
        sample_feed = {
            'source': 'PhishTank (Demo)',
            'updated': datetime.datetime.now().isoformat(),
            'note': 'Register at phishtank.org for full API access',
            'items': [
                {
                    'url': 'http://example-phish-1.com/login',
                    'target': 'PayPal',
                    'submitted': '2024-01-15',
                    'verified': True
                },
                {
                    'url': 'http://secure-bank-verify.tk/account',
                    'target': 'Banking',
                    'submitted': '2024-01-14',
                    'verified': True
                },
                {
                    'url': 'http://amaz0n-secure.xyz/signin',
                    'target': 'Amazon',
                    'submitted': '2024-01-14',
                    'verified': True
                }
            ]
        }
        
        self.cache[cache_key] = {
            'timestamp': datetime.datetime.now().timestamp(),
            'data': sample_feed
        }
        
        return sample_feed
    
    def get_openphish_feed(self, limit=20):
        """Get recent phishing URLs from OpenPhish community feed"""
        cache_key = 'openphish'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        feed_data = {
            'source': 'OpenPhish Community',
            'updated': datetime.datetime.now().isoformat(),
            'items': []
        }
        
        try:
            # OpenPhish community feed (free, updated every 12 hours)
            response = requests.get(
                'https://openphish.com/feed.txt',
                timeout=10
            )
            
            if response.status_code == 200:
                urls = response.text.strip().split('\n')
                
                for url in urls[:limit]:
                    if url.strip():
                        feed_data['items'].append({
                            'url': url.strip(),
                            'target': self._guess_target(url),
                            'source': 'OpenPhish'
                        })
                        
        except Exception as e:
            feed_data['error'] = str(e)
            feed_data['note'] = 'Could not fetch live feed'
        
        self.cache[cache_key] = {
            'timestamp': datetime.datetime.now().timestamp(),
            'data': feed_data
        }
        
        return feed_data
    
    def get_urlhaus_feed(self, limit=20):
        """Get recent malware URLs from URLhaus"""
        cache_key = 'urlhaus'
        
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]['data']
        
        feed_data = {
            'source': 'URLhaus (abuse.ch)',
            'updated': datetime.datetime.now().isoformat(),
            'items': []
        }
        
        try:
            # URLhaus recent additions API
            response = requests.get(
                'https://urlhaus-api.abuse.ch/v1/urls/recent/',
                timeout=10,
                headers={'Accept': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('query_status') == 'ok':
                    for item in data.get('urls', [])[:limit]:
                        feed_data['items'].append({
                            'url': item.get('url', ''),
                            'threat_type': item.get('threat', 'malware'),
                            'status': item.get('url_status', 'unknown'),
                            'added': item.get('date_added', ''),
                            'tags': item.get('tags', [])
                        })
                        
        except Exception as e:
            feed_data['error'] = str(e)
            feed_data['note'] = 'Could not fetch live feed'
        
        self.cache[cache_key] = {
            'timestamp': datetime.datetime.now().timestamp(),
            'data': feed_data
        }
        
        return feed_data
    
    def get_combined_feed(self, limit=30):
        """Get combined threat feed from multiple sources"""
        combined = {
            'updated': datetime.datetime.now().isoformat(),
            'sources': [],
            'items': []
        }
        
        # Try OpenPhish
        openphish = self.get_openphish_feed(limit=limit//2)
        if openphish.get('items'):
            combined['sources'].append('OpenPhish')
            for item in openphish['items']:
                item['source'] = 'OpenPhish'
                item['threat_type'] = 'phishing'
                combined['items'].append(item)
        
        # Try URLhaus
        urlhaus = self.get_urlhaus_feed(limit=limit//2)
        if urlhaus.get('items'):
            combined['sources'].append('URLhaus')
            for item in urlhaus['items']:
                item['source'] = 'URLhaus'
                combined['items'].append(item)
        
        # Sort by most recent if possible
        combined['total_items'] = len(combined['items'])
        
        return combined
    
    def _guess_target(self, url):
        """Guess the target brand from URL"""
        url_lower = url.lower()
        
        brands = {
            'paypal': 'PayPal',
            'amazon': 'Amazon',
            'apple': 'Apple',
            'microsoft': 'Microsoft',
            'google': 'Google',
            'facebook': 'Facebook',
            'netflix': 'Netflix',
            'bank': 'Banking',
            'chase': 'Chase Bank',
            'wellsfargo': 'Wells Fargo',
            'instagram': 'Instagram',
            'linkedin': 'LinkedIn',
            'dropbox': 'Dropbox',
            'office365': 'Office 365',
            'outlook': 'Microsoft Outlook'
        }
        
        for key, brand in brands.items():
            if key in url_lower:
                return brand
        
        return 'Unknown'
    
    def check_url_in_feeds(self, url):
        """Check if a URL appears in threat feeds"""
        result = {
            'found': False,
            'sources': []
        }
        
        # Normalize URL for comparison
        url_lower = url.lower().strip()
        
        # Check OpenPhish
        openphish = self.get_openphish_feed(limit=100)
        for item in openphish.get('items', []):
            if url_lower in item.get('url', '').lower():
                result['found'] = True
                result['sources'].append({
                    'name': 'OpenPhish',
                    'threat_type': 'phishing'
                })
                break
        
        # Check URLhaus
        urlhaus = self.get_urlhaus_feed(limit=100)
        for item in urlhaus.get('items', []):
            if url_lower in item.get('url', '').lower():
                result['found'] = True
                result['sources'].append({
                    'name': 'URLhaus',
                    'threat_type': item.get('threat_type', 'malware')
                })
                break
        
        return result


class LearningCenter:
    """Educational content about phishing"""
    
    @staticmethod
    def get_phishing_tips():
        """Get tips for identifying phishing"""
        return [
            {
                'title': 'Check the Sender',
                'description': 'Verify the sender\'s email address carefully. Phishers often use addresses that look similar to legitimate ones.',
                'example': 'support@paypa1.com vs support@paypal.com'
            },
            {
                'title': 'Look for Urgency',
                'description': 'Phishing emails often create a sense of urgency to make you act without thinking.',
                'example': '"Your account will be suspended in 24 hours!"'
            },
            {
                'title': 'Hover Over Links',
                'description': 'Before clicking, hover over links to see the actual URL destination.',
                'example': 'Link text says "PayPal" but URL goes to a different domain'
            },
            {
                'title': 'Check for HTTPS',
                'description': 'Legitimate sites use HTTPS, but phishing sites may not. However, some phishing sites do use HTTPS.',
                'example': 'Look for the padlock icon, but don\'t rely on it alone'
            },
            {
                'title': 'Beware of Attachments',
                'description': 'Unexpected attachments, especially executables, PDFs, or Office documents with macros can be dangerous.',
                'example': 'invoice.pdf.exe is not a PDF!'
            },
            {
                'title': 'Generic Greetings',
                'description': 'Legitimate companies usually address you by name, not "Dear Customer" or "Dear User".',
                'example': '"Dear Valued Customer" vs "Dear John Smith"'
            },
            {
                'title': 'Grammar and Spelling',
                'description': 'Professional companies proofread their emails. Multiple errors may indicate phishing.',
                'example': 'Obvious typos and grammatical mistakes'
            },
            {
                'title': 'Too Good to Be True',
                'description': 'Offers that seem too good (lottery wins, unexpected refunds) are usually scams.',
                'example': '"You\'ve won $1,000,000!"'
            }
        ]
    
    @staticmethod
    def get_common_phishing_types():
        """Get information about common phishing types"""
        return [
            {
                'type': 'Email Phishing',
                'description': 'Mass emails impersonating legitimate organizations',
                'targets': 'General public',
                'indicators': ['Generic greeting', 'Urgent tone', 'Suspicious links']
            },
            {
                'type': 'Spear Phishing',
                'description': 'Targeted attacks using personal information',
                'targets': 'Specific individuals or organizations',
                'indicators': ['Uses your name', 'References real events', 'Appears to be from a colleague']
            },
            {
                'type': 'Whaling',
                'description': 'Spear phishing targeting executives',
                'targets': 'CEOs, CFOs, high-level executives',
                'indicators': ['Requests wire transfers', 'Urgent business matters', 'From "CEO"']
            },
            {
                'type': 'Smishing (SMS)',
                'description': 'Phishing via text messages',
                'targets': 'Mobile phone users',
                'indicators': ['Short links', 'Urgent requests', 'Unknown numbers']
            },
            {
                'type': 'Vishing (Voice)',
                'description': 'Phishing via phone calls',
                'targets': 'Anyone with a phone',
                'indicators': ['Caller ID spoofing', 'Pressure tactics', 'Requests for sensitive info']
            },
            {
                'type': 'QR Code Phishing (Quishing)',
                'description': 'Malicious QR codes leading to phishing sites',
                'targets': 'Mobile device users',
                'indicators': ['QR codes in unexpected places', 'Covering legitimate QR codes']
            }
        ]
    
    @staticmethod
    def get_what_to_do():
        """Get guidance on what to do if you suspect phishing"""
        return {
            'if_received': [
                'Do not click any links or download attachments',
                'Do not reply to the email',
                'Report the email as phishing in your email client',
                'Forward to your IT security team if at work',
                'Delete the email after reporting'
            ],
            'if_clicked': [
                'Disconnect from the internet immediately',
                'Change passwords for any accounts that may be affected',
                'Enable two-factor authentication',
                'Run a full antivirus scan',
                'Monitor your accounts for suspicious activity',
                'Report to your IT department and relevant authorities'
            ],
            'if_entered_info': [
                'Change your password immediately',
                'Enable two-factor authentication',
                'Contact your bank if financial info was shared',
                'Place a fraud alert on your credit reports',
                'Monitor all accounts for unauthorized access',
                'Report identity theft to authorities'
            ]
        }
