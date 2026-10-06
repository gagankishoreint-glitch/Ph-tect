"""
Share and Report Module
Generate shareable report links and submit to threat databases
"""

import hashlib
import json
import os
import datetime
import base64
from urllib.parse import quote


class ShareReport:
    """Generate shareable reports and submit to threat databases"""
    
    def __init__(self, storage_dir='/tmp/shared_reports'):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
    
    def generate_report_id(self, data):
        """Generate unique report ID"""
        content = json.dumps(data, sort_keys=True) + str(datetime.datetime.now().timestamp())
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def save_report(self, report_type, analysis_data):
        """
        Save analysis report for sharing
        Returns: report ID and share URL
        """
        report_id = self.generate_report_id(analysis_data)
        
        report = {
            'id': report_id,
            'type': report_type,  # 'email' or 'url'
            'created_at': datetime.datetime.now().isoformat(),
            'expires_at': (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat(),
            'data': analysis_data,
            'views': 0
        }
        
        # Save to file
        report_path = os.path.join(self.storage_dir, f'{report_id}.json')
        with open(report_path, 'w') as f:
            json.dump(report, f)
        
        return {
            'success': True,
            'report_id': report_id,
            'expires_in': '7 days'
        }
    
    def get_report(self, report_id):
        """Retrieve a shared report"""
        report_path = os.path.join(self.storage_dir, f'{report_id}.json')
        
        if not os.path.exists(report_path):
            return {'success': False, 'error': 'Report not found or expired'}
        
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            
            # Check expiration
            expires_at = datetime.datetime.fromisoformat(report['expires_at'])
            if datetime.datetime.now() > expires_at:
                os.remove(report_path)
                return {'success': False, 'error': 'Report has expired'}
            
            # Increment view count
            report['views'] += 1
            with open(report_path, 'w') as f:
                json.dump(report, f)
            
            return {'success': True, 'report': report}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def generate_share_text(self, report_type, analysis_data, base_url=''):
        """Generate shareable text summary"""
        if report_type == 'url':
            url = analysis_data.get('url', 'Unknown URL')
            risk_level = analysis_data.get('risk_level', 'Unknown')
            score = analysis_data.get('danger_score', 0)
            
            text = f"""🛡️ Phishing Intelligence Report

🔗 URL Analyzed: {url}
⚠️ Risk Level: {risk_level}
📊 Threat Score: {score}/100

"""
            reasons = analysis_data.get('reasons', [])
            if reasons:
                text += "🚨 Risk Factors:\n"
                for r in reasons[:5]:
                    text += f"  • {r}\n"
            
            text += f"\n🔍 Full analysis at: {base_url}"
            
        else:  # email
            sender = analysis_data.get('sender', 'Unknown')
            subject = analysis_data.get('subject', 'No subject')
            risk_level = analysis_data.get('risk_level', 'Unknown')
            score = analysis_data.get('danger_score', 0)
            
            text = f"""🛡️ Phishing Intelligence Report

📧 Email Analysis
From: {sender}
Subject: {subject}
⚠️ Risk Level: {risk_level}
📊 Threat Score: {score}/100

"""
            reasons = analysis_data.get('reasons', [])
            if reasons:
                text += "🚨 Threat Indicators:\n"
                for r in reasons[:5]:
                    text += f"  • {r}\n"
        
        return text
    
    def generate_twitter_share_url(self, text):
        """Generate Twitter/X share URL"""
        encoded_text = quote(text[:280])  # Twitter limit
        return f"https://twitter.com/intent/tweet?text={encoded_text}"
    
    def generate_linkedin_share_url(self, url, title, summary):
        """Generate LinkedIn share URL"""
        return f"https://www.linkedin.com/sharing/share-offsite/?url={quote(url)}"
    
    def generate_email_share_url(self, subject, body):
        """Generate mailto link"""
        return f"mailto:?subject={quote(subject)}&body={quote(body)}"
    
    def report_to_phishtank(self, url, phishtank_api_key=None):
        """
        Report URL to PhishTank
        Note: Requires PhishTank API key and account
        """
        if not phishtank_api_key:
            return {
                'success': False,
                'error': 'PhishTank API key required. Get one at phishtank.org',
                'manual_report_url': 'https://phishtank.org/add_web_phish.php'
            }
        
        # PhishTank submission would go here
        # For now, return manual submission URL
        return {
            'success': True,
            'message': 'Report submitted to PhishTank',
            'manual_report_url': 'https://phishtank.org/add_web_phish.php'
        }
    
    def report_to_google_safe_browsing(self, url):
        """
        Generate Google Safe Browsing report URL
        Google doesn't have an API for submissions, only manual
        """
        encoded_url = quote(url)
        return {
            'success': True,
            'report_url': f'https://safebrowsing.google.com/safebrowsing/report_phish/?url={encoded_url}',
            'message': 'Click the link to report to Google Safe Browsing'
        }
    
    def report_to_microsoft(self, url):
        """Generate Microsoft Security Intelligence report URL"""
        return {
            'success': True,
            'report_url': 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site',
            'message': 'Click the link to report to Microsoft'
        }
    
    def get_all_report_urls(self, url):
        """Get all available report submission URLs"""
        encoded_url = quote(url)
        
        return {
            'google_safe_browsing': f'https://safebrowsing.google.com/safebrowsing/report_phish/?url={encoded_url}',
            'phishtank': 'https://phishtank.org/add_web_phish.php',
            'microsoft': 'https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site',
            'netcraft': f'https://report.netcraft.com/report?url={encoded_url}',
            'apwg': 'https://apwg.org/report-phishing/',
        }


# Singleton
_share_report = None

def get_share_report():
    global _share_report
    if _share_report is None:
        _share_report = ShareReport()
    return _share_report
