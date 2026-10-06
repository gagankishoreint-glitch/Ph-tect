"""
Screenshot Capture Module v4
Returns direct URLs for the browser to load - no server-side fetching needed
This bypasses any server-side network restrictions
"""

from urllib.parse import quote, urlparse
import re


class ScreenshotCapture:
    """Generate screenshot URLs for browser to load directly"""
    
    def __init__(self):
        pass
    
    def capture(self, url, timeout=15):
        """
        Generate screenshot URL for the browser to load
        No server-side HTTP requests needed!
        """
        result = {
            'success': False,
            'url': url,
            'screenshot_url': None,
            'screenshot_base64': None,
            'cached': False,
            'api_used': None,
            'error': None
        }
        
        # Validate and normalize URL
        if not url.startswith('http'):
            url = 'https://' + url
        
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                result['error'] = 'Invalid URL'
                return result
        except:
            result['error'] = 'Invalid URL format'
            return result
        
        encoded_url = quote(url, safe='')
        
        # WordPress mshots is very reliable and free
        # The browser will load this URL directly
        result['success'] = True
        result['screenshot_url'] = f'https://s.wordpress.com/mshots/v1/{encoded_url}?w=1280&h=960'
        result['api_used'] = 'WordPress mshots'
        result['note'] = 'Image may take a few seconds to generate on first load'
        
        return result
    
    def get_thumbnail_url(self, url):
        """Get a direct thumbnail URL"""
        if not url.startswith('http'):
            url = 'https://' + url
        encoded_url = quote(url, safe='')
        return f'https://s.wordpress.com/mshots/v1/{encoded_url}?w=600&h=450'
    
    def analyze_screenshot_safety(self, url):
        """Analyze if URL looks suspicious"""
        warnings = []
        url_lower = url.lower()
        
        if 'login' in url_lower or 'signin' in url_lower:
            warnings.append('URL contains login page - may be phishing')
        
        if any(ext in url_lower for ext in ['.exe', '.zip', '.rar']):
            warnings.append('URL points to downloadable file')
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        for tld in suspicious_tlds:
            if tld in url_lower:
                warnings.append(f'Suspicious TLD: {tld}')
                break
        
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            warnings.append('URL uses IP address instead of domain')
        
        return {
            'safe_to_preview': len(warnings) == 0,
            'warnings': warnings
        }


_screenshot_capture = None

def get_screenshot_capture():
    global _screenshot_capture
    if _screenshot_capture is None:
        _screenshot_capture = ScreenshotCapture()
    return _screenshot_capture
