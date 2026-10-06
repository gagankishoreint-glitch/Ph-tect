"""
QR Code Scanner Module
Uses OpenCV's built-in QR code detector - no external libraries needed
"""

import cv2
import numpy as np
from PIL import Image
import io
import base64
import re


class QRCodeScanner:
    """QR Scanner using OpenCV's built-in QRCodeDetector"""
    
    def __init__(self):
        self.detector = cv2.QRCodeDetector()
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
    
    def decode_qr_from_base64(self, base64_string):
        """Decode QR code from base64 image string"""
        try:
            # Remove data URL prefix if present
            if 'base64,' in base64_string:
                base64_string = base64_string.split('base64,')[1]
            
            # Decode base64 to bytes
            image_bytes = base64.b64decode(base64_string)
            
            # Convert to PIL Image then to OpenCV format
            pil_image = Image.open(io.BytesIO(image_bytes))
            
            # Convert to RGB if necessary
            if pil_image.mode != 'RGB':
                pil_image = pil_image.convert('RGB')
            
            # Convert PIL to OpenCV format (numpy array)
            cv_image = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            
            return self._decode_image(cv_image)
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to process image: {str(e)}'
            }
    
    def _decode_image(self, cv_image):
        """Decode QR code from OpenCV image"""
        results = []
        
        # Method 1: Direct detection
        data, points, _ = self.detector.detectAndDecode(cv_image)
        if data:
            results.append(self._process_qr_data(data))
        
        # Method 2: Try with grayscale if no results
        if not results:
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            data, points, _ = self.detector.detectAndDecode(gray)
            if data:
                results.append(self._process_qr_data(data))
        
        # Method 3: Try with threshold
        if not results:
            _, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
            data, points, _ = self.detector.detectAndDecode(thresh)
            if data:
                results.append(self._process_qr_data(data))
        
        # Method 4: Try with adaptive threshold
        if not results:
            adaptive = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, 11, 2
            )
            data, points, _ = self.detector.detectAndDecode(adaptive)
            if data:
                results.append(self._process_qr_data(data))
        
        # Method 5: Try with contrast enhancement
        if not results:
            enhanced = cv2.equalizeHist(gray)
            data, points, _ = self.detector.detectAndDecode(enhanced)
            if data:
                results.append(self._process_qr_data(data))
        
        if not results:
            return {
                'success': False,
                'error': 'No QR code found in image. Please ensure the QR code is clear, well-lit, and not blurry.'
            }
        
        return {
            'success': True,
            'count': len(results),
            'results': results
        }
    
    def _process_qr_data(self, data):
        """Process decoded QR data"""
        is_url = bool(self.url_pattern.match(data))
        analysis = self._analyze_qr_content(data)
        
        return {
            'data': data,
            'type': 'QRCODE',
            'is_url': is_url,
            'analysis': analysis
        }
    
    def _analyze_qr_content(self, data):
        """Analyze QR code content for suspicious patterns"""
        analysis = {
            'content_type': 'unknown',
            'risk_indicators': [],
            'preliminary_risk': 'low'
        }
        
        data_lower = data.lower()
        
        # Determine content type
        if self.url_pattern.match(data):
            analysis['content_type'] = 'url'
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                ('http://', 'Uses insecure HTTP protocol'),
                ('bit.ly', 'Uses URL shortener (bit.ly)'),
                ('tinyurl', 'Uses URL shortener (tinyurl)'),
                ('t.co', 'Uses URL shortener (t.co)'),
                ('goo.gl', 'Uses URL shortener (goo.gl)'),
                ('.xyz', 'Suspicious TLD (.xyz)'),
                ('.top', 'Suspicious TLD (.top)'),
                ('.club', 'Suspicious TLD (.club)'),
                ('.tk', 'Free/suspicious TLD (.tk)'),
                ('.ml', 'Free/suspicious TLD (.ml)'),
                ('.ga', 'Free/suspicious TLD (.ga)'),
                ('login', 'Contains "login" - may be credential harvesting'),
                ('verify', 'Contains "verify" - common phishing keyword'),
                ('secure-', 'Contains "secure-" - potential brand impersonation'),
                ('account-', 'Contains "account-" - potential brand impersonation'),
                ('update-', 'Contains "update-" - potential brand impersonation'),
                ('paypal', 'References PayPal - verify authenticity'),
                ('amazon', 'References Amazon - verify authenticity'),
                ('microsoft', 'References Microsoft - verify authenticity'),
                ('apple', 'References Apple - verify authenticity'),
                ('google', 'References Google - verify authenticity'),
                ('bank', 'References banking - verify authenticity'),
                ('netflix', 'References Netflix - verify authenticity'),
            ]
            
            for pattern, message in suspicious_patterns:
                if pattern in data_lower:
                    analysis['risk_indicators'].append(message)
            
            # Check for IP address instead of domain
            ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            if re.match(ip_pattern, data):
                analysis['risk_indicators'].append('Uses IP address instead of domain name')
            
            # Check for excessive subdomains
            try:
                from urllib.parse import urlparse
                parsed = urlparse(data)
                subdomain_count = parsed.netloc.count('.')
                if subdomain_count > 3:
                    analysis['risk_indicators'].append(f'Excessive subdomains ({subdomain_count} levels)')
            except:
                pass
                
        elif data.startswith('tel:') or data.startswith('TEL:'):
            analysis['content_type'] = 'phone'
        elif data.startswith('mailto:') or data.startswith('MAILTO:'):
            analysis['content_type'] = 'email'
        elif data.startswith('WIFI:'):
            analysis['content_type'] = 'wifi'
            analysis['risk_indicators'].append('WiFi configuration - be cautious connecting to unknown networks')
        elif data.startswith('BEGIN:VCARD'):
            analysis['content_type'] = 'contact'
        elif data.startswith('bitcoin:') or data.startswith('ethereum:'):
            analysis['content_type'] = 'cryptocurrency'
            analysis['risk_indicators'].append('Cryptocurrency address - verify before sending funds')
        elif data.startswith('sms:') or data.startswith('SMS:'):
            analysis['content_type'] = 'sms'
        else:
            analysis['content_type'] = 'text'
        
        # Determine preliminary risk level
        if len(analysis['risk_indicators']) >= 3:
            analysis['preliminary_risk'] = 'high'
        elif len(analysis['risk_indicators']) >= 1:
            analysis['preliminary_risk'] = 'medium'
        else:
            analysis['preliminary_risk'] = 'low'
        
        return analysis


def get_qr_scanner():
    """Get QR scanner instance"""
    return QRCodeScanner()
