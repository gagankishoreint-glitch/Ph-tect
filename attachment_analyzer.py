"""
Attachment Analyzer Module
==========================
Analyzes email attachments (PDF, Word, Excel) for phishing indicators.
No external API needed — uses python-magic, zipfile, and pattern matching.
"""

import os
import re
import zipfile
import hashlib
import base64
from io import BytesIO


# Dangerous file extensions
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
    '.jar', '.ps1', '.psm1', '.reg', '.dll', '.msi', '.hta'
}

# Suspicious extensions (need content analysis)
SUSPICIOUS_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.iso', '.img'
}

# Macro indicators in Office documents
MACRO_PATTERNS = [
    b'vbaProject.bin',
    b'word/vbaProject',
    b'xl/vbaProject',
    b'AutoOpen',
    b'AutoExec',
    b'Auto_Open',
    b'Document_Open',
    b'Workbook_Open',
    b'Shell(',
    b'WScript.Shell',
    b'CreateObject',
    b'powershell',
    b'cmd.exe',
    b'base64',
    b'URLDownloadToFile',
    b'WinHttpRequest',
]

# Suspicious PDF patterns
PDF_PATTERNS = [
    b'/JavaScript',
    b'/JS',
    b'/Launch',
    b'/OpenAction',
    b'/AA',
    b'/EmbeddedFile',
    b'/RichMedia',
    b'/Flash',
    b'eval(',
    b'unescape(',
]

# Phishing keywords in document content
PHISHING_KEYWORDS = [
    'click here', 'verify your account', 'update your password',
    'suspended', 'unauthorized access', 'confirm your identity',
    'act now', 'limited time', 'click the link below',
    'enable macros', 'enable editing', 'enable content',
]


class AttachmentAnalyzer:

    def analyze_base64(self, filename, base64_data):
        """
        Analyze a base64-encoded attachment.
        This is what the API endpoint calls.
        """
        try:
            # Decode base64
            if ',' in base64_data:
                base64_data = base64_data.split(',')[1]
            file_bytes = base64.b64decode(base64_data)
            return self.analyze_bytes(filename, file_bytes)
        except Exception as e:
            return {
                'success': False,
                'error': f'Could not decode attachment: {str(e)}'
            }

    def analyze_bytes(self, filename, file_bytes):
        """
        Analyze raw file bytes.
        """
        result = {
            'success': True,
            'filename': filename,
            'file_size': len(file_bytes),
            'file_size_kb': round(len(file_bytes) / 1024, 1),
            'extension': '',
            'risk_score': 0,
            'risk_level': 'LOW',
            'risk_factors': [],
            'is_dangerous': False,
            'has_macros': False,
            'has_scripts': False,
            'file_hash': hashlib.md5(file_bytes).hexdigest(),
            'summary': ''
        }

        # Get extension
        ext = os.path.splitext(filename)[1].lower()
        result['extension'] = ext

        # 1. Check for immediately dangerous extensions
        if ext in DANGEROUS_EXTENSIONS:
            result['risk_score'] = 100
            result['is_dangerous'] = True
            result['risk_factors'].append(
                f'Executable file type ({ext}) — never open attachments of this type'
            )

        # 2. Check file size anomalies
        if len(file_bytes) < 100:
            result['risk_factors'].append('File is suspiciously small — may be a dropper')
            result['risk_score'] += 15

        # 3. Analyze by type
        if ext == '.pdf':
            self._analyze_pdf(file_bytes, result)
        elif ext in {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'}:
            self._analyze_office(file_bytes, result, ext)
        elif ext in {'.zip', '.rar', '.7z'}:
            self._analyze_archive(file_bytes, result)

        # 4. Check filename for suspicious patterns
        self._check_filename(filename, result)

        # 5. Cap score and set risk level
        result['risk_score'] = min(result['risk_score'], 100)
        score = result['risk_score']

        if score >= 80:
            result['risk_level'] = 'CRITICAL'
            result['summary'] = 'This attachment is highly suspicious and should not be opened.'
        elif score >= 60:
            result['risk_level'] = 'HIGH'
            result['summary'] = 'This attachment has multiple risk indicators. Exercise extreme caution.'
        elif score >= 40:
            result['risk_level'] = 'MEDIUM'
            result['summary'] = 'This attachment has some suspicious characteristics. Verify the sender.'
        elif score >= 20:
            result['risk_level'] = 'LOW'
            result['summary'] = 'Minor concerns detected. The attachment appears mostly safe.'
        else:
            result['risk_level'] = 'SAFE'
            result['summary'] = 'No significant threats detected in this attachment.'

        return result

    def _analyze_pdf(self, file_bytes, result):
        """Analyze PDF for malicious patterns."""
        found_patterns = []

        for pattern in PDF_PATTERNS:
            if pattern in file_bytes:
                found_patterns.append(pattern.decode('utf-8', errors='ignore'))

        if '/JavaScript' in found_patterns or '/JS' in found_patterns:
            result['has_scripts'] = True
            result['risk_score'] += 40
            result['risk_factors'].append('PDF contains JavaScript — common in malicious PDFs')

        if '/Launch' in found_patterns:
            result['risk_score'] += 35
            result['risk_factors'].append('PDF contains Launch action — can execute system commands')

        if '/OpenAction' in found_patterns or '/AA' in found_patterns:
            result['risk_score'] += 20
            result['risk_factors'].append('PDF contains automatic action on open')

        if '/EmbeddedFile' in found_patterns:
            result['risk_score'] += 25
            result['risk_factors'].append('PDF contains embedded files')

        # Check for phishing keywords in PDF text
        text = file_bytes.decode('utf-8', errors='ignore').lower()
        for keyword in PHISHING_KEYWORDS:
            if keyword in text:
                result['risk_score'] += 10
                result['risk_factors'].append(f'Contains phishing phrase: "{keyword}"')
                break

    def _analyze_office(self, file_bytes, result, ext):
        """Analyze Office documents for macros and suspicious content."""
        # Modern Office files (.docx, .xlsx etc) are ZIP archives
        if ext in {'.docx', '.xlsx', '.pptx'}:
            try:
                with zipfile.ZipFile(BytesIO(file_bytes)) as zf:
                    filenames = zf.namelist()

                    # Check for VBA macro project
                    if any('vbaProject' in f for f in filenames):
                        result['has_macros'] = True
                        result['risk_score'] += 45
                        result['risk_factors'].append(
                            'Office document contains VBA macros — common attack vector'
                        )

                    # Read all content and check for patterns
                    for fname in filenames:
                        try:
                            content = zf.read(fname)
                            for pattern in MACRO_PATTERNS:
                                if pattern in content:
                                    if pattern in {b'Shell(', b'WScript.Shell', b'CreateObject',
                                                   b'powershell', b'cmd.exe', b'URLDownloadToFile'}:
                                        result['risk_score'] += 30
                                        result['risk_factors'].append(
                                            f'Suspicious code pattern: {pattern.decode("utf-8", errors="ignore")}'
                                        )
                                        result['has_scripts'] = True
                        except Exception:
                            pass

                    # Check for external relationships (phone-home)
                    if any('external' in f.lower() for f in filenames):
                        result['risk_score'] += 20
                        result['risk_factors'].append(
                            'Document contains external references — may phone home on open'
                        )

            except zipfile.BadZipFile:
                # Old .doc/.xls binary format
                self._analyze_office_binary(file_bytes, result)

        else:
            # Old binary format
            self._analyze_office_binary(file_bytes, result)

    def _analyze_office_binary(self, file_bytes, result):
        """Analyze old-format binary Office files."""
        for pattern in MACRO_PATTERNS:
            if pattern in file_bytes:
                result['has_macros'] = True
                result['risk_score'] += 35
                result['risk_factors'].append(
                    'Binary Office file may contain macros'
                )
                break

    def _analyze_archive(self, file_bytes, result):
        """Analyze ZIP archives for dangerous contents."""
        try:
            with zipfile.ZipFile(BytesIO(file_bytes)) as zf:
                inner_files = zf.namelist()

                # Check for dangerous files inside the archive
                for inner_file in inner_files:
                    inner_ext = os.path.splitext(inner_file)[1].lower()
                    if inner_ext in DANGEROUS_EXTENSIONS:
                        result['risk_score'] += 50
                        result['is_dangerous'] = True
                        result['risk_factors'].append(
                            f'Archive contains dangerous file: {inner_file}'
                        )

                # Check for double extensions (file.pdf.exe trick)
                for inner_file in inner_files:
                    parts = inner_file.split('.')
                    if len(parts) > 2:
                        last_ext = '.' + parts[-1].lower()
                        if last_ext in DANGEROUS_EXTENSIONS:
                            result['risk_score'] += 40
                            result['risk_factors'].append(
                                f'Double extension detected: {inner_file}'
                            )

        except (zipfile.BadZipFile, Exception):
            result['risk_factors'].append('Archive could not be read — may be corrupted or encrypted')
            result['risk_score'] += 15

    def _check_filename(self, filename, result):
        """Check filename for suspicious patterns."""
        name_lower = filename.lower()

        # Double extension trick
        parts = filename.split('.')
        if len(parts) > 2:
            second_last_ext = '.' + parts[-2].lower()
            if second_last_ext in SUSPICIOUS_EXTENSIONS:
                result['risk_score'] += 30
                result['risk_factors'].append(
                    f'Suspicious double extension: {filename}'
                )

        # Urgency in filename
        urgency_words = ['urgent', 'invoice', 'payment', 'account', 'verify',
                         'suspended', 'important', 'action_required', 'confirm']
        for word in urgency_words:
            if word in name_lower:
                result['risk_score'] += 10
                result['risk_factors'].append(
                    f'Suspicious filename contains "{word}"'
                )
                break

        # Very long filename
        if len(filename) > 100:
            result['risk_score'] += 10
            result['risk_factors'].append('Unusually long filename')


def get_attachment_analyzer():
    return AttachmentAnalyzer()
