"""
Email Header Analyzer Module
Parse and analyze email headers for authentication and security
"""

import re
import email
from email import policy
from email.parser import Parser
import email.utils
import ipaddress
import dns.resolver
from datetime import datetime


class EmailHeaderAnalyzer:
    def __init__(self):
        self.parser = Parser(policy=policy.default)
    
    def analyze_headers(self, raw_headers):
        """Analyze raw email headers"""
        result = {
            'success': False,
            'basic_info': {},
            'authentication': {
                'spf': {'status': 'not_found', 'details': None},
                'dkim': {'status': 'not_found', 'details': None},
                'dmarc': {'status': 'not_found', 'details': None}
            },
            'routing': [],
            'routing_summary': {
                'total_hops': 0,
                'originating_ip': None,
                'total_delay_seconds': 0
            },
            'domain_dns_records': None,
            'security_analysis': [],
            'risk_score': 0,
            'risk_level': 'unknown'
        }
        
        try:
            # Parse headers
            msg = self.parser.parsestr(raw_headers)
            
            # Extract basic info
            result['basic_info'] = self._extract_basic_info(msg)
            
            # Analyze authentication headers
            result['authentication'] = self._analyze_authentication(msg, raw_headers)
            
            # Analyze routing (Received headers)
            result['routing'] = self._analyze_routing(msg)

            # Summarize routing
            originating_ip = None
            for hop in result['routing']:
                if hop.get('ip_type') == 'public' and hop.get('ip'):
                    originating_ip = hop['ip']
                    break
            
            total_delay = sum(h.get('delay_seconds', 0) for h in result['routing'])
            result['routing_summary'] = {
                'total_hops': len(result['routing']),
                'originating_ip': originating_ip,
                'total_delay_seconds': total_delay
            }

            # Live DNS SPF/DMARC/MX lookup for From domain (isolated safely)
            try:
                from_domain = self._extract_domain(result['basic_info'].get('from', ''))
                if from_domain:
                    result['domain_dns_records'] = self.check_domain_records(from_domain)
            except Exception as dns_err:
                result['domain_dns_records'] = {'status': 'error', 'details': str(dns_err)}
            
            # Security analysis
            result['security_analysis'] = self._security_analysis(msg, raw_headers, result)
            
            # Calculate risk score
            result['risk_score'], result['risk_level'] = self._calculate_risk(result)
            
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _extract_basic_info(self, msg):
        """Extract basic email information"""
        info = {
            'from': None,
            'to': None,
            'subject': None,
            'date': None,
            'message_id': None,
            'reply_to': None,
            'return_path': None
        }
        
        info['from'] = msg.get('From', '')
        info['to'] = msg.get('To', '')
        info['subject'] = msg.get('Subject', '')
        info['date'] = msg.get('Date', '')
        info['message_id'] = msg.get('Message-ID', '')
        info['reply_to'] = msg.get('Reply-To', '')
        info['return_path'] = msg.get('Return-Path', '')
        
        return info
    
    def _analyze_authentication(self, msg, raw_headers):
        """Analyze SPF, DKIM, and DMARC"""
        auth = {
            'spf': {'status': 'not_found', 'details': None, 'raw': None},
            'dkim': {'status': 'not_found', 'details': None, 'raw': None},
            'dmarc': {'status': 'not_found', 'details': None, 'raw': None}
        }
        
        # Look for Authentication-Results header
        auth_results = msg.get('Authentication-Results', '')
        
        # Also check Received-SPF header
        received_spf = msg.get('Received-SPF', '')
        
        # Check ARC headers
        arc_auth = msg.get('ARC-Authentication-Results', '')
        
        combined_auth = f"{auth_results} {received_spf} {arc_auth}".lower()
        
        # SPF Analysis
        spf_patterns = [
            (r'spf=pass', 'pass'),
            (r'spf=fail', 'fail'),
            (r'spf=softfail', 'softfail'),
            (r'spf=neutral', 'neutral'),
            (r'spf=none', 'none'),
            (r'spf=temperror', 'temperror'),
            (r'spf=permerror', 'permerror')
        ]
        
        for pattern, status in spf_patterns:
            if re.search(pattern, combined_auth):
                auth['spf']['status'] = status
                auth['spf']['raw'] = received_spf or self._extract_auth_detail(auth_results, 'spf')
                break
        
        # DKIM Analysis
        dkim_patterns = [
            (r'dkim=pass', 'pass'),
            (r'dkim=fail', 'fail'),
            (r'dkim=neutral', 'neutral'),
            (r'dkim=none', 'none'),
            (r'dkim=temperror', 'temperror'),
            (r'dkim=permerror', 'permerror')
        ]
        
        for pattern, status in dkim_patterns:
            if re.search(pattern, combined_auth):
                auth['dkim']['status'] = status
                auth['dkim']['raw'] = self._extract_auth_detail(auth_results, 'dkim')
                break
        
        # Check for DKIM-Signature header
        dkim_sig = msg.get('DKIM-Signature', '')
        if dkim_sig and auth['dkim']['status'] == 'not_found':
            auth['dkim']['status'] = 'present'
            auth['dkim']['details'] = 'DKIM signature present but status unknown'
        
        # DMARC Analysis
        dmarc_patterns = [
            (r'dmarc=pass', 'pass'),
            (r'dmarc=fail', 'fail'),
            (r'dmarc=none', 'none'),
            (r'dmarc=bestguesspass', 'bestguesspass')
        ]
        
        for pattern, status in dmarc_patterns:
            if re.search(pattern, combined_auth):
                auth['dmarc']['status'] = status
                auth['dmarc']['raw'] = self._extract_auth_detail(auth_results, 'dmarc')
                break
        
        return auth
    
    def _extract_auth_detail(self, auth_results, auth_type):
        """Extract specific authentication detail from results"""
        pattern = rf'{auth_type}=[^\s;]+'
        match = re.search(pattern, auth_results, re.IGNORECASE)
        return match.group(0) if match else None
    
    def _analyze_routing(self, msg):
        """Analyze email routing from Received headers chronologically"""
        routing = []
        received_headers = msg.get_all('Received', [])
        if not received_headers:
            return routing

        # Received headers are prepended by each MTA (latest first).
        # We process chronologically (oldest hop = hop 1, to newest hop).
        ordered_headers = list(reversed(received_headers))
        prev_dt = None

        for idx, header in enumerate(ordered_headers):
            hop_num = idx + 1
            hop = {
                'hop_number': hop_num,
                'raw': header[:250] + '...' if len(header) > 250 else header,
                'from_server': None,
                'by_server': None,
                'ip': None,
                'ip_type': None,
                'timestamp': None,
                'delay_seconds': 0,
                'suspicious': False,
                'notes': []
            }

            # Extract 'from' server
            from_match = re.search(r'from\s+([^\s\(\)]+)', header, re.IGNORECASE)
            if from_match:
                hop['from_server'] = from_match.group(1).strip('[]();,')

            # Extract 'by' server
            by_match = re.search(r'by\s+([^\s\(\)]+)', header, re.IGNORECASE)
            if by_match:
                hop['by_server'] = by_match.group(1).strip('[]();,')

            # Extract IP address inside brackets or boundary
            ip_match = re.search(r'\[([0-9a-fA-F\:\.]+)\]', header)
            if not ip_match:
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
            
            if ip_match:
                candidate_ip = ip_match.group(1) if '[' in ip_match.group(0) else ip_match.group(0)
                try:
                    ip_obj = ipaddress.ip_address(candidate_ip)
                    hop['ip'] = str(ip_obj)
                    if ip_obj.is_loopback:
                        hop['ip_type'] = 'loopback'
                    elif ip_obj.is_private:
                        hop['ip_type'] = 'private'
                    elif ip_obj.is_reserved:
                        hop['ip_type'] = 'reserved'
                    else:
                        hop['ip_type'] = 'public'
                except ValueError:
                    pass

            # Extract and parse timestamp
            if ';' in header:
                ts_part = header.split(';')[-1].strip()
                clean_ts = re.sub(r'\s*\([A-Z0-9_\-\s]+\)', '', ts_part).strip()
                try:
                    dt = email.utils.parsedate_to_datetime(clean_ts)
                    hop['timestamp'] = dt.isoformat()
                    if prev_dt is not None:
                        diff = int((dt - prev_dt).total_seconds())
                        hop['delay_seconds'] = max(0, diff)
                        if diff < -60:
                            hop['suspicious'] = True
                            hop['notes'].append(f"Clock skew anomaly: timestamp is {abs(diff)}s earlier than previous hop")
                        elif diff > 3600:
                            hop['notes'].append(f"MTA relay queue delay: {diff // 60}m")
                    prev_dt = dt
                except Exception:
                    hop['timestamp'] = ts_part[:40]

            # Suspicious routing checks
            if hop.get('ip_type') == 'loopback':
                hop['suspicious'] = True
                hop['notes'].append('Routes through localhost/loopback address')

            for pattern, note in [
                (r'\.ru\b', 'Routes through Russian domain TLD'),
                (r'\.cn\b', 'Routes through Chinese domain TLD'),
                (r'unknown', 'MTA reported unknown server or unresolved host')
            ]:
                if re.search(pattern, header, re.IGNORECASE):
                    hop['suspicious'] = True
                    hop['notes'].append(note)

            routing.append(hop)

        return routing
    
    def _security_analysis(self, msg, raw_headers, result):
        """Perform security analysis"""
        findings = []
        
        basic = result['basic_info']
        auth = result['authentication']
        
        # Check From vs Return-Path mismatch
        from_addr = basic.get('from', '')
        return_path = basic.get('return_path', '')
        
        from_domain = self._extract_domain(from_addr)
        return_domain = self._extract_domain(return_path)
        
        if from_domain and return_domain and from_domain != return_domain:
            findings.append({
                'severity': 'high',
                'finding': 'From and Return-Path domains do not match',
                'details': f"From: {from_domain}, Return-Path: {return_domain}",
                'recommendation': 'This is a strong indicator of spoofing'
            })
        
        # Check From vs Reply-To mismatch
        reply_to = basic.get('reply_to', '')
        reply_domain = self._extract_domain(reply_to)
        
        if reply_to and from_domain and reply_domain and from_domain != reply_domain:
            findings.append({
                'severity': 'medium',
                'finding': 'Reply-To domain differs from From domain',
                'details': f"From: {from_domain}, Reply-To: {reply_domain}",
                'recommendation': 'Replies may go to a different address than shown'
            })
        
        # Check SPF status
        if auth['spf']['status'] == 'fail':
            findings.append({
                'severity': 'high',
                'finding': 'SPF authentication failed',
                'details': 'Sender is not authorized to send from this domain',
                'recommendation': 'This email may be spoofed'
            })
        elif auth['spf']['status'] == 'softfail':
            findings.append({
                'severity': 'medium',
                'finding': 'SPF authentication soft-failed',
                'details': 'Sender may not be authorized',
                'recommendation': 'Treat with caution'
            })
        elif auth['spf']['status'] == 'not_found':
            findings.append({
                'severity': 'low',
                'finding': 'No SPF authentication results found',
                'details': 'Cannot verify sender authorization',
                'recommendation': 'Domain may not have SPF configured'
            })
        
        # Check DKIM status
        if auth['dkim']['status'] == 'fail':
            findings.append({
                'severity': 'high',
                'finding': 'DKIM authentication failed',
                'details': 'Email signature verification failed',
                'recommendation': 'Email may have been modified in transit or spoofed'
            })
        elif auth['dkim']['status'] == 'not_found':
            findings.append({
                'severity': 'low',
                'finding': 'No DKIM signature found',
                'details': 'Email is not digitally signed',
                'recommendation': 'Cannot verify email integrity'
            })
        
        # Check DMARC status
        if auth['dmarc']['status'] == 'fail':
            findings.append({
                'severity': 'high',
                'finding': 'DMARC authentication failed',
                'details': 'Email failed domain authentication policy',
                'recommendation': 'This email should be treated as suspicious'
            })
        
        # Check for suspicious routing
        suspicious_hops = [h for h in result['routing'] if h.get('suspicious')]
        if suspicious_hops:
            findings.append({
                'severity': 'medium',
                'finding': f'{len(suspicious_hops)} suspicious routing hop(s) detected',
                'details': ', '.join([n for h in suspicious_hops for n in h.get('notes', [])]),
                'recommendation': 'Email routing may be unusual'
            })
        
        # Check for X-Mailer or unusual headers
        x_mailer = msg.get('X-Mailer', '')
        if x_mailer:
            suspicious_mailers = ['PHPMailer', 'Swiftmailer', 'sendmail']
            for mailer in suspicious_mailers:
                if mailer.lower() in x_mailer.lower():
                    findings.append({
                        'severity': 'low',
                        'finding': f'Email sent using {mailer}',
                        'details': f'X-Mailer: {x_mailer}',
                        'recommendation': 'Common in automated/bulk email'
                    })
                    break
        
        # Check for missing Message-ID
        if not basic.get('message_id'):
            findings.append({
                'severity': 'medium',
                'finding': 'Missing Message-ID header',
                'details': 'Legitimate emails typically have a Message-ID',
                'recommendation': 'May indicate manually crafted email'
            })
        
        return findings
    
    def _extract_domain(self, email_string):
        """Extract domain from email address"""
        if not email_string:
            return None
        
        # Handle "Name <email@domain.com>" format
        match = re.search(r'[\w\.-]+@([\w\.-]+)', email_string)
        if match:
            return match.group(1).lower()
        
        return None
    
    def _calculate_risk(self, result):
        """Calculate overall risk score"""
        score = 0
        
        auth = result['authentication']
        findings = result['security_analysis']
        
        # Authentication scoring
        auth_scores = {
            'pass': 0,
            'fail': 30,
            'softfail': 15,
            'neutral': 5,
            'none': 10,
            'not_found': 5,
            'present': 0,
            'temperror': 10,
            'permerror': 15,
            'bestguesspass': 5
        }
        
        score += auth_scores.get(auth['spf']['status'], 5)
        score += auth_scores.get(auth['dkim']['status'], 5)
        score += auth_scores.get(auth['dmarc']['status'], 5)
        
        # Findings scoring
        severity_scores = {
            'high': 20,
            'medium': 10,
            'low': 5
        }
        
        for finding in findings:
            score += severity_scores.get(finding.get('severity', 'low'), 5)
        
        # Cap at 100
        score = min(score, 100)
        
        # Determine risk level
        if score >= 60:
            risk_level = 'high'
        elif score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return score, risk_level
    
    def check_domain_records(self, domain):
        """Check SPF, DKIM, and DMARC records for a domain with timeout protection"""
        records = {
            'domain': domain,
            'spf': None,
            'dmarc': None,
            'mx': [],
            'has_mx': False,
            'status': 'checked'
        }
        
        try:
            resolver = dns.resolver.Resolver()
        except Exception:
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            except Exception:
                records['status'] = 'resolver_unavailable'
                return records
        resolver.timeout = 2.0
        resolver.lifetime = 2.5

        try:
            # Check SPF (TXT record on domain)
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    txt_data = b''.join(record.strings).decode('utf-8', errors='ignore') if hasattr(record, 'strings') else str(record).strip('"')
                    if txt_data.startswith('v=spf1'):
                        records['spf'] = txt_data
                        break
            except Exception:
                pass
            
            # Check DMARC (TXT record on _dmarc.domain)
            try:
                dmarc_records = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                for record in dmarc_records:
                    txt_data = b''.join(record.strings).decode('utf-8', errors='ignore') if hasattr(record, 'strings') else str(record).strip('"')
                    if txt_data.startswith('v=DMARC1'):
                        records['dmarc'] = txt_data
                        break
            except Exception:
                pass
            
            # Check MX records
            try:
                mx_records = resolver.resolve(domain, 'MX')
                records['mx'] = [str(r.exchange).rstrip('.') for r in mx_records]
                records['has_mx'] = len(records['mx']) > 0
            except Exception:
                pass
                
        except Exception as e:
            records['error'] = str(e)
            records['status'] = 'lookup_error'
        
        return records
