"""
Prevention & Network Defense Export Engine
Generates actionable prevention rules from detected malicious domains, URLs, and IPs:
- DNS Sinkhole (Pi-hole / AdGuard Home / Unbound format)
- Operating System Hosts Blocklist (/etc/hosts & Windows)
- Network IDS Rules (Snort / Suricata)
- Linux Packet Filter Rules (iptables / UFW)
"""

from datetime import datetime
from urllib.parse import urlparse
import ipaddress


class PreventionExporter:
    def __init__(self):
        pass

    def extract_indicators(self, items):
        """Extract unique clean domains and IP addresses from list of URLs/domains/IPs"""
        domains = set()
        ips = set()

        for item in items:
            if not item:
                continue
            item = item.strip()
            # If item is URL, parse out host
            if '://' in item or '/' in item:
                if not item.startswith(('http://', 'https://')):
                    item = 'http://' + item
                host = urlparse(item).netloc.split(':')[0]
            else:
                host = item.split(':')[0].strip('/')

            if not host:
                continue

            # Check if host is an IP
            try:
                ip_obj = ipaddress.ip_address(host)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    ips.add(str(ip_obj))
            except ValueError:
                # Valid domain
                if '.' in host and not host.startswith('.'):
                    domains.add(host.lower())

        return sorted(list(domains)), sorted(list(ips))

    def generate_dns_sinkhole(self, items):
        """Generate Pi-hole / CoreDNS / Unbound sinkhole entries (0.0.0.0 domain)"""
        domains, _ = self.extract_indicators(items)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [
            "# ===========================================================",
            f"# Ph-tect Automated DNS Sinkhole Blocklist",
            f"# Generated on: {now}",
            f"# Total Blocked Domains: {len(domains)}",
            "# Usage: Import into Pi-hole, AdGuard Home, or Unbound DNS",
            "# ===========================================================\n"
        ]
        for d in domains:
            lines.append(f"0.0.0.0 {d}")
        return "\n".join(lines)

    def generate_hosts_blocklist(self, items):
        """Generate OS /etc/hosts loopback entries (127.0.0.1 domain)"""
        domains, _ = self.extract_indicators(items)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [
            "# ===========================================================",
            f"# Ph-tect Local System Hosts Blocklist (/etc/hosts)",
            f"# Generated on: {now}",
            f"# Total Blocked Domains: {len(domains)}",
            "# Usage: Append to /etc/hosts (Linux/macOS) or C:\\Windows\\System32\\drivers\\etc\\hosts",
            "# ===========================================================\n"
        ]
        for d in domains:
            lines.append(f"127.0.0.1 {d}")
            lines.append(f"::1 {d}")
        return "\n".join(lines)

    def generate_snort_suricata_rules(self, items, start_sid=9000001):
        """Generate Network Intrusion Detection System (Snort/Suricata) rules"""
        domains, ips = self.extract_indicators(items)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [
            "# ===========================================================",
            f"# Ph-tect NIDS Rules (Snort / Suricata)",
            f"# Generated on: {now}",
            "# ===========================================================\n"
        ]
        sid = start_sid
        for d in domains:
            lines.append(
                f'alert http any any -> any any (msg:"Ph-tect Phishing Domain Detected: {d}"; '
                f'content:"{d}"; http_header; classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1
            lines.append(
                f'alert tls any any -> any any (msg:"Ph-tect Phishing SNI Detected: {d}"; '
                f'tls_sni; content:"{d}"; classtype:trojan-activity; sid:{sid}; rev:1;)'
            )
            sid += 1

        for ip in ips:
            lines.append(
                f'alert ip any any -> {ip} any (msg:"Ph-tect C2/Phishing Malicious IP: {ip}"; '
                f'classtype:bad-unknown; sid:{sid}; rev:1;)'
            )
            sid += 1

        return "\n".join(lines)

    def generate_firewall_rules(self, items):
        """Generate Linux iptables / UFW firewall drop rules"""
        _, ips = self.extract_indicators(items)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [
            "#!/bin/bash",
            f"# Ph-tect Automated Firewall Drop Script",
            f"# Generated on: {now}",
            f"# Total Blocked IP Endpoints: {len(ips)}",
            "set -e\n"
        ]
        for ip in ips:
            lines.append(f"iptables -A OUTPUT -p tcp -d {ip} -j DROP")
            lines.append(f"iptables -A INPUT -s {ip} -j DROP")
        return "\n".join(lines)
