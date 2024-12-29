import dns.resolver
import socket
from typing import Dict, Any
from scanners.base_scanner import BaseScanner

class DomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        
    async def scan(self) -> dict:
        try:
            # Basic DNS records
            a_records = dns.resolver.resolve(self.target, 'A')
            mx_records = dns.resolver.resolve(self.target, 'MX')
            txt_records = dns.resolver.resolve(self.target, 'TXT')
            ns_records = dns.resolver.resolve(self.target, 'NS')
            
            # Get reverse DNS for IP addresses
            ip_info = []
            for ip in [str(rdata) for rdata in a_records]:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    ip_info.append({
                        'ip': ip,
                        'hostname': hostname
                    })
                except socket.herror:
                    ip_info.append({
                        'ip': ip,
                        'hostname': None
                    })
            
            self.results = {
                'target': self.target,
                'ip_addresses': ip_info,
                'nameservers': [str(ns) for ns in ns_records],
                'mx_records': [{'exchange': str(mx.exchange), 'preference': mx.preference} for mx in mx_records],
                'txt_records': [str(txt) for txt in txt_records],
                'attack_surface': {
                    'total_ips': len(ip_info),
                    'total_nameservers': len(ns_records),
                    'mail_servers': len(mx_records)
                }
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results