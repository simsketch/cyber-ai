import dns.resolver
from typing import Dict, Any, List
from .base_scanner import BaseScanner

class DomainFinder(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        try:
            answers = dns.resolver.resolve(target, 'A')
            mx_records = dns.resolver.resolve(target, 'MX')
            txt_records = dns.resolver.resolve(target, 'TXT')
            
            self.results = {
                'ip_addresses': [str(rdata) for rdata in answers],
                'mx_records': [str(rdata.exchange) for rdata in mx_records],
                'txt_records': [str(rdata) for rdata in txt_records],
                'target': target
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': target
            }
            
        return self.results