import dns.resolver
from typing import Dict, Any
from scanners.base_scanner import BaseScanner

class DomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        
    async def scan(self) -> dict:
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            mx_records = dns.resolver.resolve(self.target, 'MX')
            txt_records = dns.resolver.resolve(self.target, 'TXT')
            
            self.results = {
                'ip_addresses': [str(rdata) for rdata in answers],
                'mx_records': [str(rdata.exchange) for rdata in mx_records],
                'txt_records': [str(rdata) for rdata in txt_records],
                'target': self.target
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results