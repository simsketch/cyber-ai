import dns.resolver
import dns.zone
from scanners.base_scanner import BaseScanner

class SubdomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'api']
        
    async def scan(self) -> dict:
        try:
            found_subdomains = []
            
            # Try common subdomains
            for subdomain in self.common_subdomains:
                try:
                    fqdn = f"{subdomain}.{self.target}"
                    answers = dns.resolver.resolve(fqdn, 'A')
                    if answers:
                        found_subdomains.append({
                            'subdomain': fqdn,
                            'ip_addresses': [str(rdata) for rdata in answers]
                        })
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception:
                    continue
            
            self.results = {
                'target': self.target,
                'subdomains': found_subdomains
            }
            
            return self.results
            
        except Exception as e:
            return {
                'error': str(e),
                'target': self.target
            }