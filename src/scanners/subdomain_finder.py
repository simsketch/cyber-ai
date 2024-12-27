import dns.resolver
import dns.zone
from typing import Dict, Any, List
from .base_scanner import BaseScanner

class SubdomainFinder(BaseScanner):
    def __init__(self):
        super().__init__()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
            'ns1', 'ns2', 'dns', 'dns1', 'dns2', 'mx', 'remote', 'blog',
            'webdisk', 'admin', 'staging', 'dev', 'api', 'test', 'portal'
        ]
        
    async def scan(self, target: str) -> Dict[str, Any]:
        discovered_subdomains = set()
        
        try:
            # Try zone transfer first
            try:
                ns_records = dns.resolver.resolve(target, 'NS')
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), target))
                        for name, _ in zone.nodes.items():
                            subdomain = str(name) + '.' + target
                            discovered_subdomains.add(subdomain)
                    except:
                        continue
            except:
                pass
            
            # Brute force common subdomains
            for sub in self.common_subdomains:
                try:
                    subdomain = f"{sub}.{target}"
                    answers = dns.resolver.resolve(subdomain, 'A')
                    discovered_subdomains.add(subdomain)
                except:
                    continue
                    
            self.results = {
                'target': target,
                'subdomains': list(discovered_subdomains)
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': target
            }
            
        return self.results