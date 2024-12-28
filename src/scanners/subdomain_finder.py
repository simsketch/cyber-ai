import dns.resolver
import dns.zone
import requests
from scanners.base_scanner import BaseScanner

class SubdomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server',
            'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
            'staging', 'app', 'admin', 'portal', 'test', 'cdn',
            'cloud', 'git', 'host', 'mx', 'email', 'ftp'
        ]
        
    async def scan(self) -> dict:
        try:
            found_subdomains = []
            zone_transfer_results = []
            
            # Try zone transfer first
            try:
                ns_records = dns.resolver.resolve(self.target, 'NS')
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.target))
                        if zone:
                            zone_transfer_results.extend([str(name) + '.' + self.target 
                                                        for name, _ in zone.nodes.items()])
                    except:
                        continue
            except:
                pass
            
            # Bruteforce common subdomains
            for subdomain in self.common_subdomains:
                try:
                    fqdn = f"{subdomain}.{self.target}"
                    answers = dns.resolver.resolve(fqdn, 'A')
                    if answers:
                        subdomain_info = {
                            'subdomain': fqdn,
                            'ip_addresses': [str(rdata) for rdata in answers],
                            'discovery_method': 'bruteforce'
                        }
                        
                        # Try to get HTTP status
                        try:
                            response = requests.head(f"https://{fqdn}", timeout=5)
                            subdomain_info['http_status'] = response.status_code
                        except:
                            subdomain_info['http_status'] = None
                            
                        found_subdomains.append(subdomain_info)
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception:
                    continue
            
            # Add zone transfer results
            for subdomain in zone_transfer_results:
                if subdomain not in [s['subdomain'] for s in found_subdomains]:
                    try:
                        answers = dns.resolver.resolve(subdomain, 'A')
                        subdomain_info = {
                            'subdomain': subdomain,
                            'ip_addresses': [str(rdata) for rdata in answers],
                            'discovery_method': 'zone_transfer'
                        }
                        found_subdomains.append(subdomain_info)
                    except:
                        continue
            
            self.results = {
                'target': self.target,
                'subdomains': found_subdomains,
                'zone_transfer_vulnerable': bool(zone_transfer_results),
                'attack_surface': {
                    'total_subdomains': len(found_subdomains),
                    'unique_ips': len(set(ip 
                        for subdomain in found_subdomains 
                        for ip in subdomain['ip_addresses']
                    )),
                    'zone_transfer_count': len(zone_transfer_results)
                }
            }
            
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results