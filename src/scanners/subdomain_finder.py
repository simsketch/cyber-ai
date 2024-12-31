import dns.resolver
import dns.zone
import requests
import asyncio
import aiohttp
from typing import List, Dict
from scanners.base_scanner import BaseScanner

class SubdomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server',
            'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
            'staging', 'app', 'admin', 'portal', 'test', 'cdn',
            'cloud', 'git', 'host', 'mx', 'email', 'ftp', 'docs',
            'web', 'support', 'store', 'shop', 'beta', 'ww1', 'ww2',
            'news', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'webdisk', 'local', 'mobile', 'firewall', 'gateway',
            'm', 'forum', 'images', 'img', 'auth', 'cp', 'admin1',
            'search', 'api2', 'api1', 'stat', 'stats', 'ns3', 'ns4',
            'demo', 'old', 'new', 'testing', 'development', 'internal'
        ]
        
    async def _check_cert_transparency(self) -> List[str]:
        try:
            print("Checking certificate transparency logs...")
            ct_domains = set()
            
            # Check multiple CT log providers
            ct_apis = [
                f"https://crt.sh/?q=%.{self.target}&output=json",
                f"https://certspotter.com/api/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names"
            ]
            
            async with aiohttp.ClientSession() as session:
                for api_url in ct_apis:
                    try:
                        async with session.get(api_url, timeout=10) as response:
                            if response.status == 200:
                                data = await response.json()
                                if 'crt.sh' in api_url:
                                    ct_domains.update(entry['name_value'] for entry in data)
                                else:  # certspotter
                                    ct_domains.update(
                                        dns_name
                                        for cert in data
                                        for dns_name in cert.get('dns_names', [])
                                        if self.target in dns_name
                                    )
                    except Exception as e:
                        print(f"Error checking CT logs at {api_url}: {str(e)}")
                        continue
            
            return list(ct_domains)
        except Exception as e:
            print(f"Error in certificate transparency check: {str(e)}")
            return []

    async def _try_zone_transfer(self, nameserver: str) -> List[str]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, self.target))
            return [f"{name}.{self.target}" for name, _ in zone.nodes.items()]
        except Exception as e:
            print(f"Zone transfer failed for {nameserver}: {str(e)}")
            return []

    async def _resolve_subdomain(self, subdomain: str) -> Dict:
        try:
            fqdn = f"{subdomain}.{self.target}" if subdomain != '@' else self.target
            answers = dns.resolver.resolve(fqdn, 'A')
            
            subdomain_info = {
                'subdomain': fqdn,
                'ip_addresses': [str(rdata) for rdata in answers],
                'discovery_method': 'bruteforce'
            }
            
            # Try to get HTTP status and server info
            try:
                for protocol in ['https', 'http']:
                    try:
                        response = requests.head(
                            f"{protocol}://{fqdn}",
                            timeout=5,
                            allow_redirects=True
                        )
                        subdomain_info.update({
                            'http_status': response.status_code,
                            'server': response.headers.get('Server'),
                            'protocol': protocol,
                            'redirect_url': response.url if response.history else None
                        })
                        break
                    except requests.RequestException:
                        continue
            except Exception as e:
                print(f"Error checking HTTP for {fqdn}: {str(e)}")
            
            return subdomain_info
        except dns.resolver.NXDOMAIN:
            return None
        except Exception as e:
            print(f"Error resolving {subdomain}: {str(e)}")
            return None

    async def scan(self) -> dict:
        try:
            print(f"Starting subdomain enumeration for {self.target}")
            found_subdomains = []
            zone_transfer_results = []
            
            # Try zone transfer first
            try:
                ns_records = dns.resolver.resolve(self.target, 'NS')
                for ns in ns_records:
                    zone_results = await self._try_zone_transfer(str(ns))
                    if zone_results:
                        zone_transfer_results.extend(zone_results)
            except Exception as e:
                print(f"Error in zone transfer attempt: {str(e)}")
            
            # Get certificate transparency results
            ct_results = await self._check_cert_transparency()
            
            # Combine all subdomain sources
            all_subdomains = set(
                [s.strip('.') for s in zone_transfer_results] +
                [s.strip('.') for s in ct_results] +
                [f"{s}.{self.target}" for s in self.common_subdomains]
            )
            
            # Resolve all unique subdomains
            tasks = []
            for subdomain in all_subdomains:
                if subdomain.endswith(self.target):
                    prefix = subdomain[:-len(self.target)-1]
                    if prefix:
                        tasks.append(self._resolve_subdomain(prefix))
            
            results = await asyncio.gather(*tasks)
            found_subdomains = [r for r in results if r is not None]
            
            # Mark discovery method for CT and zone transfer results
            for subdomain in found_subdomains:
                if subdomain['subdomain'] in zone_transfer_results:
                    subdomain['discovery_method'] = 'zone_transfer'
                elif subdomain['subdomain'] in ct_results:
                    subdomain['discovery_method'] = 'cert_transparency'
            
            # Calculate attack surface metrics
            unique_ips = set()
            for subdomain in found_subdomains:
                unique_ips.update(subdomain.get('ip_addresses', []))
            
            web_servers = len([s for s in found_subdomains if s.get('http_status')])
            
            self.results = {
                'target': self.target,
                'subdomains': found_subdomains,
                'zone_transfer_vulnerable': bool(zone_transfer_results),
                'attack_surface': {
                    'total_subdomains': len(found_subdomains),
                    'unique_ips': len(unique_ips),
                    'zone_transfer_count': len(zone_transfer_results),
                    'cert_transparency_count': len(ct_results),
                    'web_servers': web_servers,
                    'risk_level': 'HIGH' if bool(zone_transfer_results) else 
                                'MEDIUM' if len(found_subdomains) > 10 else 'LOW'
                }
            }
            
        except Exception as e:
            print(f"Error in subdomain scan: {str(e)}")
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results