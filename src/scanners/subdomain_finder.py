import dns.resolver
import dns.zone
import requests
import asyncio
import aiohttp
import logging
from typing import List, Dict, Set
from scanners.base_scanner import BaseScanner
from itertools import product
import string
import socket
import ssl
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SubdomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        # Create cache directory in /tmp which should be writable
        self.cache_dir = "/tmp/scanner_cache"
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception as e:
            logging.error(f"Error creating cache directory: {str(e)}")
            self.cache_dir = None
        
        # Extended list of common subdomains
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
            'demo', 'old', 'new', 'testing', 'development', 'internal',
            'staging', 'backup', 'db', 'data', 'prod', 'test',
            'intranet', 'extranet', 'tools', 'direct', 'remote',
            'ops', 'monitor', 'status', 'puppet', 'chef', 'ansible',
            'jenkins', 'ci', 'jira', 'confluence', 'wiki',
            'gitlab', 'svn', 'phabricator', 'redmine',
            # Additional cloud-related subdomains
            'aws', 's3', 'azure', 'gcp', 'bucket', 'storage',
            'lambda', 'function', 'analytics', 'logs', 'metrics',
            'grafana', 'prometheus', 'kibana', 'elastic', 'es',
            'redis', 'cache', 'queue', 'worker', 'tasks',
            # Additional service-specific subdomains
            'auth', 'login', 'sso', 'idp', 'accounts', 'identity',
            'payments', 'billing', 'checkout', 'cart', 'orders',
            'api-docs', 'swagger', 'graphql', 'gql', 'rest',
            'websocket', 'ws', 'wss', 'socket', 'stream',
            # Security-related subdomains
            'security', 'bounty', 'hackerone', 'bugcrowd', 'pentest',
            'vulns', 'vulnerabilities', 'security-report'
        ]
        
        # Add numeric variations
        numeric_variations = [
            f"{sub}{num}" for sub in 
            ['dev', 'staging', 'test', 'prod', 'api', 'app', 'web', 'srv'] 
            for num in range(1, 5)
        ]
        self.common_subdomains.extend(numeric_variations)
        
        # Add environment variations
        env_prefixes = ['dev', 'staging', 'qa', 'prod', 'test', 'uat', 'sandbox']
        env_suffixes = ['api', 'app', 'web', 'admin', 'backend', 'frontend', 'worker']
        env_variations = [
            f"{prefix}-{suffix}" for prefix, suffix in product(env_prefixes, env_suffixes)
        ]
        self.common_subdomains.extend(env_variations)
        
        # Add region variations
        regions = ['us', 'eu', 'asia', 'au', 'sa', 'na', 'af']
        region_variations = [
            f"{region}-{sub}" for region, sub in product(regions, ['prod', 'dev', 'staging'])
        ]
        self.common_subdomains.extend(region_variations)

    async def _check_cert_transparency(self) -> Set[str]:
        try:
            print("Checking certificate transparency logs...")
            ct_domains = set()
            
            # Extended list of CT log providers
            ct_apis = [
                f"https://crt.sh/?q=%.{self.target}&output=json",
                f"https://certspotter.com/api/v1/issuances?domain={self.target}&include_subdomains=true&expand=dns_names",
                f"https://www.google.com/transparencyreport/api/v1/certificates?domain={self.target}",
                f"https://api.certstream.calidog.io/v1/query?domain={self.target}",
                f"https://sslmate.com/certspotter/api/v1/issuances?domain={self.target}",
                f"https://api.facebook.com/certificates?domain={self.target}",
                f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?domain={self.target}"
            ]
            
            async with aiohttp.ClientSession() as session:
                for api_url in ct_apis:
                    try:
                        async with session.get(api_url, timeout=10) as response:
                            if response.status == 200:
                                data = await response.json()
                                if 'crt.sh' in api_url:
                                    ct_domains.update(entry['name_value'] for entry in data)
                                elif 'certspotter' in api_url:
                                    ct_domains.update(
                                        dns_name
                                        for cert in data
                                        for dns_name in cert.get('dns_names', [])
                                        if self.target in dns_name
                                    )
                                elif 'google' in api_url:
                                    for cert in data.get('certificates', []):
                                        ct_domains.update(cert.get('subject_dns_names', []))
                                elif 'certstream' in api_url:
                                    ct_domains.update(cert['domain'] for cert in data.get('certificates', []))
                                elif 'sslmate' in api_url:
                                    ct_domains.update(
                                        dns_name
                                        for cert in data
                                        for dns_name in cert.get('names', [])
                                    )
                                elif 'facebook' in api_url:
                                    ct_domains.update(cert['domain'] for cert in data.get('data', []))
                    except Exception as e:
                        print(f"Error checking CT logs at {api_url}: {str(e)}")
                        continue
            
            return ct_domains
        except Exception as e:
            print(f"Error in certificate transparency check: {str(e)}")
            return set()

    async def _try_zone_transfer(self, nameserver: str) -> List[str]:
        try:
            print(f"Attempting zone transfer from {nameserver}...")
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, self.target))
            return [f"{name}.{self.target}" for name, _ in zone.nodes.items()]
        except Exception as e:
            print(f"Zone transfer failed for {nameserver}: {str(e)}")
            return []

    async def _get_ssl_info(self, hostname: str, port: int = 443) -> Dict:
        """Get SSL certificate information including alt names"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'subjectAltName': [x[1] for x in cert['subjectAltName']],
                    }
        except Exception as e:
            print(f"Error getting SSL info for {hostname}: {str(e)}")
            return {}

    async def _resolve_subdomain(self, subdomain: str) -> Dict:
        fqdn = f"{subdomain}.{self.target}" if subdomain != '@' else self.target
        logging.info(f"Attempting to resolve subdomain: {fqdn}")
        
        # List of nameserver groups to try in order
        nameserver_groups = [
            ['8.8.8.8', '8.8.4.4'],  # Google DNS
            ['1.1.1.1', '1.0.0.1'],  # Cloudflare
            ['9.9.9.9'],             # Quad9
            ['208.67.222.222']       # OpenDNS
        ]
        
        for nameservers in nameserver_groups:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 5
                resolver.nameservers = nameservers
                resolver.rotate = True
                
                logging.info(f"Trying nameservers {nameservers} for {fqdn}")
                answers = resolver.resolve(fqdn, 'A')
                
                subdomain_info = {
                    'subdomain': fqdn,
                    'ip_addresses': [str(rdata) for rdata in answers],
                    'discovery_method': 'bruteforce'
                }
                
                logging.info(f"Successfully resolved {fqdn} to {subdomain_info['ip_addresses']}")
                
                # Try to get HTTP status and server info
                try:
                    for protocol in ['https', 'http']:
                        try:
                            logging.info(f"Checking {protocol} for {fqdn}")
                            response = requests.head(
                                f"{protocol}://{fqdn}",
                                timeout=10,
                                allow_redirects=True,
                                verify=False  # Allow self-signed certificates
                            )
                            subdomain_info.update({
                                'http_status': response.status_code,
                                'server': response.headers.get('Server'),
                                'protocol': protocol,
                                'redirect_url': response.url if response.history else None,
                                'headers': dict(response.headers),
                                'ssl_info': await self._get_ssl_info(fqdn) if protocol == 'https' else None
                            })
                            logging.info(f"HTTP check successful for {protocol}://{fqdn} - Status: {response.status_code}")
                            break
                        except requests.RequestException as e:
                            logging.warning(f"Error checking {protocol} for {fqdn}: {str(e)}")
                            continue
                except Exception as e:
                    logging.error(f"Error checking HTTP for {fqdn}: {str(e)}")
                
                # Enhanced DNS record checks
                for record_type in ['AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'CAA']:
                    try:
                        logging.info(f"Checking {record_type} records for {fqdn}")
                        records = resolver.resolve(fqdn, record_type)
                        subdomain_info[f'{record_type.lower()}_records'] = [str(r) for r in records]
                        logging.info(f"Found {len(subdomain_info[f'{record_type.lower()}_records'])} {record_type} records")
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                        logging.debug(f"No {record_type} records found for {fqdn}")
                        continue
                    except Exception as e:
                        logging.error(f"Error resolving {record_type} records for {fqdn}: {str(e)}")
                        continue
                
                return subdomain_info
                
            except dns.resolver.NXDOMAIN:
                logging.debug(f"Subdomain {fqdn} does not exist (using nameservers {nameservers})")
                continue
            except dns.resolver.NoAnswer:
                logging.debug(f"No A records found for {fqdn} (using nameservers {nameservers})")
                continue
            except dns.resolver.NoNameservers:
                logging.warning(f"No nameservers could be reached for {fqdn} (using {nameservers})")
                continue
            except dns.exception.Timeout:
                logging.warning(f"Timeout resolving {fqdn} (using nameservers {nameservers})")
                continue
            except Exception as e:
                logging.error(f"Unexpected error resolving {fqdn} using {nameservers}: {str(e)}")
                continue
        
        logging.warning(f"Failed to resolve subdomain {fqdn} with all nameserver groups")
        return None

    async def scan(self) -> dict:
        """Run subdomain enumeration scan"""
        try:
            logging.info(f"Starting subdomain scan steps for {self.target}")
            
            # Initialize results
            results = {
                "subdomains": [],
                "attack_surface": {
                    "security_issues": []
                }
            }
            
            # Basic DNS enumeration
            logging.info("Running DNS enumeration...")
            found_subdomains = []
            zone_transfer_results = []
            
            # Try zone transfer first with a timeout
            try:
                async with asyncio.timeout(30):  # 30 second timeout for zone transfers
                    logging.info("Attempting zone transfer...")
                    ns_records = dns.resolver.resolve(self.target, 'NS')
                    for ns in ns_records:
                        zone_results = await self._try_zone_transfer(str(ns))
                        if zone_results:
                            zone_transfer_results.extend(zone_results)
                            logging.info(f"Zone transfer successful from {ns}, found {len(zone_results)} records")
            except asyncio.TimeoutError:
                logging.error("Zone transfer attempts timed out")
            except Exception as e:
                logging.error(f"Error in zone transfer attempt: {str(e)}")
            
            # Generate permutations for common patterns
            pattern_subdomains = set()
            logging.info("Generating subdomain patterns...")
            for sub in self.common_subdomains[:100]:  # Limit to first 100 most common subdomains
                pattern_subdomains.add(f"{sub}.{self.target}")
            
            # Process subdomains in smaller batches with timeouts
            batch_size = 10
            all_subdomains = list(pattern_subdomains) + zone_transfer_results
            
            for i in range(0, len(all_subdomains), batch_size):
                batch = all_subdomains[i:i+batch_size]
                tasks = []
                for subdomain in batch:
                    tasks.append(self._resolve_subdomain(subdomain))
                
                try:
                    async with asyncio.timeout(30):  # 30 second timeout per batch
                        logging.info(f"Processing batch {i//batch_size + 1}/{(len(all_subdomains) + batch_size - 1)//batch_size}")
                        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                        for result in batch_results:
                            if result is not None and not isinstance(result, Exception):
                                found_subdomains.append(result)
                                logging.info(f"Found valid subdomain: {result}")
                except asyncio.TimeoutError:
                    logging.error(f"Batch resolution timed out for {len(tasks)} subdomains")
                except Exception as e:
                    logging.error(f"Error processing subdomain batch: {str(e)}")
                
                # Add a small delay between batches to prevent overwhelming DNS servers
                await asyncio.sleep(1)
            
            # Update results
            results["subdomains"] = found_subdomains
            
            # Add security issues if zone transfer was possible
            if zone_transfer_results:
                results["attack_surface"]["security_issues"].append({
                    "title": "Zone Transfer Possible",
                    "severity": "high",
                    "description": "Domain allows zone transfers, exposing all DNS records",
                    "recommendation": "Disable zone transfers except for authorized slave servers"
                })
            
            logging.info(f"Subdomain scan completed for {self.target} - Found {len(found_subdomains)} subdomains")
            return results
            
        except Exception as e:
            logging.error(f"Error in subdomain scan: {str(e)}")
            raise