import dns.resolver
import dns.zone
import requests
import asyncio
import aiohttp
import logging
from typing import List, Dict, Set
from scanners.base_scanner import BaseScanner
import string
import socket
import ssl
import os
import sublist3r

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

    async def _resolve_subdomain(self, subdomain: str) -> Dict:
        """Resolve a subdomain and get its details"""
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
                    "subdomain": fqdn,
                    "ip_addresses": [str(rdata) for rdata in answers],
                    "discovery_method": "sublist3r"
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
        """Run subdomain enumeration scan using sublist3r"""
        try:
            logging.info(f"Starting subdomain scan steps for {self.target}")
            
            # Initialize results
            results = {
                "subdomains": [],
                "attack_surface": {
                    "security_issues": []
                }
            }
            
            # Use sublist3r to enumerate subdomains
            logging.info("Running Sublist3r enumeration...")
            try:
                # Run sublist3r in a separate thread to not block the event loop
                loop = asyncio.get_event_loop()
                subdomains = await loop.run_in_executor(
                    None,
                    sublist3r.main,
                    self.target,
                    40,  # threads
                    None,  # savefile
                    None,  # ports
                    False,  # silent
                    True,  # verbose
                    False,  # enable_bruteforce
                    None   # engines
                )
                
                logging.info(f"Sublist3r found {len(subdomains)} subdomains")
                
                # Process subdomains in smaller batches with timeouts
                batch_size = 10
                all_subdomains = [sub.replace(f".{self.target}", "") for sub in subdomains]
                
                found_subdomains = []
                for i in range(0, len(all_subdomains), batch_size):
                    batch = all_subdomains[i:i+batch_size]
                    tasks = []
                    for subdomain in batch:
                        if subdomain:  # Skip empty subdomains
                            tasks.append(self._resolve_subdomain(subdomain))
                    
                    try:
                        async with asyncio.timeout(30):  # 30 second timeout per batch
                            logging.info(f"Processing batch {i//batch_size + 1}/{(len(all_subdomains) + batch_size - 1)//batch_size}")
                            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                            for result in batch_results:
                                if result is not None and not isinstance(result, Exception):
                                    found_subdomains.append(result)
                                    logging.info(f"Found valid subdomain: {result.get('subdomain')}")
                    except asyncio.TimeoutError:
                        logging.error(f"Batch resolution timed out for {len(tasks)} subdomains")
                    except Exception as e:
                        logging.error(f"Error processing subdomain batch: {str(e)}")
                    
                    # Add a small delay between batches to prevent overwhelming DNS servers
                    await asyncio.sleep(1)
                
                # Update results with proper structure
                results["subdomains"] = [
                    {
                        "subdomain": sub.get('subdomain', ''),
                        "ip_addresses": sub.get('ip_addresses', []),
                        "http_status": sub.get('http_status'),
                        "server": sub.get('server'),
                        "protocol": sub.get('protocol'),
                        "headers": sub.get('headers', {}),
                        "ssl_info": sub.get('ssl_info', {}),
                        "dns_records": {
                            rtype.lower(): sub.get(f'{rtype.lower()}_records', [])
                            for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV', 'CAA']
                            if f'{rtype.lower()}_records' in sub
                        }
                    }
                    for sub in found_subdomains
                    if isinstance(sub, dict) and 'subdomain' in sub
                ]
                
            except Exception as e:
                logging.error(f"Error in Sublist3r enumeration: {str(e)}")
                results["attack_surface"]["security_issues"].append({
                    "title": "Subdomain Enumeration Error",
                    "severity": "medium",
                    "description": f"Error during subdomain enumeration: {str(e)}",
                    "recommendation": "Review subdomain enumeration results manually"
                })
            
            logging.info(f"Subdomain scan completed for {self.target} - Found {len(results['subdomains'])} subdomains")
            return results
            
        except Exception as e:
            logging.error(f"Error in subdomain scan: {str(e)}")
            raise