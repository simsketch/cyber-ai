import dns.resolver
import dns.zone
import socket
import whois
import requests
import ipaddress
import ssl
import socket
import logging
from typing import Dict, Any, List
from scanners.base_scanner import BaseScanner
from utils.cve_cache import CVECache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.cve_cache = CVECache()
        self.dns_record_types = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA', 'SRV', 'PTR',
            'DNSKEY', 'DS', 'RRSIG', 'NSEC', 'NSEC3', 'CNAME', 'HINFO',
            'AFSDB', 'CERT', 'NAPTR', 'TLSA'
        ]
        
    async def _safe_resolve(self, qname: str, rdtype: str) -> List:
        logging.info(f"Attempting to resolve {rdtype} records for {qname}")
        
        # List of nameserver groups to try in order
        nameserver_groups = [
            ['8.8.8.8', '8.8.4.4'],  # Google DNS
            ['1.1.1.1', '1.0.0.1'],  # Cloudflare
            ['9.9.9.9'],             # Quad9
            ['208.67.222.222']       # OpenDNS
        ]
        
        last_error = None
        for nameservers in nameserver_groups:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                resolver.nameservers = nameservers
                resolver.rotate = True
                
                logging.info(f"Trying nameservers: {nameservers}")
                answers = list(resolver.resolve(qname, rdtype))
                
                if answers:
                    logging.info(f"Successfully resolved {len(answers)} {rdtype} records for {qname}")
                    for answer in answers:
                        logging.info(f"- {answer}")
                    return answers
                
            except dns.resolver.NoAnswer:
                logging.warning(f"No {rdtype} records found for {qname} using nameservers {nameservers}")
                last_error = f"No {rdtype} records found"
                continue
            except dns.resolver.NXDOMAIN:
                logging.error(f"Domain {qname} does not exist (using nameservers {nameservers})")
                last_error = "Domain does not exist"
                break  # No point trying other nameservers
            except dns.resolver.NoNameservers:
                logging.error(f"No nameservers could be reached for {qname} (using {nameservers})")
                last_error = "No nameservers reachable"
                continue
            except dns.exception.Timeout:
                logging.error(f"Timeout resolving {rdtype} records for {qname} (using nameservers {nameservers})")
                last_error = "Resolution timeout"
                continue
            except Exception as e:
                logging.error(f"Unexpected error resolving {rdtype} records for {qname} using {nameservers}: {str(e)}")
                last_error = str(e)
                continue
        
        if last_error:
            logging.error(f"All resolution attempts failed for {qname} {rdtype}: {last_error}")
        return []

    async def _get_ssl_info(self, hostname: str, port: int = 443) -> Dict:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            # Disable hostname verification for nameservers since they often use shared certificates
            if any(ns in hostname.lower() for ns in ['ns1', 'ns2', 'ns3', 'ns4', '.ns.', 'dns']):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'subjectAltName': [x[1] for x in cert['subjectAltName']],
                        'OCSP': cert.get('OCSP', []),
                        'caIssuers': cert.get('caIssuers', []),
                        'crlDistributionPoints': cert.get('crlDistributionPoints', [])
                    }
        except Exception as e:
            print(f"Error getting SSL info for {hostname}: {str(e)}")
            return {}

    async def _get_whois_info(self) -> Dict:
        """Get WHOIS information for the domain"""
        try:
            w = whois.whois(self.target)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
                'expiration_date': str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
                'last_updated': str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date),
                'status': w.status if isinstance(w.status, list) else [w.status],
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
                'emails': w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else [],
                'registrant': w.get('registrant', ''),
                'admin_contact': w.get('admin_contact', ''),
                'tech_contact': w.get('tech_contact', ''),
                'privacy_enabled': 'privacy' in str(w).lower() or 'redacted' in str(w).lower()
            }
        except Exception as e:
            print(f"Error getting WHOIS info: {str(e)}")
            return {}

    async def _get_ip_info(self, ip: str) -> Dict:
        """Get detailed information about an IP address"""
        try:
            # Get IP geolocation and network info
            response = requests.get(f"https://ipapi.co/{ip}/json/")
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'country': data.get('country_name'),
                    'region': data.get('region'),
                    'city': data.get('city'),
                    'org': data.get('org'),
                    'asn': data.get('asn'),
                    'network': data.get('network'),
                    'timezone': data.get('timezone'),
                    'abuse_contacts': data.get('abuse'),
                    'reverse_dns': await self._get_reverse_dns(ip),
                    'security_lists': await self._check_security_lists(ip)
                }
        except Exception as e:
            print(f"Error getting IP info for {ip}: {str(e)}")
        
        return {'ip': ip}

    async def _check_security_lists(self, ip: str) -> Dict:
        """Check IP against various security lists"""
        try:
            # Example security list check (you would need to implement actual API calls)
            return {
                'blacklisted': False,  # Placeholder
                'reputation_score': 0,  # Placeholder
                'threat_categories': []  # Placeholder
            }
        except Exception as e:
            print(f"Error checking security lists for {ip}: {str(e)}")
            return {}

    async def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS record for an IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    async def _analyze_ip_ranges(self, ips: List[str]) -> Dict:
        """Analyze IP ranges and networks"""
        networks = {}
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                else:
                    network = ipaddress.ip_network(f"{ip}/64", strict=False)
                networks[str(network)] = {
                    'version': ip_obj.version,
                    'is_private': ip_obj.is_private,
                    'is_global': ip_obj.is_global,
                    'reverse_pointer': ip_obj.reverse_pointer,
                    'network_address': str(network.network_address),
                    'broadcast_address': str(network.broadcast_address),
                    'total_hosts': network.num_addresses,
                    'network_range': f"{network.network_address}-{network.broadcast_address}",
                    'cloud_provider': self._detect_cloud_provider(ip)
                }
            except Exception as e:
                print(f"Error analyzing IP range for {ip}: {str(e)}")
        return networks

    def _detect_cloud_provider(self, ip: str) -> str:
        """Detect if IP belongs to a major cloud provider"""
        # This is a simplified example - you would need to implement actual cloud IP range checks
        return "Unknown"  # Placeholder

    async def scan(self) -> dict:
        try:
            print(f"\nStarting comprehensive domain enumeration for {self.target}")
            
            # Get latest CVEs
            cve_data = await self.cve_cache.get_latest_cves()
            print(f"Loaded {len(cve_data.get('cves', []))} CVEs from cache")
            
            # Comprehensive DNS enumeration
            dns_records = {}
            for record_type in self.dns_record_types:
                try:
                    print(f"\nResolving {record_type} records...")
                    records = await self._safe_resolve(self.target, record_type)
                    if records:
                        dns_records[record_type] = [str(record) for record in records]
                except Exception as e:
                    print(f"Error resolving {record_type} records: {str(e)}")
                    # Continue with next record type instead of failing
                    continue
            
            # Additional security records - make these non-blocking
            try:
                spf_records = [txt for txt in dns_records.get('TXT', []) if 'v=spf1' in str(txt)]
            except Exception:
                spf_records = []
            
            try:
                dmarc_records = await self._safe_resolve(f"_dmarc.{self.target}", 'TXT')
            except Exception:
                dmarc_records = []
            
            # Get WHOIS information
            print("\nGetting WHOIS information...")
            whois_info = await self._get_whois_info()
            
            # Get SSL certificate information
            print("\nGetting SSL certificate information...")
            ssl_info = await self._get_ssl_info(self.target)
            
            # Get reverse DNS and IP information
            print("\nGathering IP information...")
            ip_info = []
            all_ips = []
            
            # Process A and AAAA records
            for record_type, ip_type in [('A', 'IPv4'), ('AAAA', 'IPv6')]:
                records = dns_records.get(record_type, [])
                for ip in records:
                    all_ips.append(str(ip))
                    ip_details = await self._get_ip_info(str(ip))
                    ip_details.update({'type': ip_type})
                    ip_info.append(ip_details)
                    print(f"Found {ip_type} record: {ip}")
            
            # Analyze IP ranges
            print("\nAnalyzing IP ranges...")
            network_info = await self._analyze_ip_ranges(all_ips)
            
            # Format nameserver information
            nameservers = []
            for ns in dns_records.get('NS', []):
                ns_name = str(ns)
                try:
                    ns_ips = []
                    try:
                        ns_ips = [str(ip) for ip in dns.resolver.resolve(ns_name, 'A')]
                    except Exception as e:
                        print(f"Error resolving nameserver IPs for {ns_name}: {str(e)}")
                    
                    ssl_info = {}
                    try:
                        if 443 in await self._check_open_ports(ns_name):
                            ssl_info = await self._get_ssl_info(ns_name)
                    except Exception as e:
                        print(f"Error getting SSL info for nameserver {ns_name}: {str(e)}")
                    
                    nameservers.append({
                        'hostname': ns_name,
                        'ip_addresses': ns_ips,
                        'ssl_info': ssl_info
                    })
                    if ns_ips:
                        print(f"Found nameserver: {ns_name} -> {', '.join(ns_ips)}")
                except Exception as e:
                    print(f"Error processing nameserver {ns_name}: {str(e)}")
                    nameservers.append({
                        'hostname': ns_name,
                        'ip_addresses': [],
                        'error': str(e)
                    })
            
            # Format mail server information
            mail_servers = []
            for mx in dns_records.get('MX', []):
                try:
                    mx_obj = mx.split(' ')
                    mx_name = mx_obj[1] if len(mx_obj) > 1 else mx
                    mx_preference = int(mx_obj[0]) if len(mx_obj) > 1 else 0
                    
                    mx_ips = []
                    try:
                        mx_ips = [str(ip) for ip in dns.resolver.resolve(mx_name, 'A')]
                    except Exception as e:
                        print(f"Error resolving mail server IPs for {mx_name}: {str(e)}")
                    
                    ssl_info = {}
                    try:
                        if 443 in await self._check_open_ports(mx_name):
                            ssl_info = await self._get_ssl_info(mx_name)
                    except Exception as e:
                        print(f"Error getting SSL info for mail server {mx_name}: {str(e)}")
                    
                    mail_servers.append({
                        'hostname': mx_name,
                        'preference': mx_preference,
                        'ip_addresses': mx_ips,
                        'ssl_info': ssl_info
                    })
                except Exception as e:
                    print(f"Error processing MX record {mx}: {str(e)}")
                    continue

            # Enhanced security posture analysis
            security_issues = []
            if not spf_records:
                security_issues.append({
                    'issue': 'Missing SPF record',
                    'severity': 'HIGH',
                    'impact': 'Email spoofing possible',
                    'recommendation': 'Implement SPF record with appropriate policy'
                })
            if not dmarc_records:
                security_issues.append({
                    'issue': 'Missing DMARC record',
                    'severity': 'HIGH',
                    'impact': 'No email authentication policy',
                    'recommendation': 'Implement DMARC record with appropriate policy'
                })
            if len(nameservers) < 2:
                security_issues.append({
                    'issue': 'Insufficient nameservers',
                    'severity': 'MEDIUM',
                    'impact': 'Single point of failure for DNS',
                    'recommendation': 'Add additional nameservers for redundancy'
                })
            if not dns_records.get('CAA', []):
                security_issues.append({
                    'issue': 'Missing CAA records',
                    'severity': 'MEDIUM',
                    'impact': 'Unauthorized certificate issuance possible',
                    'recommendation': 'Implement CAA records to restrict certificate authorities'
                })
            if not dns_records.get('DNSKEY', []):
                security_issues.append({
                    'issue': 'DNSSEC not enabled',
                    'severity': 'MEDIUM',
                    'impact': 'DNS spoofing possible',
                    'recommendation': 'Enable DNSSEC for the domain'
                })

            # Calculate risk score
            risk_score = sum(3 for issue in security_issues if issue['severity'] == 'HIGH') + \
                        sum(2 for issue in security_issues if issue['severity'] == 'MEDIUM') + \
                        sum(1 for issue in security_issues if issue['severity'] == 'LOW')

            self.results = {
                'target': self.target,
                'whois': whois_info,
                'dns_records': dns_records,
                'ip_addresses': ip_info,
                'networks': network_info,
                'nameservers': nameservers,
                'mail_servers': mail_servers,
                'ssl_certificate': ssl_info,
                'security_records': {
                    'spf': spf_records,
                    'dmarc': [str(dmarc) for dmarc in dmarc_records],
                    'dnssec': bool(dns_records.get('DNSKEY', [])),
                    'caa': dns_records.get('CAA', [])
                },
                'attack_surface': {
                    'total_ips': len(ip_info),
                    'total_nameservers': len(nameservers),
                    'mail_servers': len(mail_servers),
                    'security_issues': security_issues,
                    'risk_score': risk_score,
                    'risk_level': 'CRITICAL' if risk_score > 10 else 
                                'HIGH' if risk_score > 7 else 
                                'MEDIUM' if risk_score > 4 else 'LOW',
                    'network_exposure': {
                        'total_networks': len(network_info),
                        'public_ips': len([ip for ip in ip_info if not ipaddress.ip_address(ip['ip']).is_private]),
                        'private_ips': len([ip for ip in ip_info if ipaddress.ip_address(ip['ip']).is_private]),
                        'cloud_hosted': any(net.get('cloud_provider', 'Unknown') != 'Unknown' 
                                         for net in network_info.values())
                    }
                }
            }
            
            print("\nDomain enumeration complete")
            
        except Exception as e:
            print(f"Error in domain scan: {str(e)}")
            self.results = {
                'error': str(e),
                'target': self.target
            }
        
        return self.results

    async def _check_open_ports(self, hostname: str) -> List[int]:
        """Check common ports on a hostname"""
        common_ports = [80, 443, 25, 587, 465]
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
        return open_ports