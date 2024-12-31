import dns.resolver
import dns.zone
import socket
import whois
import requests
import ipaddress
from typing import Dict, Any, List
from scanners.base_scanner import BaseScanner
from utils.cve_cache import CVECache

class DomainFinder(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.cve_cache = CVECache()
        
    async def _safe_resolve(self, qname: str, rdtype: str) -> List:
        try:
            return list(dns.resolver.resolve(qname, rdtype))
        except dns.resolver.NoAnswer:
            print(f"No {rdtype} records found for {qname}")
            return []
        except dns.resolver.NXDOMAIN:
            print(f"Domain {qname} does not exist")
            return []
        except Exception as e:
            print(f"Error resolving {rdtype} records for {qname}: {str(e)}")
            return []

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
                'emails': w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
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
                    'abuse_contacts': data.get('abuse')
                }
        except Exception as e:
            print(f"Error getting IP info for {ip}: {str(e)}")
        
        return {'ip': ip}

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
                    'total_hosts': network.num_addresses
                }
            except Exception as e:
                print(f"Error analyzing IP range for {ip}: {str(e)}")
        return networks

    async def scan(self) -> dict:
        try:
            print(f"\nStarting comprehensive domain enumeration for {self.target}")
            
            # Get latest CVEs
            cve_data = await self.cve_cache.get_latest_cves()
            print(f"Loaded {len(cve_data.get('cves', []))} CVEs from cache")
            
            # Basic DNS records with safe resolution
            print("\nResolving A records...")
            a_records = await self._safe_resolve(self.target, 'A')
            
            print("\nResolving AAAA records...")
            aaaa_records = await self._safe_resolve(self.target, 'AAAA')
            
            print("\nResolving MX records...")
            mx_records = await self._safe_resolve(self.target, 'MX')
            
            print("\nResolving TXT records...")
            txt_records = await self._safe_resolve(self.target, 'TXT')
            
            print("\nResolving NS records...")
            ns_records = await self._safe_resolve(self.target, 'NS')
            
            print("\nResolving CAA records...")
            caa_records = await self._safe_resolve(self.target, 'CAA')
            
            print("\nResolving SRV records...")
            srv_records = await self._safe_resolve(self.target, 'SRV')
            
            # Additional security records
            spf_records = [txt for txt in txt_records if 'v=spf1' in str(txt)]
            dmarc_records = await self._safe_resolve(f"_dmarc.{self.target}", 'TXT')
            
            # Get WHOIS information
            print("\nGetting WHOIS information...")
            whois_info = await self._get_whois_info()
            
            # Get reverse DNS and IP information
            print("\nGathering IP information...")
            ip_info = []
            all_ips = []
            for records, ip_type in [(a_records, 'IPv4'), (aaaa_records, 'IPv6')]:
                for ip in [str(rdata) for rdata in records]:
                    all_ips.append(ip)
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        ip_details = await self._get_ip_info(ip)
                        ip_details.update({
                            'type': ip_type,
                            'hostname': hostname
                        })
                        ip_info.append(ip_details)
                        print(f"Found {ip_type} record: {ip} -> {hostname}")
                    except socket.herror:
                        ip_details = await self._get_ip_info(ip)
                        ip_details.update({
                            'type': ip_type,
                            'hostname': None
                        })
                        ip_info.append(ip_details)
                        print(f"Found {ip_type} record: {ip} (no reverse DNS)")
            
            # Analyze IP ranges
            print("\nAnalyzing IP ranges...")
            network_info = await self._analyze_ip_ranges(all_ips)
            
            # Analyze security posture
            security_issues = []
            if not spf_records:
                security_issues.append("Missing SPF record")
            if not dmarc_records:
                security_issues.append("Missing DMARC record")
            if len(ns_records) < 2:
                security_issues.append("Less than 2 nameservers")
            if not caa_records:
                security_issues.append("Missing CAA records")
            
            # Format nameserver information
            nameservers = []
            for ns in ns_records:
                ns_name = str(ns)
                try:
                    ns_ips = [str(ip) for ip in dns.resolver.resolve(ns_name, 'A')]
                    nameservers.append({
                        'hostname': ns_name,
                        'ip_addresses': ns_ips
                    })
                    print(f"Found nameserver: {ns_name} -> {', '.join(ns_ips)}")
                except Exception:
                    nameservers.append({
                        'hostname': ns_name,
                        'ip_addresses': []
                    })
                    print(f"Found nameserver: {ns_name}")
            
            # Format mail server information
            mail_servers = []
            for mx in mx_records:
                mx_name = str(mx.exchange)
                try:
                    mx_ips = [str(ip) for ip in dns.resolver.resolve(mx_name, 'A')]
                    mail_servers.append({
                        'hostname': mx_name,
                        'preference': mx.preference,
                        'ip_addresses': mx_ips
                    })
                    print(f"Found mail server: {mx_name} (preference: {mx.preference}) -> {', '.join(mx_ips)}")
                except Exception:
                    mail_servers.append({
                        'hostname': mx_name,
                        'preference': mx.preference,
                        'ip_addresses': []
                    })
                    print(f"Found mail server: {mx_name} (preference: {mx.preference})")
            
            self.results = {
                'target': self.target,
                'whois': whois_info,
                'ip_addresses': ip_info,
                'networks': network_info,
                'nameservers': nameservers,
                'mail_servers': mail_servers,
                'txt_records': [str(txt) for txt in txt_records],
                'spf_records': [str(spf) for spf in spf_records],
                'dmarc_records': [str(dmarc) for dmarc in dmarc_records],
                'caa_records': [str(caa) for caa in caa_records],
                'srv_records': [str(srv) for srv in srv_records],
                'attack_surface': {
                    'total_ips': len(ip_info),
                    'total_nameservers': len(nameservers),
                    'mail_servers': len(mail_servers),
                    'security_issues': security_issues,
                    'risk_level': 'HIGH' if len(security_issues) > 2 else 
                                'MEDIUM' if security_issues else 'LOW',
                    'network_exposure': {
                        'total_networks': len(network_info),
                        'public_ips': len([ip for ip in ip_info if not ipaddress.ip_address(ip['ip']).is_private]),
                        'private_ips': len([ip for ip in ip_info if ipaddress.ip_address(ip['ip']).is_private])
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