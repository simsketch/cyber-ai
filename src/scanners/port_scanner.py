import nmap
import asyncio
from typing import Dict, List
from scanners.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.nm = nmap.PortScanner()
        self.risky_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            137: 'NetBIOS',
            139: 'NetBIOS',
            443: 'HTTPS',
            445: 'SMB',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-ALT',
            27017: 'MongoDB'
        }

    async def _run_scan(self, target: str, ports: str, arguments: str) -> Dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.nm.scan(target, ports, arguments)
        )

    async def scan(self) -> dict:
        try:
            print(f"Starting port scan for {self.target}")
            
            # First quick scan for common ports without requiring root
            await self._run_scan(self.target, None, '-Pn -T4 -sT -F --version-intensity 5')
            initial_results = self.nm.scaninfo()
            
            # If less than 10 ports found, do a more thorough scan
            total_open = sum(len(self.nm[host][proto].keys()) 
                           for host in self.nm.all_hosts() 
                           for proto in self.nm[host].all_protocols())
            
            if total_open < 10:
                print("Few ports found, running more thorough scan...")
                await self._run_scan(self.target, '1-1000', '-Pn -sT --version-intensity 7')
            
            hosts_info = []
            findings = []
            vulnerabilities = []
            
            for host in self.nm.all_hosts():
                host_info = {
                    'ip': host,
                    'status': self.nm[host].state(),
                    'os_match': self.nm[host].get('osmatch', []),
                    'ports': []
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        service_detail = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'cpe': port_info.get('cpe', [])
                        }
                        host_info['ports'].append(service_detail)
                        
                        # Analyze for vulnerabilities
                        if service_detail['state'] == 'open':
                            if port in self.risky_ports:
                                severity = 'high' if port in [21, 23, 3389] else 'medium'
                                finding = {
                                    'title': f'Open {self.risky_ports[port]} Port',
                                    'description': (f'Found open {self.risky_ports[port]} port ({port}) '
                                                  f'running {service_detail["product"]} {service_detail["version"]}'),
                                    'severity': severity,
                                    'evidence': service_detail,
                                    'remediation': f'Review and restrict access to {self.risky_ports[port]} port {port}'
                                }
                                findings.append(finding)
                            
                            # Check for version-specific vulnerabilities
                            if service_detail['version']:
                                vulnerabilities.append({
                                    'service': service_detail['service'],
                                    'product': service_detail['product'],
                                    'version': service_detail['version'],
                                    'port': port
                                })
                
                hosts_info.append(host_info)
            
            risk_score = sum(1 for f in findings if f['severity'] == 'high') * 3 + \
                        sum(1 for f in findings if f['severity'] == 'medium') * 2 + \
                        sum(1 for f in findings if f['severity'] == 'low')
            
            self.results = {
                'target': self.target,
                'hosts': hosts_info,
                'findings': findings,
                'vulnerabilities': vulnerabilities,
                'attack_surface': {
                    'total_open_ports': total_open,
                    'high_risk_ports': len([f for f in findings if f['severity'] == 'high']),
                    'medium_risk_ports': len([f for f in findings if f['severity'] == 'medium']),
                    'risk_score': risk_score,
                    'risk_level': 'HIGH' if risk_score > 10 else 'MEDIUM' if risk_score > 5 else 'LOW'
                }
            }
            
        except Exception as e:
            print(f"Error in port scan: {str(e)}")
            self.results = {
                'error': str(e),
                'target': self.target
            }
        
        return self.results