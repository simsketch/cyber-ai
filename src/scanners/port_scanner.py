import nmap
from scanners.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.nm = nmap.PortScanner()
        self.risky_ports = {
            21: "FTP",
            23: "Telnet",
            135: "RPC",
            137: "NetBIOS",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL"
        }
        
    async def scan(self) -> dict:
        try:
            # Scan top 100 ports with service version detection and OS detection
            self.nm.scan(self.target, arguments='-sV -sS -O -F')
            
            scan_info = self.nm.scaninfo()
            hosts_info = []
            findings = []
            
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
                        port_data = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        }
                        host_info['ports'].append(port_data)
                        
                        # Check for risky open ports
                        if port_data['state'] == 'open':
                            if port in self.risky_ports:
                                findings.append({
                                    'title': f'Open {self.risky_ports[port]} Port',
                                    'description': f'Found open {self.risky_ports[port]} port ({port}) on {host}. '
                                                 f'Service: {port_data["service"]} {port_data["product"]} {port_data["version"]}',
                                    'severity': 'high' if port in [21, 23, 3389] else 'medium',
                                    'remediation': f'Consider closing or restricting access to {self.risky_ports[port]} port {port}'
                                })
                            elif port < 1024:
                                findings.append({
                                    'title': f'Open Privileged Port {port}',
                                    'description': f'Found open privileged port {port} on {host}. '
                                                 f'Service: {port_data["service"]} {port_data["product"]} {port_data["version"]}',
                                    'severity': 'low',
                                    'remediation': 'Review if this port needs to be open and restrict access if possible'
                                })
                
                hosts_info.append(host_info)
            
            self.results = {
                'target': self.target,
                'scan_info': scan_info,
                'hosts': hosts_info,
                'findings': findings,
                'attack_surface': {
                    'total_open_ports': sum(len([p for p in host['ports'] if p['state'] == 'open']) 
                                          for host in hosts_info),
                    'services_running': len(set(p['service'] for host in hosts_info 
                                              for p in host['ports'] if p['state'] == 'open'))
                }
            }
            
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results