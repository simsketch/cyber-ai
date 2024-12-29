import nmap
from scanners.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.nm = nmap.PortScanner()
        
    async def scan(self) -> dict:
        try:
            # Scan top 100 ports with service version detection and OS detection
            self.nm.scan(self.target, arguments='-sV -sS -O -F')
            
            scan_info = self.nm.scaninfo()
            hosts_info = []
            
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
                        host_info['ports'].append({
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', '')
                        })
                
                hosts_info.append(host_info)
            
            self.results = {
                'target': self.target,
                'scan_info': scan_info,
                'hosts': hosts_info,
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