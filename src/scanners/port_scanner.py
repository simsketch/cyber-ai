import nmap
from typing import Dict, Any
from .base_scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.nm = nmap.PortScanner()
        
    async def scan(self, target: str) -> Dict[str, Any]:
        try:
            # Run a SYN scan on common ports
            self.nm.scan(target, arguments='-sS -sV -F --version-intensity 5')
            
            scan_results = {}
            for host in self.nm.all_hosts():
                host_data = {
                    'state': self.nm[host].state(),
                    'ports': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_data = self.nm[host][proto][port]
                        host_data['ports'][port] = {
                            'state': port_data['state'],
                            'service': port_data['name'],
                            'version': port_data.get('version', ''),
                            'product': port_data.get('product', '')
                        }
                        
                scan_results[host] = host_data
            
            self.results = {
                'target': target,
                'scan_results': scan_results
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': target
            }
            
        return self.results