import nmap
from scanners.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        self.nm = nmap.PortScanner()  # Initialize nmap scanner without target
        
    async def scan(self) -> dict:
        try:
            # Perform the scan with target during scan operation
            self.nm.scan(self.target, arguments='-sV -sS -p-')
            
            # Process results
            self.results = {
                'target': self.target,
                'hosts': {}
            }
            
            for host in self.nm.all_hosts():
                self.results['hosts'][host] = {
                    'state': self.nm[host].state(),
                    'ports': self.nm[host]['tcp'] if 'tcp' in self.nm[host] else {}
                }
                
            return self.results
            
        except Exception as e:
            return {
                'error': str(e),
                'target': self.target
            }