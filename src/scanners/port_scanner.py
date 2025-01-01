import nmap
import asyncio
from typing import Dict, List
from scanners.base_scanner import BaseScanner
import logging

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
        logging.info(f"Initialized PortScanner for {target}")

    async def _run_scan(self, target: str, ports: str, arguments: str) -> Dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.nm.scan(target, arguments=f"{arguments} {'-p' + ports if ports else ''}")
        )

    async def scan(self) -> dict:
        """Run port scan"""
        try:
            logging.info(f"Starting port scan steps for {self.target}")
            
            # Initialize results
            results = {
                "open_ports": [],
                "services": []
            }
            
            # DNS resolution
            logging.info("Resolving target DNS...")
            
            # Quick initial scan
            logging.info("Starting quick port scan...")
            await self._run_scan(self.target, None, '-Pn -T4 -sV -F --version-intensity 5')
            
            # Process results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if port_info['state'] == 'open':
                            service_detail = {
                                'port': port,
                                'protocol': proto,
                                'service': port_info['name'],
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'state': port_info['state']
                            }
                            results["open_ports"].append(service_detail)
                            if service_detail['service'] not in results["services"]:
                                results["services"].append(service_detail['service'])
            
            logging.info(f"Port scan completed for {self.target} - Found {len(results['open_ports'])} open ports")
            return results
            
        except Exception as e:
            logging.error(f"Error in port scan: {str(e)}")
            raise