import asyncio
import os
from typing import Dict, Any, List
from dotenv import load_dotenv
from datetime import datetime
import json
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from agents.scan_agent import ScanAgent
from scanners.domain_finder import DomainFinder
from scanners.port_scanner import PortScanner
from scanners.subdomain_finder import SubdomainFinder
from scanners.waf_detector import WAFDetector
from scanners.url_fuzzer import URLFuzzer
from scanners.tech_detector import TechDetector
from scanners.vulnerability_scanner import VulnerabilityScanner

class SecurityOrchestrator:
    def __init__(self):
        load_dotenv()
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        self.target = os.getenv('SCAN_TARGET')
        
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        if not self.target:
            raise ValueError("SCAN_TARGET environment variable is required")
            
        self.scan_agent = ScanAgent(target=self.target, api_key=self.openai_api_key)
        self.console = Console()
        
        # Initialize all scanners
        self.scanners = {
            'domain': DomainFinder(target=self.target),
            'subdomain': SubdomainFinder(target=self.target),
            'port': PortScanner(target=self.target),
            'tech': TechDetector(target=self.target),
            'waf': WAFDetector(target=self.target),
            'fuzzer': URLFuzzer(target=self.target),
            'vulnerability': VulnerabilityScanner(target=self.target)
        }
        
        # Define scan order and dependencies
        self.scan_order = [
            'domain',      # Start with basic domain info
            'subdomain',   # Find subdomains
            'port',        # Scan ports on main domain and subdomains
            'tech',        # Identify technologies
            'waf',         # Detect WAF
            'fuzzer',      # Find sensitive URLs
            'vulnerability' # Test for vulnerabilities
        ]
        
        self.results_history = []
        
    async def run_scan(self, scanner_name: str) -> Dict[str, Any]:
        scanner = self.scanners.get(scanner_name)
        if not scanner:
            return {'error': f'Scanner {scanner_name} not found'}
            
        result = await scanner.scan()
        return result
        
    def _print_summary_table(self, results: Dict[str, Any]):
        table = Table(title=f"Security Scan Summary for {self.target}")
        table.add_column("Scanner", style="cyan")
        table.add_column("Findings", style="magenta")
        table.add_column("Risk Level", style="red")
        
        for result in results:
            scanner_type = result['scan_type']
            if 'error' in result['results']:
                table.add_row(
                    scanner_type,
                    f"Error: {result['results']['error']}",
                    "N/A"
                )
                continue
                
            findings = []
            risk_level = result['results'].get('attack_surface', {}).get('risk_level', 'LOW')
            
            if scanner_type == 'domain':
                findings.append(f"IPs: {result['results']['attack_surface']['total_ips']}")
                findings.append(f"Nameservers: {result['results']['attack_surface']['total_nameservers']}")
            elif scanner_type == 'subdomain':
                findings.append(f"Subdomains: {result['results']['attack_surface']['total_subdomains']}")
                if result['results']['zone_transfer_vulnerable']:
                    findings.append("Zone Transfer Vulnerable!")
            elif scanner_type == 'port':
                findings.append(f"Open Ports: {result['results']['attack_surface']['total_open_ports']}")
                findings.append(f"Services: {result['results']['attack_surface']['services_running']}")
            elif scanner_type == 'tech':
                missing_headers = result['results']['attack_surface']['missing_security_headers']
                findings.append(f"Missing Security Headers: {len(missing_headers)}")
                findings.append(f"Insecure Cookies: {result['results']['attack_surface']['insecure_cookies']}")
            elif scanner_type == 'waf':
                findings.append(f"WAF Detected: {result['results']['waf_detected']}")
                findings.append(f"Effectiveness: {result['results']['attack_surface']['waf_effectiveness']:.2%}")
            elif scanner_type == 'fuzzer':
                findings.append(f"Sensitive Files: {result['results']['attack_surface']['sensitive_file_count']}")
                findings.append(f"Backup Files: {result['results']['attack_surface']['backup_file_count']}")
            elif scanner_type == 'vulnerability':
                findings.append(f"Vulnerabilities: {result['results']['attack_surface']['total_vulnerabilities']}")
                findings.append(f"Types: {', '.join(result['results']['attack_surface']['vulnerability_types'])}")
            
            table.add_row(
                scanner_type,
                "\n".join(findings),
                risk_level
            )
        
        self.console.print(table)
        
    async def scan_target(self):
        self.console.print(f"[bold green]Starting comprehensive security scan for target: {self.target}[/bold green]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Running scans...", total=len(self.scan_order))
            
            for scanner_name in self.scan_order:
                progress.update(task, advance=1)
                self.console.print(f"[yellow]Running {scanner_name} scan...[/yellow]")
                
                result = await self.run_scan(scanner_name)
                self.results_history.append({
                    'scan_type': scanner_name,
                    'timestamp': datetime.now().isoformat(),
                    'results': result
                })
                
                # Check for high-risk findings
                if 'attack_surface' in result and result['attack_surface'].get('risk_level') == 'HIGH':
                    self.console.print(f"[bold red]High risk issues detected in {scanner_name} scan![/bold red]")
            
            # Generate summary and reports
            self.console.print("\n[green]Scan complete! Generating reports...[/green]")
            self._print_summary_table(self.results_history)
            
            # Generate detailed report
            report = await self.scan_agent.generate_report(self.results_history)
            
            # Save results
            output_dir = 'data/scan_results'
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            results_file = f"{output_dir}/scan_{timestamp}.json"
            report_file = f"{output_dir}/report_{timestamp}.md"
            
            with open(results_file, 'w') as f:
                json.dump(self.results_history, f, indent=2)
                
            with open(report_file, 'w') as f:
                f.write(report)
                
            self.console.print(f"[bold green]Results saved to {results_file}[/bold green]")
            self.console.print(f"[bold green]Report saved to {report_file}[/bold green]")

console = Console()

def check_env():
    # Print current working directory
    console.print(f"[yellow]Current working directory: {os.getcwd()}[/yellow]")
    
    # Load env vars
    load_dotenv()
    
    # Check if env vars are loaded
    api_key = os.getenv('OPENAI_API_KEY')
    target = os.getenv('SCAN_TARGET')
    
    console.print(f"[yellow]OPENAI_API_KEY exists: {bool(api_key)}[/yellow]")
    console.print(f"[yellow]SCAN_TARGET exists: {bool(target)}[/yellow]")
    
    if not api_key or not target:
        raise ValueError("OPENAI_API_KEY and SCAN_TARGET must be set in environment variables")
    
    return api_key, target

async def main():
    try:
        api_key, target = check_env()
        console.print(f"[green]Environment variables loaded successfully[/green]")
        
        orchestrator = SecurityOrchestrator()
        await orchestrator.scan_target()
        
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())