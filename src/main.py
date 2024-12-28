import asyncio
import os
from typing import Dict, Any, List
from dotenv import load_dotenv
from agents.scan_agent import ScanAgent
from scanners.domain_finder import DomainFinder
from scanners.port_scanner import PortScanner
from scanners.subdomain_finder import SubdomainFinder
from scanners.waf_detector import WAFDetector
from scanners.url_fuzzer import URLFuzzer
from scanners.tech_detector import TechDetector
import json
from datetime import datetime
from rich.console import Console
from rich.progress import Progress

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
        self.scanners = {
            'domain': DomainFinder(target=self.target),
            'port': PortScanner(target=self.target),
            'subdomain': SubdomainFinder(target=self.target),
            'waf': WAFDetector(target=self.target),
            'fuzzer': URLFuzzer(target=self.target),
            'tech': TechDetector(target=self.target)
        }
        self.results_history = []
        
    async def run_scan(self, scanner_name: str, target: str, params: Dict = None) -> Dict[str, Any]:
        scanner = self.scanners.get(scanner_name)
        if not scanner:
            return {'error': f'Scanner {scanner_name} not found'}
            
        result = await scanner.scan()
        return result
        
    async def scan_target(self, target: str, max_iterations: int = 5):
        self.console.print(f"[bold green]Starting security scan for target: {target}[/bold green]")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Running scans...", total=max_iterations)
            
            # Start with domain scan
            current_scan = 'domain'
            iterations = 0
            
            while current_scan and iterations < max_iterations:
                progress.update(task, advance=1)
                
                # Run current scan
                self.console.print(f"[yellow]Running {current_scan} scan...[/yellow]")
                result = await self.run_scan(current_scan, target)
                self.results_history.append({
                    'scan_type': current_scan,
                    'timestamp': datetime.now().isoformat(),
                    'results': result
                })
                
                # Analyze results and determine next scan
                analysis = await self.scan_agent.analyze_results(result)
                current_scan = analysis.get('next_scan')
                iterations += 1
                
                if analysis.get('risk_level') == 'HIGH':
                    self.console.print("[bold red]High risk issues detected![/bold red]")
                    
            # Generate final report
            self.console.print("[green]Generating final report...[/green]")
            report = self.scan_agent.generate_report(self.results_history)
            
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
                
            self.console.print(f"[bold green]Scan complete! Results saved to {results_file}[/bold green]")
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
        await orchestrator.scan_target(target)
        
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        exit(1)

if __name__ == "__main__":
    asyncio.run(main())