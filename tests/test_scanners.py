import asyncio
import os
import sys
from dotenv import load_dotenv
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanners.domain_finder import DomainFinder
from src.scanners.port_scanner import PortScanner
from src.scanners.subdomain_finder import SubdomainFinder
from src.scanners.waf_detector import WAFDetector
from src.scanners.url_fuzzer import URLFuzzer
from src.scanners.tech_detector import TechDetector

async def test_scanner(scanner, target: str):
    print(f"\nTesting {scanner.__class__.__name__}")
    print("-" * 50)
    
    try:
        results = await scanner.scan(target)
        print("Results:")
        print(results)
    except Exception as e:
        print(f"Error: {str(e)}")

async def main():
    load_dotenv()
    
    # Use a known test target
    target = os.getenv('TEST_TARGET', 'example.com')
    
    scanners = [
        DomainFinder(),
        PortScanner(),
        SubdomainFinder(),
        WAFDetector(),
        URLFuzzer(),
        TechDetector()
    ]
    
    for scanner in scanners:
        await test_scanner(scanner, target)
        # Small delay between scans
        await asyncio.sleep(2)

if __name__ == "__main__":
    asyncio.run(main())