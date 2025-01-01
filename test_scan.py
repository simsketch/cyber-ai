import asyncio
import dns.resolver
import logging
from datetime import datetime
from scanners.subdomain_finder import SubdomainFinder
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def test_dns_resolution(target):
    logging.info(f"Testing DNS resolution for {target}")
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    
    try:
        # Test A record
        answers = resolver.resolve(target, 'A')
        logging.info(f"A records: {[str(rdata) for rdata in answers]}")
        
        # Test NS records
        ns_records = resolver.resolve(target, 'NS')
        logging.info(f"NS records: {[str(ns) for ns in ns_records]}")
        
        # Test MX records
        mx_records = resolver.resolve(target, 'MX')
        logging.info(f"MX records: {[str(mx) for mx in mx_records]}")
        
        return True
    except Exception as e:
        logging.error(f"DNS resolution error: {str(e)}")
        return False

async def run_subdomain_scan(target):
    logging.info(f"Starting subdomain scan for {target}")
    scanner = SubdomainFinder(target)
    
    try:
        # Test certificate transparency first
        logging.info("Checking certificate transparency logs...")
        ct_results = await scanner._check_cert_transparency()
        if ct_results:
            logging.info(f"Found {len(ct_results)} domains in CT logs")
            for domain in ct_results:
                logging.info(f"CT Log Domain: {domain}")
        
        # Run the full scan
        logging.info("Starting full subdomain scan...")
        results = await scanner.scan()
        return results
    except Exception as e:
        logging.error(f"Scan error: {str(e)}")
        return None

async def main():
    target = "hackthebox.com"
    start_time = datetime.now()
    logging.info(f"Starting scan at {start_time}")
    
    # Basic DNS resolution test
    if not await test_dns_resolution(target):
        logging.error("Basic DNS resolution failed")
        return
    
    # Run the full subdomain scan
    results = await run_subdomain_scan(target)
    if results:
        logging.info("\nScan Results:")
        print(json.dumps(results, indent=2))
    
    end_time = datetime.now()
    duration = end_time - start_time
    logging.info(f"\nScan completed in {duration.total_seconds():.2f} seconds")

if __name__ == "__main__":
    asyncio.run(main()) 