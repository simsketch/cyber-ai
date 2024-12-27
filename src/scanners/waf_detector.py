import aiohttp
import re
from typing import Dict, Any
from .base_scanner import BaseScanner

class WAFDetector(BaseScanner):
    def __init__(self):
        super().__init__()
        self.waf_signatures = {
            'Cloudflare': [
                'cloudflare-nginx',
                'cloudflare',
                '__cfduid',
                'cf-ray'
            ],
            'AWS WAF': [
                'x-amzn-RequestId',
                'x-amz-cf-id',
                'awselb'
            ],
            'Akamai': [
                'akamai',
                'ak_bmsc'
            ],
            'Imperva': [
                'incap_ses',
                'visid_incap',
                'incap_visid_83'
            ],
            'Sucuri': [
                'sucuri',
                'x-sucuri-id'
            ]
        }
        
    async def _check_headers(self, url: str) -> Dict[str, Any]:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    cookies = response.cookies
                    
                    detected_wafs = []
                    
                    # Check headers and cookies against signatures
                    all_values = [
                        *[v.lower() for v in headers.values()],
                        *[v.lower() for v in headers.keys()],
                        *[c.key.lower() for c in cookies.values()],
                        *[c.value.lower() for c in cookies.values()]
                    ]
                    
                    for waf_name, signatures in self.waf_signatures.items():
                        for sig in signatures:
                            if any(sig.lower() in value for value in all_values):
                                detected_wafs.append({
                                    'name': waf_name,
                                    'signature': sig,
                                    'confidence': 'HIGH'
                                })
                                break
                    
                    return {
                        'detected_wafs': detected_wafs,
                        'headers': headers,
                        'status_code': response.status
                    }
            except Exception as e:
                return {
                    'error': str(e),
                    'detected_wafs': []
                }
    
    async def _check_behavior(self, url: str) -> Dict[str, Any]:
        # Test with potentially malicious payloads to trigger WAF
        test_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "/?param=../../etc/passwd"
        ]
        
        results = []
        base_status = None
        
        async with aiohttp.ClientSession() as session:
            # First get baseline response
            try:
                async with session.get(url) as response:
                    base_status = response.status
            except:
                pass
            
            # Test each payload
            for payload in test_payloads:
                try:
                    test_url = f"{url}?test={payload}"
                    async with session.get(test_url) as response:
                        if response.status != base_status and response.status in [403, 406, 429, 503]:
                            results.append({
                                'payload': payload,
                                'triggered_status': response.status,
                                'base_status': base_status
                            })
                except Exception as e:
                    results.append({
                        'payload': payload,
                        'error': str(e)
                    })
                    
        return {
            'behavior_tests': results,
            'waf_likely': len([r for r in results if 'triggered_status' in r]) > 0
        }
    
    async def scan(self, target: str) -> Dict[str, Any]:
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'
            
        try:
            header_results = await self._check_headers(target)
            behavior_results = await self._check_behavior(target)
            
            self.results = {
                'target': target,
                'header_analysis': header_results,
                'behavior_analysis': behavior_results,
                'waf_detected': bool(header_results.get('detected_wafs') or behavior_results.get('waf_likely')),
                'confidence': 'HIGH' if header_results.get('detected_wafs') else 'MEDIUM' if behavior_results.get('waf_likely') else 'LOW'
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': target
            }
            
        return self.results