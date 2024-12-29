import requests
from scanners.base_scanner import BaseScanner
from utils.url_helper import URLHelper

class WAFDetector(BaseScanner):
    def __init__(self, target: str):
        self.full_url, target_domain = URLHelper.normalize_url(target)
        super().__init__(target_domain)
        
    async def scan(self) -> dict:
        try:
            # WAF detection patterns that typically trigger WAFs
            waf_detection_patterns = [
                {
                    'name': 'Generic XSS',
                    'payload': '<script>alert(1)</script>',
                    'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                },
                {
                    'name': 'SQL Injection',
                    'payload': "' OR '1'='1' --",
                    'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                },
                {
                    'name': 'Common WAF Headers',
                    'payload': '',
                    'headers': {
                        'X-Forwarded-For': '127.0.0.1',
                        'X-Remote-IP': '127.0.0.1',
                        'X-Originating-IP': '127.0.0.1',
                        'X-Remote-Addr': '127.0.0.1'
                    }
                }
            ]
            
            waf_indicators = {
                'headers': [
                    'x-waf',
                    'x-firewall',
                    'x-cdn',
                    'server',
                    'x-cache',
                    'x-powered-by'
                ],
                'waf_names': [
                    'cloudflare',
                    'akamai',
                    'aws',
                    'cloudfront',
                    'fastly',
                    'sucuri',
                    'incapsula',
                    'f5',
                    'nginx'
                ]
            }
            
            waf_detected = False
            waf_details = []
            
            # Test normal request first
            try:
                normal_response = requests.get(self.full_url, timeout=5)
                # Check headers for WAF indicators
                for header in normal_response.headers:
                    header_lower = header.lower()
                    value_lower = str(normal_response.headers[header]).lower()
                    
                    if header_lower in waf_indicators['headers']:
                        for waf in waf_indicators['waf_names']:
                            if waf in value_lower:
                                waf_detected = True
                                waf_details.append(f"WAF detected: {waf} (from {header})")
            except requests.RequestException:
                pass
            
            # Test WAF detection patterns
            test_results = []
            for pattern in waf_detection_patterns:
                try:
                    if pattern['payload']:
                        url = f"{self.full_url}?test={pattern['payload']}"
                    else:
                        url = self.full_url
                        
                    response = requests.get(
                        url,
                        headers=pattern['headers'],
                        timeout=5,
                        allow_redirects=False
                    )
                    
                    is_blocked = response.status_code in [403, 406, 429, 501, 502]
                    test_results.append({
                        'test_name': pattern['name'],
                        'blocked': is_blocked,
                        'status_code': response.status_code
                    })
                    
                    if is_blocked:
                        waf_detected = True
                        waf_details.append(f"WAF detected: Blocked {pattern['name']}")
                        
                except requests.RequestException as e:
                    test_results.append({
                        'test_name': pattern['name'],
                        'blocked': True,
                        'error': str(e)
                    })
            
            self.results = {
                'target': self.target,
                'full_url': self.full_url,
                'waf_detected': waf_detected,
                'waf_details': waf_details,
                'test_results': test_results,
                'attack_surface': {
                    'waf_effectiveness': sum(1 for test in test_results if test.get('blocked', False)) / len(test_results),
                    'protection_level': 'HIGH' if waf_detected and all(test.get('blocked', False) for test in test_results)
                                     else 'MEDIUM' if waf_detected
                                     else 'LOW'
                }
            }
            
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': self.target,
                'full_url': self.full_url
            }
            
        return self.results