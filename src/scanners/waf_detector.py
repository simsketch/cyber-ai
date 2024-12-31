import requests
import re
from typing import Dict, List, Optional
from scanners.base_scanner import BaseScanner
from utils.url_helper import URLHelper

class WAFDetector(BaseScanner):
    def __init__(self, target: str):
        self.full_url, target_domain = URLHelper.normalize_url(target)
        super().__init__(target_domain)
        self.waf_signatures = {
            'Cloudflare': {
                'headers': {
                    'server': r'cloudflare',
                    'cf-ray': r'.*',
                    'cf-cache-status': r'.*'
                },
                'cookies': ['__cfduid', 'cf_clearance'],
                'blocks': ['Error 1015', 'CF-Browser-Verification']
            },
            'AWS WAF': {
                'headers': {'x-amzn-requestid': r'.*'},
                'blocks': ['AWS WAF', 'Request blocked']
            },
            'Akamai': {
                'headers': {
                    'server': r'AkamaiGHost',
                    'x-akamai-transformed': r'.*'
                },
                'blocks': ['Access Denied', 'Your request was blocked']
            },
            'Imperva/Incapsula': {
                'headers': {
                    'x-iinfo': r'.*',
                    'x-cdn': r'Incapsula'
                },
                'cookies': ['incap_ses', 'visid_incap'],
                'blocks': ['Incapsula Incident', 'Access Denied']
            },
            'F5 BIG-IP ASM': {
                'headers': {
                    'server': r'BigIP',
                    'x-cnection': r'close'
                },
                'cookies': ['TS', 'BIGipServer'],
                'blocks': ['The requested URL was rejected']
            },
            'Sucuri': {
                'headers': {'x-sucuri-id': r'.*'},
                'blocks': ['Access Denied - Sucuri Website Firewall']
            },
            'Fastly': {
                'headers': {
                    'x-fastly-request-id': r'.*',
                    'fastly-client': r'.*'
                }
            },
            'ModSecurity': {
                'headers': {'server': r'mod_security|NOYB'},
                'blocks': ['ModSecurity Action', 'ModSecurity Rule']
            }
        }
        
    async def _send_test_request(self, url: str, payload: Dict) -> Dict:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                **payload.get('headers', {})
            }
            
            if payload.get('method', 'GET') == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload.get('data', ''),
                    timeout=10,
                    allow_redirects=False
                )
            else:
                test_url = f"{url}?{payload.get('query', '')}" if payload.get('query') else url
                response = requests.get(
                    test_url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False
                )
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:1000],  # First 1000 chars for analysis
                'response_time': response.elapsed.total_seconds()
            }
        except requests.RequestException as e:
            return {
                'error': str(e),
                'status_code': None,
                'headers': {},
                'body': ''
            }

    def _analyze_response(self, response: Dict, waf_name: str) -> Optional[Dict]:
        signatures = self.waf_signatures[waf_name]
        matches = []
        
        # Check headers
        if 'headers' in signatures:
            for header, pattern in signatures['headers'].items():
                header_value = response['headers'].get(header.lower())
                if header_value and re.search(pattern, header_value, re.I):
                    matches.append(f"Header match: {header}")
        
        # Check cookies
        if 'cookies' in signatures:
            for cookie in signatures['cookies']:
                for response_cookie in response['headers'].get('set-cookie', '').split(','):
                    if cookie.lower() in response_cookie.lower():
                        matches.append(f"Cookie match: {cookie}")
        
        # Check block messages
        if 'blocks' in signatures:
            for block in signatures['blocks']:
                if block.lower() in response['body'].lower():
                    matches.append(f"Block message: {block}")
        
        if matches:
            return {
                'waf': waf_name,
                'confidence': len(matches),
                'matches': matches
            }
        return None

    async def scan(self) -> dict:
        try:
            print(f"Starting WAF detection for {self.target}")
            
            # Test payloads designed to trigger WAF responses
            test_payloads = [
                {
                    'name': 'SQL Injection',
                    'query': "id=1' OR '1'='1",
                    'headers': {'X-Forwarded-For': '127.0.0.1'}
                },
                {
                    'name': 'XSS',
                    'query': "q=<script>alert(1)</script>",
                    'headers': {'X-Requested-With': 'XMLHttpRequest'}
                },
                {
                    'name': 'Path Traversal',
                    'query': "file=../../../etc/passwd",
                    'headers': {'Accept': '*/*'}
                },
                {
                    'name': 'Command Injection',
                    'method': 'POST',
                    'data': "cmd=cat /etc/passwd",
                    'headers': {'Content-Type': 'application/x-www-form-urlencoded'}
                },
                {
                    'name': 'User-Agent',
                    'headers': {'User-Agent': 'sqlmap/1.0-dev'}
                }
            ]
            
            waf_findings = []
            baseline_response = await self._send_test_request(self.full_url, {})
            
            # Check baseline response for WAF signatures
            for waf_name in self.waf_signatures:
                finding = self._analyze_response(baseline_response, waf_name)
                if finding:
                    waf_findings.append(finding)
            
            # Test with attack payloads
            for payload in test_payloads:
                print(f"Testing {payload['name']} payload...")
                response = await self._send_test_request(self.full_url, payload)
                
                # Skip if request failed
                if 'error' in response:
                    continue
                
                # Analyze response for WAF behavior
                is_blocked = (
                    response['status_code'] in [403, 406, 429, 501, 502] or
                    response['status_code'] != baseline_response['status_code'] or
                    abs(response['response_time'] - baseline_response['response_time']) > 2
                )
                
                if is_blocked:
                    for waf_name in self.waf_signatures:
                        finding = self._analyze_response(response, waf_name)
                        if finding:
                            finding['triggered_by'] = payload['name']
                            if finding not in waf_findings:
                                waf_findings.append(finding)
            
            # Calculate detection confidence and risk metrics
            detected_wafs = len(waf_findings)
            highest_confidence = max([f['confidence'] for f in waf_findings]) if waf_findings else 0
            
            self.results = {
                'target': self.target,
                'waf_detected': bool(waf_findings),
                'findings': waf_findings,
                'attack_surface': {
                    'detected_wafs': detected_wafs,
                    'highest_confidence': highest_confidence,
                    'protection_level': 'HIGH' if detected_wafs > 1 or highest_confidence > 3 else
                                     'MEDIUM' if detected_wafs == 1 else 'LOW',
                    'bypass_potential': 'LOW' if detected_wafs > 1 else
                                     'MEDIUM' if detected_wafs == 1 else 'HIGH'
                }
            }
            
        except Exception as e:
            print(f"Error in WAF detection: {str(e)}")
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results