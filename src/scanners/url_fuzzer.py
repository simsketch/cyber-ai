import aiohttp
import asyncio
from typing import Dict, Any, List
from .base_scanner import BaseScanner

class URLFuzzer(BaseScanner):
    def __init__(self):
        super().__init__()
        self.common_paths = [
            'admin',
            'login',
            'wp-admin',
            'administrator',
            'phpmyadmin',
            'dashboard',
            'api',
            'v1',
            'v2',
            'console',
            'cms',
            'wp-content',
            'backup',
            'dev',
            'test',
            'staging',
            '.git',
            '.env',
            'config',
            'setup',
            'install'
        ]
        
        self.common_extensions = [
            '',
            '/',
            '.php',
            '.html',
            '.asp',
            '.aspx',
            '.jsp',
            '.js',
            '.txt',
            '.bak',
            '.old',
            '.zip',
            '.tar.gz',
            '.sql'
        ]
        
    async def _test_url(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        try:
            async with session.get(url, allow_redirects=True) as response:
                return {
                    'url': url,
                    'status': response.status,
                    'content_type': response.headers.get('content-type', ''),
                    'content_length': response.headers.get('content-length', ''),
                    'location': response.headers.get('location', '') if response.status in [301, 302, 307, 308] else None
                }
        except Exception as e:
            return {
                'url': url,
                'error': str(e)
            }
            
    async def _fuzz_paths(self, base_url: str) -> List[Dict[str, Any]]:
        if not base_url.startswith(('http://', 'https://')):
            base_url = f'https://{base_url}'
            
        if not base_url.endswith('/'):
            base_url += '/'
            
        results = []
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            # Generate URLs to test
            for path in self.common_paths:
                for ext in self.common_extensions:
                    url = f"{base_url}{path}{ext}"
                    tasks.append(self._test_url(session, url))
                    
            # Run tests concurrently in batches
            batch_size = 10
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch)
                results.extend(batch_results)
                
                # Small delay to avoid overwhelming the server
                await asyncio.sleep(0.5)
                
        return results
        
    def _analyze_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        interesting_findings = []
        
        for result in results:
            # Skip errors
            if 'error' in result:
                continue
                
            # Check for interesting responses
            if result['status'] in [200, 201, 301, 302, 401, 403]:
                finding = {
                    'url': result['url'],
                    'status': result['status'],
                    'interesting_factors': []
                }
                
                # Check for sensitive paths
                sensitive_keywords = ['admin', 'login', 'config', 'backup', 'test', 'dev']
                if any(keyword in result['url'].lower() for keyword in sensitive_keywords):
                    finding['interesting_factors'].append('sensitive_path')
                    
                # Check for interesting content types
                if 'application/json' in result.get('content_type', ''):
                    finding['interesting_factors'].append('api_endpoint')
                    
                # Check for redirects to interesting locations
                if result.get('location') and any(keyword in result['location'].lower() for keyword in sensitive_keywords):
                    finding['interesting_factors'].append('sensitive_redirect')
                    
                if finding['interesting_factors']:
                    interesting_findings.append(finding)
                    
        return {
            'total_urls_tested': len(results),
            'interesting_findings': interesting_findings,
            'errors': [r for r in results if 'error' in r]
        }
    
    async def scan(self, target: str) -> Dict[str, Any]:
        try:
            fuzz_results = await self._fuzz_paths(target)
            analysis = self._analyze_results(fuzz_results)
            
            self.results = {
                'target': target,
                'analysis': analysis,
                'risk_level': 'HIGH' if len(analysis['interesting_findings']) > 5 else 
                             'MEDIUM' if len(analysis['interesting_findings']) > 0 else 
                             'LOW'
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': target
            }
            
        return self.results