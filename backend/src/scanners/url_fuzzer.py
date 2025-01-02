import aiohttp
import asyncio
from typing import List, Dict
from scanners.base_scanner import BaseScanner
from utils.url_helper import URLHelper

class URLFuzzer(BaseScanner):
    def __init__(self, target: str):
        self.full_url, target_domain = URLHelper.normalize_url(target)
        super().__init__(target_domain)
        self.wordlists = {
            'common': [
                'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
                'dashboard', 'api', 'v1', 'v2', 'swagger', 'docs',
                '.git', '.env', 'backup', 'db', 'database', 'dev',
                'test', 'staging', 'prod', 'beta', 'debug', 'console',
                'wp-content', 'wp-includes', 'wp-config', 'config',
                'setup', 'install', 'admin.php', 'index.php', 'info.php'
            ],
            'sensitive': [
                'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'phpinfo.php',
                '.htaccess', '.htpasswd', '.svn', '.git/HEAD', '.env.backup',
                'backup.sql', 'dump.sql', 'database.sql', 'web.config',
                'server-status', 'server-info', '.well-known/security.txt'
            ],
            'extensions': ['.bak', '.old', '.backup', '.zip', '.tar.gz', '.sql', '.log']
        }
        
    async def _test_url(self, session: aiohttp.ClientSession, url: str) -> Dict:
        try:
            async with session.head(url, allow_redirects=True, timeout=5) as response:
                return {
                    'url': url,
                    'status': response.status,
                    'content_type': response.headers.get('content-type', ''),
                    'content_length': response.headers.get('content-length', ''),
                    'location': response.headers.get('location', '') if response.status in [301, 302] else None
                }
        except Exception as e:
            return None

    async def scan(self) -> dict:
        try:
            found_urls = []
            base_url = f"https://{self.target}"
            
            # Prepare URL combinations
            urls_to_test = set()
            
            # Add common paths
            urls_to_test.update([f"{base_url}/{word}" for word in self.wordlists['common']])
            
            # Add sensitive files
            urls_to_test.update([f"{base_url}/{file}" for file in self.wordlists['sensitive']])
            
            # Add common paths with extensions
            for word in self.wordlists['common']:
                for ext in self.wordlists['extensions']:
                    urls_to_test.add(f"{base_url}/{word}{ext}")
            
            # Test URLs concurrently
            async with aiohttp.ClientSession() as session:
                tasks = []
                for url in urls_to_test:
                    tasks.append(self._test_url(session, url))
                
                results = await asyncio.gather(*tasks)
                found_urls = [r for r in results if r is not None and r['status'] != 404]
            
            # Categorize findings
            sensitive_files = [url for url in found_urls 
                             if any(sensitive in url['url'] for sensitive in self.wordlists['sensitive'])]
            backup_files = [url for url in found_urls 
                          if any(ext in url['url'] for ext in self.wordlists['extensions'])]
            potential_vulnerabilities = [url for url in found_urls 
                                      if url['status'] in [500, 501, 502, 503]]
            
            self.results = {
                'target': self.target,
                'total_urls_tested': len(urls_to_test),
                'found_urls': found_urls,
                'findings': {
                    'sensitive_files': sensitive_files,
                    'backup_files': backup_files,
                    'potential_vulnerabilities': potential_vulnerabilities
                },
                'attack_surface': {
                    'total_findings': len(found_urls),
                    'sensitive_file_count': len(sensitive_files),
                    'backup_file_count': len(backup_files),
                    'server_error_count': len(potential_vulnerabilities),
                    'risk_level': 'HIGH' if sensitive_files or backup_files else 
                                 'MEDIUM' if potential_vulnerabilities else 'LOW'
                }
            }
            
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results