import aiohttp
from bs4 import BeautifulSoup
import re
from typing import Dict, Any, List
from .base_scanner import BaseScanner

class TechDetector(BaseScanner):
    def __init__(self):
        super().__init__()
        self.tech_signatures = {
            'WordPress': {
                'headers': ['x-powered-by: wordpress'],
                'meta': ['generator.*wordpress'],
                'scripts': ['wp-content', 'wp-includes'],
                'html': ['wp-content', 'wp-includes']
            },
            'Drupal': {
                'headers': ['x-generator.*drupal'],
                'meta': ['generator.*drupal'],
                'scripts': ['drupal.js'],
                'html': ['sites/default/files']
            },
            'Joomla': {
                'headers': [],
                'meta': ['generator.*joomla'],
                'scripts': ['/media/system/js/'],
                'html': ['/media/system/js/']
            },
            'Django': {
                'headers': ['csrftoken'],
                'meta': [],
                'scripts': ['django'],
                'html': ['csrfmiddlewaretoken']
            },
            'React': {
                'headers': [],
                'meta': [],
                'scripts': ['react.js', 'react.min.js', 'react.production.min.js'],
                'html': ['data-reactroot', 'react-app']
            },
            'Angular': {
                'headers': [],
                'meta': [],
                'scripts': ['angular.js', 'angular.min.js'],
                'html': ['ng-app', 'ng-controller']
            },
            'Vue.js': {
                'headers': [],
                'meta': [],
                'scripts': ['vue.js', 'vue.min.js'],
                'html': ['v-app', 'v-bind']
            },
            'jQuery': {
                'headers': [],
                'meta': [],
                'scripts': ['jquery.js', 'jquery.min.js'],
                'html': ['jquery']
            },
            'Bootstrap': {
                'headers': [],
                'meta': [],
                'scripts': ['bootstrap.js', 'bootstrap.min.js'],
                'html': ['bootstrap']
            },
            'PHP': {
                'headers': ['x-powered-by: php'],
                'meta': [],
                'scripts': ['.php'],
                'html': []
            },
            'ASP.NET': {
                'headers': ['x-aspnet-version', 'x-powered-by: asp.net'],
                'meta': [],
                'scripts': ['.aspx'],
                'html': ['__viewstate']
            },
            'Nginx': {
                'headers': ['server: nginx'],
                'meta': [],
                'scripts': [],
                'html': []
            },
            'Apache': {
                'headers': ['server: apache'],
                'meta': [],
                'scripts': [],
                'html': []
            }
        }
        
    def _check_signature(self, content: str, signatures: List[str]) -> List[str]:
        matches = []
        for sig in signatures:
            if re.search(sig, content, re.I):
                matches.append(sig)
        return matches
        
    async def _analyze_page(self, url: str) -> Dict[str, Any]:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            
        detected_tech = {}
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    html = await response.text()
                    
                    # Parse HTML
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract meta tags
                    meta_content = ' '.join([str(tag) for tag in soup.find_all('meta')])
                    
                    # Extract scripts
                    scripts_content = ' '.join([str(tag) for tag in soup.find_all('script')])
                    
                    # Check each technology signature
                    for tech, sigs in self.tech_signatures.items():
                        matches = []
                        
                        # Check headers
                        header_matches = self._check_signature(
                            ' '.join([f"{k}: {v}" for k, v in headers.items()]).lower(),
                            sigs['headers']
                        )
                        if header_matches:
                            matches.extend(header_matches)
                            
                        # Check meta tags
                        meta_matches = self._check_signature(meta_content.lower(), sigs['meta'])
                        if meta_matches:
                            matches.extend(meta_matches)
                            
                        # Check scripts
                        script_matches = self._check_signature(scripts_content.lower(), sigs['scripts'])
                        if script_matches:
                            matches.extend(script_matches)
                            
                        # Check HTML content
                        html_matches = self._check_signature(html.lower(), sigs['html'])
                        if html_matches:
                            matches.extend(html_matches)
                            
                        if matches:
                            detected_tech[tech] = {
                                'confidence': 'HIGH' if len(matches) > 2 else 'MEDIUM',
                                'matches': matches
                            }
                            
                    return {
                        'technologies': detected_tech,
                        'headers': headers,
                        'status_code': response.status
                    }
                    
            except Exception as e:
                return {
                    'error': str(e)
                }
                
    def _assess_security_implications(self, tech_results: Dict[str, Any]) -> Dict[str, Any]:
        security_implications = []
        risk_level = 'LOW'
        
        # Check for known security implications
        detected_tech = tech_results.get('technologies', {})
        
        for tech, details in detected_tech.items():
            if tech == 'WordPress':
                security_implications.append({
                    'technology': tech,
                    'implication': 'WordPress sites often face plugin vulnerabilities and brute force attacks',
                    'recommendation': 'Ensure WordPress and all plugins are up to date, implement security plugins'
                })
                risk_level = 'MEDIUM'
                
            elif tech == 'PHP':
                security_implications.append({
                    'technology': tech,
                    'implication': 'PHP applications can be vulnerable to injection attacks if not properly secured',
                    'recommendation': 'Ensure latest PHP version, implement proper input validation'
                })
                risk_level = 'MEDIUM'
                
            elif tech == 'jQuery':
                if details['confidence'] == 'HIGH':
                    security_implications.append({
                        'technology': tech,
                        'implication': 'Outdated jQuery versions can have XSS vulnerabilities',
                        'recommendation': 'Update to latest jQuery version'
                    })
                    
        return {
            'implications': security_implications,
            'risk_level': risk_level
        }
    
    async def scan(self, target: str) -> Dict[str, Any]:
        try:
            tech_results = await self._analyze_page(target)
            security_assessment = self._assess_security_implications(tech_results)
            
            self.results = {
                'target': target,
                'technology_detection': tech_results,
                'security_assessment': security_assessment
            }
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': target
            }
            
        return self.results