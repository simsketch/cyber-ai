import requests
from bs4 import BeautifulSoup
import re
import json
from typing import Dict, List, Optional
from scanners.base_scanner import BaseScanner
from utils.url_helper import URLHelper

class TechDetector(BaseScanner):
    def __init__(self, target: str):
        self.full_url, target_domain = URLHelper.normalize_url(target)
        super().__init__(target_domain)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def _detect_cms(self, soup: BeautifulSoup, headers: Dict, body: str) -> Dict[str, str]:
        cms_patterns = {
            'WordPress': {
                'meta': {'generator': r'WordPress'},
                'headers': {'x-powered-by': r'WordPress'},
                'body': [r'wp-content', r'wp-includes'],
                'paths': ['/wp-admin/', '/wp-login.php']
            },
            'Drupal': {
                'meta': {'generator': r'Drupal'},
                'body': [r'Drupal.settings', r'/sites/default/files'],
                'paths': ['/user/login', '/admin']
            },
            'Joomla': {
                'meta': {'generator': r'Joomla'},
                'body': [r'joomla!', r'/components/com_'],
                'paths': ['/administrator/', '/components/']
            },
            'Ghost': {
                'meta': {'generator': r'Ghost'},
                'body': [r'ghost-blog', r'ghost-theme'],
                'paths': ['/ghost/']
            }
        }
        
        detected = {}
        for cms, patterns in cms_patterns.items():
            # Check meta tags
            if 'meta' in patterns:
                for meta in soup.find_all('meta', attrs={'name': 'generator'}):
                    content = meta.get('content', '').lower()
                    for pattern in patterns['meta'].values():
                        if re.search(pattern.lower(), content):
                            detected[cms] = self._get_version_from_meta(soup, cms)
            
            # Check headers
            if 'headers' in patterns:
                for header, pattern in patterns['headers'].items():
                    if header.lower() in headers:
                        if re.search(pattern.lower(), headers[header.lower()]):
                            detected[cms] = self._get_version_from_headers(headers, cms)
            
            # Check body patterns
            if 'body' in patterns:
                for pattern in patterns['body']:
                    if re.search(pattern.lower(), body.lower()):
                        detected[cms] = detected.get(cms) or 'detected'
            
            # Check paths
            if 'paths' in patterns:
                for path in patterns['paths']:
                    try:
                        response = requests.head(f"https://{self.target}{path}", 
                                              headers=self.headers, 
                                              timeout=5)
                        if response.status_code != 404:
                            detected[cms] = detected.get(cms) or 'detected'
                    except:
                        continue
        
        return detected
    
    def _get_version_from_meta(self, soup: BeautifulSoup, cms: str) -> Optional[str]:
        version_patterns = {
            'WordPress': r'WordPress\s+([\d.]+)',
            'Drupal': r'Drupal\s+([\d.]+)',
            'Joomla': r'Joomla!\s+([\d.]+)'
        }
        if cms in version_patterns:
            for meta in soup.find_all('meta', attrs={'name': 'generator'}):
                content = meta.get('content', '')
                match = re.search(version_patterns[cms], content)
                if match:
                    return match.group(1)
        return None
    
    def _get_version_from_headers(self, headers: Dict, cms: str) -> Optional[str]:
        version_patterns = {
            'WordPress': r'WordPress/([\d.]+)',
            'Drupal': r'Drupal/([\d.]+)',
            'PHP': r'PHP/([\d.]+)'
        }
        if cms in version_patterns:
            for header in headers.values():
                match = re.search(version_patterns[cms], header)
                if match:
                    return match.group(1)
        return None

    async def scan(self) -> dict:
        try:
            url = f"https://{self.target}"
            response = requests.get(url, headers=self.headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all scripts
            scripts = [script.get('src', '') for script in soup.find_all('script', src=True)]
            
            # Detect technologies
            technologies = {
                'server': response.headers.get('Server'),
                'powered_by': response.headers.get('X-Powered-By'),
                'cms': self._detect_cms(soup, response.headers, response.text),
                'frameworks': [],
                'javascript': {
                    'libraries': [],
                    'frameworks': []
                },
                'analytics': [],
                'security': {
                    'headers': {
                        'x-frame-options': response.headers.get('X-Frame-Options'),
                        'x-xss-protection': response.headers.get('X-XSS-Protection'),
                        'content-security-policy': response.headers.get('Content-Security-Policy'),
                        'strict-transport-security': response.headers.get('Strict-Transport-Security'),
                        'x-content-type-options': response.headers.get('X-Content-Type-Options'),
                        'referrer-policy': response.headers.get('Referrer-Policy')
                    },
                    'cookies': [{
                        'name': cookie.name,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                        'samesite': cookie.get_nonstandard_attr('SameSite'),
                        'expires': str(cookie.expires) if cookie.expires else None
                    } for cookie in response.cookies]
                }
            }
            
            # JavaScript frameworks and libraries detection
            js_patterns = {
                'React': [r'react', r'reactjs', r'react-dom'],
                'Angular': [r'angular', r'ng-', r'@angular'],
                'Vue.js': [r'vue', r'vuejs', r'vue.min.js'],
                'jQuery': [r'jquery', r'jquery.min.js'],
                'Bootstrap': [r'bootstrap', r'bootstrap.min.js'],
                'Lodash': [r'lodash', r'lodash.min.js'],
                'Moment.js': [r'moment', r'moment.min.js'],
                'D3.js': [r'd3', r'd3.min.js'],
                'Three.js': [r'three', r'three.min.js']
            }
            
            for script in scripts:
                for tech, patterns in js_patterns.items():
                    if any(re.search(pattern, script.lower()) for pattern in patterns):
                        version = self._extract_version_from_url(script)
                        if version:
                            technologies['javascript']['libraries'].append({
                                'name': tech,
                                'version': version,
                                'url': script
                            })
                        else:
                            technologies['javascript']['libraries'].append({
                                'name': tech,
                                'url': script
                            })
            
            # Backend frameworks detection
            backend_patterns = {
                'Laravel': [r'laravel', r'laravel.min.js'],
                'Django': [r'django', r'csrftoken'],
                'Ruby on Rails': [r'rails', r'ruby on rails'],
                'Express': [r'express', r'node_modules'],
                'ASP.NET': [r'asp.net', r'__VIEWSTATE']
            }
            
            page_text = str(soup)
            for framework, patterns in backend_patterns.items():
                if any(re.search(pattern, page_text.lower()) for pattern in patterns):
                    technologies['frameworks'].append(framework)
            
            # Analytics and tracking detection
            analytics_patterns = {
                'Google Analytics': [r'google-analytics.com', r'ga\(', r'gtag'],
                'Google Tag Manager': [r'googletagmanager.com', r'gtm.js'],
                'Facebook Pixel': [r'connect.facebook.net', r'fbq\('],
                'Hotjar': [r'static.hotjar.com', r'hjSetting'],
                'Mixpanel': [r'cdn.mxpnl.com', r'mixpanel'],
                'Segment': [r'cdn.segment.com', r'analytics.js']
            }
            
            for analytics, patterns in analytics_patterns.items():
                if any(re.search(pattern, page_text) for pattern in patterns):
                    technologies['analytics'].append(analytics)
            
            # Security analysis
            security_issues = []
            
            # Check security headers
            missing_headers = [
                header for header, value in technologies['security']['headers'].items() 
                if not value
            ]
            if missing_headers:
                security_issues.append({
                    'type': 'missing_security_headers',
                    'details': missing_headers
                })
            
            # Check cookie security
            insecure_cookies = [
                cookie['name'] for cookie in technologies['security']['cookies']
                if not (cookie['secure'] and cookie['httponly'])
            ]
            if insecure_cookies:
                security_issues.append({
                    'type': 'insecure_cookies',
                    'details': insecure_cookies
                })
            
            # Calculate risk metrics
            risk_score = len(security_issues) + \
                        (5 if not technologies['security']['headers']['content-security-policy'] else 0) + \
                        (3 if not technologies['security']['headers']['strict-transport-security'] else 0) + \
                        len(insecure_cookies)
            
            self.results = {
                'target': self.target,
                'technologies': technologies,
                'security_issues': security_issues,
                'attack_surface': {
                    'missing_security_headers': missing_headers,
                    'insecure_cookies': len(insecure_cookies),
                    'risk_score': risk_score,
                    'risk_level': 'HIGH' if risk_score > 10 else 
                                'MEDIUM' if risk_score > 5 else 'LOW'
                }
            }
            
        except Exception as e:
            print(f"Error in technology detection: {str(e)}")
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results
        
    def _extract_version_from_url(self, url: str) -> Optional[str]:
        version_pattern = r'[\d.]+(?:[-.]?(?:min|beta|alpha|rc))?'
        match = re.search(version_pattern, url)
        return match.group(0) if match else None