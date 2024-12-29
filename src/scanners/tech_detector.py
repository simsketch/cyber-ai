import requests
from bs4 import BeautifulSoup
import re
from scanners.base_scanner import BaseScanner
from utils.url_helper import URLHelper

class TechDetector(BaseScanner):
    def __init__(self, target: str):
        self.full_url, target_domain = URLHelper.normalize_url(target)
        super().__init__(target_domain)
        
    async def scan(self) -> dict:
        try:
            url = f"https://{self.target}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            technologies = {
                'server': response.headers.get('Server'),
                'powered_by': response.headers.get('X-Powered-By'),
                'frameworks': [],
                'analytics': [],
                'security_headers': {
                    'x-frame-options': response.headers.get('X-Frame-Options'),
                    'x-xss-protection': response.headers.get('X-XSS-Protection'),
                    'content-security-policy': response.headers.get('Content-Security-Policy'),
                    'strict-transport-security': response.headers.get('Strict-Transport-Security')
                },
                'cookies': [{
                    'name': cookie.name,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly')
                } for cookie in response.cookies],
                'javascript_libraries': []
            }
            
            # Check for common frameworks
            framework_patterns = {
                'React': ['react', 'reactjs'],
                'Angular': ['ng-', 'angular'],
                'Vue': ['vue', 'vuejs'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap'],
                'Laravel': ['laravel'],
                'Django': ['csrftoken', 'django'],
                'WordPress': ['wp-content', 'wordpress']
            }
            
            page_text = str(soup)
            for framework, patterns in framework_patterns.items():
                if any(pattern in page_text.lower() for pattern in patterns):
                    technologies['frameworks'].append(framework)
            
            # Check for analytics and tracking
            if re.search(r'google-analytics|gtag|ga.js', page_text):
                technologies['analytics'].append('Google Analytics')
            if re.search(r'facebook.com/tr|fbevents.js', page_text):
                technologies['analytics'].append('Facebook Pixel')
            
            # Find JavaScript libraries
            for script in soup.find_all('script', src=True):
                src = script['src']
                for lib in ['jquery', 'bootstrap', 'react', 'angular', 'vue']:
                    if lib in src.lower():
                        technologies['javascript_libraries'].append(src)
            
            self.results = {
                'target': self.target,
                'technologies': technologies,
                'attack_surface': {
                    'missing_security_headers': [
                        header for header, value in technologies['security_headers'].items() 
                        if not value
                    ],
                    'insecure_cookies': len([
                        cookie for cookie in technologies['cookies'] 
                        if not (cookie['secure'] and cookie['httponly'])
                    ])
                }
            }
            
        except Exception as e:
            self.results = {
                'error': str(e),
                'target': self.target
            }
            
        return self.results