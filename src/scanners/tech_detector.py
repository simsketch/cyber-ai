import requests
from bs4 import BeautifulSoup
from scanners.base_scanner import BaseScanner

class TechDetector(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        
    async def scan(self) -> dict:
        try:
            url = f"https://{self.target}"
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            technologies = {
                'server': response.headers.get('Server'),
                'powered_by': response.headers.get('X-Powered-By'),
                'frameworks': [],
                'analytics': []
            }
            
            # Check for common frameworks
            if soup.find(attrs={"data-react-root": True}):
                technologies['frameworks'].append('React')
            if soup.find(attrs={"ng-version": True}):
                technologies['frameworks'].append('Angular')
            if soup.find(attrs={"data-vue-root": True}):
                technologies['frameworks'].append('Vue')
                
            # Check for analytics
            if soup.find(string=lambda text: 'google-analytics' in str(text).lower()):
                technologies['analytics'].append('Google Analytics')
                
            self.results = {
                'target': self.target,
                'technologies': technologies
            }
            return self.results
        except Exception as e:
            return {
                'error': str(e),
                'target': self.target
            }