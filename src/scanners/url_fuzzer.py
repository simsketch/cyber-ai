import requests
from scanners.base_scanner import BaseScanner

class URLFuzzer(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        
    async def scan(self) -> dict:
        try:
            wordlist = ["admin", "login", "wp-admin", "administrator", "phpmyadmin"]
            found_urls = []
            
            for word in wordlist:
                url = f"https://{self.target}/{word}"
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code != 404:
                        found_urls.append({
                            'url': url,
                            'status': response.status_code,
                            'length': len(response.content)
                        })
                except requests.RequestException:
                    continue
            
            self.results = {
                'target': self.target,
                'found_urls': found_urls
            }
            return self.results
        except Exception as e:
            return {
                'error': str(e),
                'target': self.target
            }