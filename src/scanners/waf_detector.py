from wafw00f.main import WAFW00F
from scanners.base_scanner import BaseScanner

class WAFDetector(BaseScanner):
    def __init__(self, target: str):
        super().__init__(target)
        
    async def scan(self) -> dict:
        try:
            wafw00f = WAFW00F(self.target)
            waf_results = wafw00f.identify_waf()
            
            self.results = {
                'target': self.target,
                'waf_detected': bool(waf_results),
                'waf_info': waf_results if waf_results else None
            }
            return self.results
        except Exception as e:
            return {
                'error': str(e),
                'target': self.target
            }