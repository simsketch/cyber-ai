import os
import json
import aiohttp
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
import logging

class CVECache:
    def __init__(self, cache_dir: str = None):
        # Use environment variable or fallback to /tmp
        self.cache_dir = Path(cache_dir or os.environ.get("SCANNER_CACHE_DIR", "/tmp/cyber-ai-cache"))
        self.cache_file = self.cache_dir / "cve_cache.json"
        try:
            self.cache_dir.mkdir(exist_ok=True)
            logging.info(f"Using cache directory: {self.cache_dir}")
        except Exception as e:
            logging.error(f"Error creating CVE cache directory: {str(e)}")
        
    async def get_latest_cves(self) -> dict:
        """Get latest CVEs, using cache if available and not expired"""
        if self._is_cache_valid():
            return self._read_cache()
        
        return await self._update_cache()
    
    def _is_cache_valid(self) -> bool:
        """Check if cache exists and is less than 24 hours old"""
        if not self.cache_file.exists():
            return False
            
        cache_data = self._read_cache()
        if not cache_data or 'timestamp' not in cache_data:
            return False
            
        cache_time = datetime.fromisoformat(cache_data['timestamp'])
        return datetime.now() - cache_time < timedelta(hours=24)
    
    def _read_cache(self) -> dict:
        """Read CVE data from cache file"""
        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error reading CVE cache: {str(e)}")
            return {}
    
    async def _update_cache(self) -> dict:
        """Fetch latest CVEs and update cache"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://cve.circl.lu/api/last', ssl=False) as response:
                    if response.status == 200:
                        cves = await response.json()
                        cache_data = {
                            'timestamp': datetime.now().isoformat(),
                            'cves': cves
                        }
                        
                        # Write to cache file
                        with open(self.cache_file, 'w') as f:
                            json.dump(cache_data, f)
                        
                        return cache_data
                    else:
                        print(f"Error fetching CVEs: {response.status}")
                        return self._read_cache() or {'timestamp': None, 'cves': []}
        except Exception as e:
            print(f"Error updating CVE cache: {str(e)}")
            return self._read_cache() or {'timestamp': None, 'cves': []} 