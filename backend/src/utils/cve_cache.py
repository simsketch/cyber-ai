import os
import json
import aiohttp
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging

class CVECache:
    def __init__(self, cache_dir: str = None):
        # Use environment variable or fallback to ./cve-data
        default_cache_dir = Path("cve-data")
        self.cache_dir = Path(cache_dir or os.environ.get("SCANNER_CACHE_DIR", default_cache_dir))
        self.cache_file = self.cache_dir / "cve_cache.json"
        try:
            # Ensure cache directory exists with proper permissions
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.cache_dir, 0o777)
            
            # Create empty cache file if it doesn't exist
            if not self.cache_file.exists():
                with open(self.cache_file, 'w') as f:
                    json.dump({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "cves": []
                    }, f)
                os.chmod(self.cache_file, 0o666)
                
            logging.info(f"Using cache directory: {self.cache_dir}")
            logging.info(f"Cache file path: {self.cache_file}")
        except Exception as e:
            logging.error(f"Error initializing CVE cache: {str(e)}")
            raise
        
    def _standardize_date(self, date_str: str) -> str:
        """Convert date to ISO format that JavaScript can parse"""
        try:
            logging.info(f"Attempting to standardize date: {date_str}")
            
            # If it's already a valid ISO format, just ensure it ends with Z
            if isinstance(date_str, str) and 'T' in date_str:
                try:
                    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')
                except ValueError:
                    pass
            
            # Handle common date formats
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%fZ",  # ISO format with microseconds
                "%Y-%m-%dT%H:%M:%SZ",      # ISO format without microseconds
                "%Y-%m-%d %H:%M:%S",       # Standard datetime
                "%Y-%m-%dT%H:%M:%S",       # ISO without timezone
                "%Y-%m-%d",                # Just date
            ]:
                try:
                    dt = datetime.strptime(date_str, fmt)
                    dt = dt.replace(tzinfo=timezone.utc)  # Make timezone-aware
                    result = dt.isoformat().replace('+00:00', 'Z')
                    logging.info(f"Successfully standardized date to: {result}")
                    return result
                except ValueError:
                    continue
            
            logging.error(f"Could not parse date with any known format: {date_str}")
            return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        except Exception as e:
            logging.error(f"Error standardizing date {date_str}: {str(e)}")
            return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    async def get_latest_cves(self) -> dict:
        """Get latest CVEs, using cache if available and not expired"""
        try:
            if not self._is_cache_valid():
                logging.info("CVE cache is stale or missing, updating...")
                return await self._update_cache()
            
            logging.info("Reading from valid cache file")
            return self._read_cache()
        except Exception as e:
            logging.error(f"Error in get_latest_cves: {str(e)}")
            raise
    
    def _is_cache_valid(self) -> bool:
        """Check if cache exists and is less than 24 hours old"""
        if not self.cache_file.exists():
            logging.info("CVE cache file does not exist")
            return False
            
        cache_data = self._read_cache()
        if not cache_data or 'timestamp' not in cache_data:
            logging.info("CVE cache data is invalid or missing timestamp")
            return False
            
        try:
            # Parse the timestamp, ensuring it's timezone aware
            cache_time = datetime.fromisoformat(cache_data['timestamp'].replace('Z', '+00:00'))
            current_time = datetime.now(cache_time.tzinfo)  # Use same timezone as cache_time
            age = current_time - cache_time
            is_valid = age < timedelta(hours=24)
            
            if not is_valid:
                logging.info(f"CVE cache is {age.total_seconds() / 3600:.1f} hours old (max 24 hours)")
            else:
                logging.info(f"CVE cache is valid, age: {age.total_seconds() / 3600:.1f} hours")
            
            return is_valid
        except Exception as e:
            logging.error(f"Error validating cache timestamp: {str(e)}")
            return False

    async def force_update(self) -> dict:
        """Force an update of the CVE cache regardless of its current state"""
        logging.info("Forcing CVE cache update")
        return await self._update_cache()

    def _read_cache(self) -> dict:
        """Read CVE data from cache file"""
        try:
            if not self.cache_file.exists():
                logging.warning("Cache file does not exist when trying to read")
                return {}
                
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
                logging.info(f"Successfully read cache file with {len(data.get('cves', []))} CVEs")
                return data
        except Exception as e:
            logging.error(f"Error reading CVE cache: {str(e)}")
            return {}
    
    async def _update_cache(self) -> dict:
        """Fetch latest CVEs and update cache"""
        try:
            logging.info("Fetching latest CVEs from API...")
            async with aiohttp.ClientSession() as session:
                # Request the full dataset
                async with session.get('https://cve.circl.lu/api/last', ssl=False) as response:
                    if response.status == 200:
                        cves = await response.json()
                        logging.info(f"Received {len(cves)} CVEs from API")
                        
                        # Process each CVE to extract and standardize dates
                        processed_cves = []
                        for cve in cves:
                            try:
                                processed_cve = {}
                                
                                # Extract CVE ID and metadata
                                if 'cveMetadata' in cve:
                                    metadata = cve['cveMetadata']
                                    processed_cve['id'] = metadata.get('cveId')
                                    processed_cve['Published'] = self._standardize_date(metadata.get('datePublished'))
                                    processed_cve['Modified'] = self._standardize_date(metadata.get('dateUpdated'))
                                
                                # Extract description and other details from containers
                                if 'containers' in cve and 'cna' in cve['containers']:
                                    cna = cve['containers']['cna']
                                    
                                    # Get description
                                    if 'descriptions' in cna:
                                        for desc in cna['descriptions']:
                                            if desc.get('lang') == 'en':
                                                processed_cve['summary'] = desc.get('value', '')
                                                break
                                    
                                    # Get CVSS score
                                    if 'metrics' in cna:
                                        for metric in cna['metrics']:
                                            if 'cvssV3_1' in metric:
                                                processed_cve['cvss'] = metric['cvssV3_1'].get('baseScore', 0)
                                                break
                                    
                                    # Get references
                                    if 'references' in cna:
                                        processed_cve['references'] = [ref.get('url') for ref in cna['references'] if ref.get('url')]
                                
                                # Only add CVEs that have required fields
                                if all(key in processed_cve for key in ['id', 'Published', 'Modified', 'summary']):
                                    processed_cves.append(processed_cve)
                                else:
                                    logging.warning(f"Skipping CVE due to missing required fields: {processed_cve.get('id', 'unknown')}")
                            except Exception as e:
                                logging.error(f"Error processing CVE: {str(e)}")
                                continue
                        
                        # Log processing results
                        logging.info(f"Successfully processed {len(processed_cves)} out of {len(cves)} CVEs")
                        
                        cache_data = {
                            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                            'cves': processed_cves
                        }
                        
                        # Write to cache file
                        try:
                            with open(self.cache_file, 'w') as f:
                                json.dump(cache_data, f)
                            os.chmod(self.cache_file, 0o666)
                            logging.info(f"Successfully updated CVE cache with {len(processed_cves)} records")
                            return cache_data
                        except Exception as e:
                            logging.error(f"Error writing to cache file: {str(e)}")
                            raise
                    else:
                        logging.error(f"Failed to fetch CVEs: HTTP {response.status}")
                        raise Exception(f"Failed to fetch CVEs: HTTP {response.status}")
        except Exception as e:
            logging.error(f"Error updating CVE cache: {str(e)}")
            raise