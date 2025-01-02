import os
import json
import aiohttp
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class CVECache:
    def __init__(self, cache_dir: str = None):
        logger.info("Initializing CVE Cache...")
        # Use environment variable or fallback to ./cve-data
        default_cache_dir = Path("cve-data")
        self.cache_dir = Path(cache_dir or os.environ.get("SCANNER_CACHE_DIR", default_cache_dir))
        self.cache_file = self.cache_dir / "cve_cache.json"
        try:
            logger.info(f"Setting up cache directory at: {self.cache_dir}")
            # Ensure cache directory exists with proper permissions
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.cache_dir, 0o777)
            
            # Create empty cache file if it doesn't exist
            if not self.cache_file.exists():
                logger.info("Creating new cache file...")
                with open(self.cache_file, 'w') as f:
                    json.dump({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "cves": []
                    }, f)
                os.chmod(self.cache_file, 0o666)
                logger.info("New cache file created successfully")
            else:
                logger.info("Using existing cache file")
                
            logger.info(f"Cache initialization complete. Using directory: {self.cache_dir}")
            logger.info(f"Cache file path: {self.cache_file}")
        except Exception as e:
            logger.error(f"Critical error initializing CVE cache: {str(e)}", exc_info=True)
            raise
        
    def _standardize_date(self, date_str: str) -> str:
        """Convert date to ISO format that JavaScript can parse"""
        try:
            logger.info(f"Attempting to standardize date: {date_str}")
            
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
                    logger.info(f"Successfully standardized date to: {result}")
                    return result
                except ValueError:
                    continue
            
            logger.error(f"Could not parse date with any known format: {date_str}")
            return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        except Exception as e:
            logger.error(f"Error standardizing date {date_str}: {str(e)}")
            return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    async def get_latest_cves(self) -> dict:
        """Get latest CVEs, using cache if available and not expired"""
        try:
            if not self._is_cache_valid():
                logger.info("CVE cache is stale or missing, updating...")
                return await self._update_cache()
            
            logger.info("Reading from valid cache file")
            return self._read_cache()
        except Exception as e:
            logger.error(f"Error in get_latest_cves: {str(e)}")
            raise
    
    def _is_cache_valid(self) -> bool:
        """Check if cache exists and is less than 24 hours old"""
        if not self.cache_file.exists():
            logger.info("CVE cache file does not exist")
            return False
            
        cache_data = self._read_cache()
        if not cache_data or 'timestamp' not in cache_data:
            logger.info("CVE cache data is invalid or missing timestamp")
            return False
            
        try:
            # Parse the timestamp, ensuring it's timezone aware
            cache_time = datetime.fromisoformat(cache_data['timestamp'].replace('Z', '+00:00'))
            current_time = datetime.now(cache_time.tzinfo)  # Use same timezone as cache_time
            age = current_time - cache_time
            is_valid = age < timedelta(hours=24)
            
            if not is_valid:
                logger.info(f"CVE cache is {age.total_seconds() / 3600:.1f} hours old (max 24 hours)")
            else:
                logger.info(f"CVE cache is valid, age: {age.total_seconds() / 3600:.1f} hours")
            
            return is_valid
        except Exception as e:
            logger.error(f"Error validating cache timestamp: {str(e)}")
            return False

    async def force_update(self) -> dict:
        """Force an update of the CVE cache regardless of its current state"""
        logger.info("Starting forced CVE cache update...")
        try:
            result = await self._update_cache()
            logger.info("Forced CVE cache update completed successfully")
            return result
        except Exception as e:
            logger.error(f"Failed to force update CVE cache: {str(e)}", exc_info=True)
            raise

    def _read_cache(self) -> dict:
        """Read CVE data from cache file"""
        try:
            if not self.cache_file.exists():
                logger.warning("Cache file does not exist when trying to read")
                return {}
                
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
                logger.info(f"Successfully read cache file with {len(data.get('cves', []))} CVEs")
                return data
        except Exception as e:
            logger.error(f"Error reading CVE cache: {str(e)}")
            return {}
    
    async def _update_cache(self) -> dict:
        """Fetch latest CVEs and update cache"""
        try:
            logger.info("Starting CVE fetch from API...")
            async with aiohttp.ClientSession() as session:
                logger.info("Initiating request to CVE API...")
                # Request the full dataset
                async with session.get('https://cve.circl.lu/api/last', ssl=False) as response:
                    if response.status == 200:
                        logger.info("Successfully received response from CVE API")
                        cves = await response.json()
                        logger.info(f"Parsed {len(cves)} CVEs from API response")
                        
                        # Process each CVE to extract and standardize dates
                        processed_cves = []
                        logger.info("Starting CVE processing...")
                        
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
                                    logger.warning(f"Skipping CVE due to missing required fields: {processed_cve.get('id', 'unknown')}")
                            except Exception as e:
                                logger.error(f"Error processing individual CVE: {str(e)}")
                                continue
                        
                        logger.info(f"CVE processing complete. Processed {len(processed_cves)} out of {len(cves)} CVEs")
                        
                        cache_data = {
                            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                            'cves': processed_cves
                        }
                        
                        # Write to cache file
                        try:
                            logger.info("Writing processed CVEs to cache file...")
                            with open(self.cache_file, 'w') as f:
                                json.dump(cache_data, f)
                            os.chmod(self.cache_file, 0o666)
                            logger.info(f"Successfully updated CVE cache with {len(processed_cves)} records")
                            return cache_data
                        except Exception as e:
                            logger.error(f"Error writing to cache file: {str(e)}", exc_info=True)
                            raise
                    else:
                        error_msg = f"Failed to fetch CVEs: HTTP {response.status}"
                        logger.error(error_msg)
                        raise Exception(error_msg)
        except Exception as e:
            logger.error(f"Critical error updating CVE cache: {str(e)}", exc_info=True)
            raise