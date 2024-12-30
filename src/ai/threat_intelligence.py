from typing import List, Dict, Any
import aiohttp
import asyncio
from datetime import datetime, timedelta
import json
from dataclasses import dataclass
import hashlib
import hmac
import base64

@dataclass
class ThreatIntel:
    source: str
    type: str
    indicator: str
    confidence: float
    severity: str
    context: Dict[str, Any]
    timestamp: datetime

class ThreatIntelligence:
    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.cache = {}
        self.feeds = {
            'alienvault': self._fetch_alienvault,
            'virustotal': self._fetch_virustotal,
            'threatfox': self._fetch_threatfox,
            'misp': self._fetch_misp
        }
        
    async def gather_intelligence(self, 
                                indicators: List[str],
                                context: Dict[str, Any]) -> Dict[str, Any]:
        """Gather threat intelligence from multiple sources."""
        tasks = []
        
        # Create tasks for each feed
        for feed_name, feed_func in self.feeds.items():
            if feed_name in self.config:
                tasks.append(feed_func(indicators))
                
        # Gather results
        results = await asyncio.gather(*tasks)
        
        # Process and correlate results
        processed_intel = self._process_intelligence(results)
        enriched_intel = await self._enrich_intelligence(processed_intel, context)
        
        return {
            'indicators': enriched_intel,
            'summary': self._generate_intel_summary(enriched_intel),
            'recommendations': self._generate_recommendations(enriched_intel, context)
        }
        
    async def _fetch_alienvault(self, indicators: List[str]) -> List[Dict[str, Any]]:
        """Fetch threat intelligence from AlienVault OTX."""
        async with aiohttp.ClientSession() as session:
            results = []
            for indicator in indicators:
                try:
                    headers = {
                        'X-OTX-API-KEY': self.config['alienvault']['api_key']
                    }
                    
                    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}"
                    async with session.get(url, headers=headers) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(self._parse_alienvault_data(data))
                            
                except Exception as e:
                    print(f"Error fetching AlienVault data: {str(e)}")
                    
            return results
            
    async def _fetch_virustotal(self, indicators: List[str]) -> List[Dict[str, Any]]:
        """Fetch threat intelligence from VirusTotal."""
        async with aiohttp.ClientSession() as session:
            results = []
            for indicator in indicators:
                try:
                    headers = {
                        'x-apikey': self.config['virustotal']['api_key']
                    }
                    
                    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                    params = {'domain': indicator}
                    
                    async with session.get(url, headers=headers, params=params) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(self._parse_virustotal_data(data))
                            
                except Exception as e:
                    print(f"Error fetching VirusTotal data: {str(e)}")
                    
            return results
            
    async def _enrich_intelligence(self,
                                 intel: List[ThreatIntel],
                                 context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Enrich threat intelligence with additional context and analysis."""
        enriched_intel = []
        
        for item in intel:
            # Add historical context
            historical_data = await self._get_historical_data(item.indicator)
            
            # Add industry-specific context
            industry_context = self._get_industry_context(item, context)
            
            # Calculate risk scores
            risk_scores = self._calculate_risk_scores(item, historical_data, context)
            
            # Generate mitigation suggestions
            mitigations = self._generate_mitigations(item, risk_scores)
            
            enriched_intel.append({
                'intel': item,
                'historical_data': historical_data,
                'industry_context': industry_context,
                'risk_scores': risk_scores,
                'mitigations': mitigations
            })
            
        return enriched_intel
        
    def _generate_intel_summary(self, intel: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of threat intelligence findings."""
        summary = {
            'total_indicators': len(intel),
            'risk_levels': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'threat_types': {},
            'key_findings': [],
            'trending_threats': self._identify_trending_threats(intel)
        }
        
        for item in intel:
            # Count risk levels
            risk_level = self._determine_risk_level(item['risk_scores'])
            summary['risk_levels'][risk_level] += 1
            
            # Count threat types
            threat_type = item['intel'].type
            summary['threat_types'][threat_type] = summary['threat_types'].get(threat_type, 0) + 1
            
            # Collect key findings
            if risk_level in ['HIGH', 'MEDIUM']:
                summary['key_findings'].append({
                    'indicator': item['intel'].indicator,
                    'type': threat_type,
                    'risk_level': risk_level,
                    'context': item['industry_context']
                })
                
        return summary
        
    def _generate_recommendations(self,
                                intel: List[Dict[str, Any]],
                                context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on threat intelligence."""
        recommendations = []
        
        # Group threats by type and severity
        grouped_threats = self._group_threats(intel)
        
        for threat_type, threats in grouped_threats.items():
            # Generate type-specific recommendations
            type_recs = self._generate_type_recommendations(threat_type, threats)
            
            # Prioritize recommendations
            prioritized_recs = self._prioritize_recommendations(type_recs, context)
            
            recommendations.extend(prioritized_recs)
            
        return sorted(recommendations, key=lambda x: x['priority'], reverse=True) 