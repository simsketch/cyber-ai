from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain_core.runnables import RunnableSequence
from typing import Dict, Any, List
import json
from datetime import datetime

class ScanAgent:
    def __init__(self, target: str, api_key: str):
        self.target = target
        self.llm = ChatOpenAI(
            temperature=0,
            model="gpt-3.5-turbo",
            openai_api_key=api_key
        )
        
        # Create analysis chain using new pattern
        self.analysis_prompt = PromptTemplate.from_template(
            """Analyze the security scan results and provide insights:
            Target: {target}
            Scan Results: {scan_results}
            
            Focus on:
            1. Critical security findings
            2. Attack surface analysis
            3. Potential vulnerabilities
            4. Recommendations for mitigation
            
            Format the response as a JSON object with these keys:
            - critical_findings: List of critical security issues
            - risk_assessment: Overall risk level (HIGH/MEDIUM/LOW)
            - next_steps: List of recommended actions
            - next_scan: Suggested next scan type based on findings
            """
        )
        self.analysis_chain = self.analysis_prompt | self.llm
        
    async def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        try:
            analysis = await self.analysis_chain.ainvoke({
                "target": self.target,
                "scan_results": json.dumps(scan_results, indent=2)
            })
            return json.loads(analysis.content)
        except Exception as e:
            return {
                "error": str(e),
                "next_scan": None
            }
            
    async def generate_report(self, all_results: List[Dict[str, Any]]) -> str:
        report_prompt = PromptTemplate.from_template(
            """Generate a comprehensive security assessment report based on these scan results:
            Target: {target}
            Timestamp: {timestamp}
            Scan Results: {all_results}
            
            The report should follow this structure:
            
            # Security Assessment Report: {target}
            
            ## Executive Summary
            - Overall security posture
            - Key findings summary
            - Risk assessment
            
            ## Attack Surface Analysis
            ### Domain Information
            - IP addresses and DNS records
            - Mail servers and nameservers
            - Zone transfer vulnerabilities
            
            ### Subdomain Enumeration
            - Total subdomains discovered
            - Notable findings
            - Potential security implications
            
            ### Network Services
            - Open ports and services
            - Service versions and vulnerabilities
            - Operating system detection results
            
            ### Web Technologies
            - Server technologies
            - Frameworks and libraries
            - Security headers analysis
            - Cookie security assessment
            
            ### Web Application Firewall
            - WAF detection results
            - Effectiveness analysis
            - Bypass potential
            
            ### Sensitive Information Exposure
            - Exposed files and directories
            - Backup files
            - Configuration files
            - Server information disclosure
            
            ### Vulnerability Assessment
            - Identified vulnerabilities by type
            - False positive analysis
            - Risk categorization
            
            ## Risk Assessment
            - Critical risks
            - High risks
            - Medium risks
            - Low risks
            
            ## Recommendations
            ### Immediate Actions
            - Critical fixes needed
            - Quick wins
            
            ### Short-term Improvements
            - Security hardening steps
            - Configuration changes
            
            ### Long-term Strategy
            - Security roadmap
            - Best practices implementation
            
            ## Technical Details
            - Detailed scan results
            - Raw data references
            - Testing methodology
            
            Format the report in Markdown with proper headers, lists, and code blocks for technical details.
            Include specific examples and findings from the scan results.
            Prioritize actionable insights and clear recommendations.
            """
        )
        
        report_chain = report_prompt | self.llm
        result = await report_chain.ainvoke({
            "target": self.target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "all_results": json.dumps(all_results, indent=2)
        })
        
        return result.content