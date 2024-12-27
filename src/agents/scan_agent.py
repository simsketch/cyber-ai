from langchain.chat_models import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langchain.chains import LLMChain
from typing import Dict, Any, List
import json

class ScanAgent:
    def __init__(self, openai_api_key: str):
        self.llm = ChatOpenAI(
            temperature=0,
            openai_api_key=openai_api_key,
            model_name="gpt-4"
        )
        
        self.analysis_prompt = ChatPromptTemplate.from_template(
            """You are a cybersecurity expert analyzing scan results and deciding the next steps.
            Previous scan results:
            {scan_results}
            
            Available scanners:
            - domain: Basic domain reconnaissance
            - subdomain: Subdomain enumeration
            - port: Port and service detection
            - waf: Web Application Firewall detection
            - fuzzer: URL and directory fuzzing
            - tech: Technology stack detection
            
            Based on these results, determine:
            1. What are the key findings?
            2. What potential security issues were discovered?
            3. What should be the next scan to perform?
            4. What specific parameters or areas should that scan focus on?
            
            Consider the following decision logic:
            - If domain scan reveals multiple IPs, consider port scanning each
            - If subdomains are found, consider tech detection on interesting ones
            - If web ports (80/443) are open, consider WAF detection and URL fuzzing
            - If a technology is detected, focus fuzzing on known paths for that tech
            
            Provide your response in JSON format with these keys:
            {
                "findings": [],
                "security_issues": [],
                "next_scan": "",
                "scan_params": {},
                "risk_level": "LOW|MEDIUM|HIGH",
                "explanation": ""
            }"""
        )
        
        self.analysis_chain = LLMChain(
            llm=self.llm,
            prompt=self.analysis_prompt
        )
        
    async def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        try:
            analysis = await self.analysis_chain.arun(
                scan_results=json.dumps(scan_results, indent=2)
            )
            return json.loads(analysis)
        except Exception as e:
            return {
                "error": str(e),
                "next_scan": None
            }
            
    def generate_report(self, all_results: List[Dict[str, Any]]) -> str:
        report_prompt = ChatPromptTemplate.from_template(
            """Generate a comprehensive security report based on these scan results:
            {all_results}
            
            Include:
            1. Executive Summary
            2. Key Findings
            3. Risk Assessment
            4. Recommendations
            5. Technical Details
            
            Format the report in Markdown."""
        )
        
        report_chain = LLMChain(llm=self.llm, prompt=report_prompt)
        return report_chain.run(all_results=json.dumps(all_results, indent=2))