from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
from langchain_core.runnables import RunnableSequence
from typing import Dict, Any, List
import json
from scanners.domain_finder import DomainFinder

class ScanAgent:
    def __init__(self, target: str, api_key: str):
        self.target = target
        self.llm = ChatOpenAI(
            temperature=0,
            model="gpt-3.5-turbo",
            openai_api_key=api_key
        )
        
        self.domain_finder = DomainFinder(target=self.target)
        
        # Create analysis chain using new pattern
        self.analysis_prompt = PromptTemplate.from_template(
            """Analyze the scan results and provide insights:
            {scan_results}
            """
        )
        self.analysis_chain = self.analysis_prompt | self.llm
        
    async def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        try:
            analysis = await self.analysis_chain.ainvoke(
                {"scan_results": json.dumps(scan_results, indent=2)}
            )
            return json.loads(analysis.content)
        except Exception as e:
            return {
                "error": str(e),
                "next_scan": None
            }
            
    def generate_report(self, all_results: List[Dict[str, Any]]) -> str:
        report_prompt = PromptTemplate.from_template(
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
        
        report_chain = report_prompt | self.llm
        result = report_chain.invoke({"all_results": json.dumps(all_results, indent=2)})
        return result.content