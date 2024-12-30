from typing import List, Dict, Any
from langchain_openai import ChatOpenAI
from langchain.prompts import PromptTemplate
import json

class RemediationAdvisor:
    def __init__(self, api_key: str):
        self.llm = ChatOpenAI(
            temperature=0,
            model="gpt-4",
            openai_api_key=api_key
        )
        
        self.remediation_prompt = PromptTemplate.from_template(
            """Analyze the following security finding and provide detailed remediation steps:
            
            Finding: {finding}
            Technology Stack: {tech_stack}
            Business Context: {business_context}
            
            Consider:
            1. Immediate mitigation steps
            2. Long-term fixes
            3. Best practices
            4. Implementation complexity
            5. Potential side effects
            6. Required resources
            
            Format the response as a JSON object with these keys:
            - immediate_steps: List of immediate actions
            - long_term_fixes: List of permanent solutions
            - best_practices: Related security best practices
            - implementation_details: Technical implementation guidance
            - required_resources: List of needed resources
            - estimated_timeline: Estimated time to implement
            - potential_risks: List of implementation risks
            """
        )
        
    async def generate_remediation_plan(self, 
                                      finding: Dict[str, Any],
                                      tech_stack: Dict[str, Any],
                                      business_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a detailed remediation plan for a finding."""
        try:
            response = await self.llm.ainvoke({
                "finding": json.dumps(finding),
                "tech_stack": json.dumps(tech_stack),
                "business_context": json.dumps(business_context)
            })
            
            plan = json.loads(response.content)
            
            # Enhance plan with additional context
            plan['priority'] = self._calculate_priority(finding, business_context)
            plan['dependencies'] = self._identify_dependencies(plan, tech_stack)
            plan['compliance_impact'] = self._assess_compliance_impact(finding, business_context)
            
            return plan
            
        except Exception as e:
            return {
                "error": str(e),
                "finding_id": finding.get('id')
            }
            
    def _calculate_priority(self, 
                          finding: Dict[str, Any],
                          business_context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate remediation priority based on multiple factors."""
        severity_score = {
            'CRITICAL': 1.0,
            'HIGH': 0.8,
            'MEDIUM': 0.5,
            'LOW': 0.2
        }.get(finding.get('severity', 'LOW'), 0.2)
        
        # Adjust based on business factors
        business_criticality = business_context.get('criticality', 0.5)
        data_sensitivity = business_context.get('data_sensitivity', 0.5)
        exposure = business_context.get('public_exposure', 0.5)
        
        priority_score = (severity_score * 0.4 +
                        business_criticality * 0.3 +
                        data_sensitivity * 0.2 +
                        exposure * 0.1)
        
        return {
            'score': priority_score,
            'level': self._score_to_priority_level(priority_score),
            'factors': {
                'severity': severity_score,
                'business_criticality': business_criticality,
                'data_sensitivity': data_sensitivity,
                'exposure': exposure
            }
        }
        
    def _identify_dependencies(self,
                             plan: Dict[str, Any],
                             tech_stack: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify technical dependencies for remediation."""
        dependencies = []
        
        # Check infrastructure dependencies
        if 'infrastructure' in tech_stack:
            for infra in tech_stack['infrastructure']:
                if any(infra['name'].lower() in step.lower() 
                      for step in plan['implementation_details']):
                    dependencies.append({
                        'type': 'infrastructure',
                        'name': infra['name'],
                        'version': infra.get('version'),
                        'criticality': 'HIGH'
                    })
        
        # Check software dependencies
        if 'software' in tech_stack:
            for software in tech_stack['software']:
                if any(software['name'].lower() in step.lower()
                      for step in plan['implementation_details']):
                    dependencies.append({
                        'type': 'software',
                        'name': software['name'],
                        'version': software.get('version'),
                        'criticality': 'MEDIUM'
                    })
        
        return dependencies
        
    def _assess_compliance_impact(self,
                                finding: Dict[str, Any],
                                business_context: Dict[str, Any]) -> Dict[str, Any]:
        """Assess how remediation affects compliance status."""
        compliance_frameworks = business_context.get('compliance_requirements', [])
        impact = {}
        
        for framework in compliance_frameworks:
            controls = self._map_finding_to_compliance_controls(finding, framework)
            if controls:
                impact[framework] = {
                    'affected_controls': controls,
                    'positive_impact': self._calculate_compliance_improvement(controls),
                    'documentation_needed': self._identify_required_documentation(controls)
                }
        
        return impact
        
    def _score_to_priority_level(self, score: float) -> str:
        """Convert priority score to priority level."""
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW' 