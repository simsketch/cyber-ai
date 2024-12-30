from typing import List, Dict, Any
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import networkx as nx
import pandas as pd
import numpy as np
from datetime import datetime
import json

class InteractiveReportGenerator:
    def __init__(self):
        self.layout_template = "plotly_dark"
        
    def generate_interactive_report(self,
                                  scan_results: List[Dict[str, Any]],
                                  threat_intel: Dict[str, Any],
                                  company_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an interactive HTML report."""
        # Create visualizations
        risk_timeline = self._create_risk_timeline(scan_results)
        attack_surface = self._create_attack_surface_3d(scan_results)
        threat_map = self._create_threat_map(threat_intel)
        vuln_sunburst = self._create_vulnerability_sunburst(scan_results)
        compliance_radar = self._create_compliance_radar(scan_results, company_info)
        
        # Combine into report
        report = {
            'metadata': self._generate_metadata(scan_results, company_info),
            'visualizations': {
                'risk_timeline': risk_timeline,
                'attack_surface': attack_surface,
                'threat_map': threat_map,
                'vuln_sunburst': vuln_sunburst,
                'compliance_radar': compliance_radar
            },
            'summary': self._generate_executive_summary(scan_results, threat_intel),
            'details': self._generate_detailed_findings(scan_results)
        }
        
        return self._create_html_report(report)
        
    def _create_risk_timeline(self, scan_results: List[Dict[str, Any]]) -> go.Figure:
        """Create an interactive risk timeline visualization."""
        # Prepare data
        dates = []
        risk_scores = []
        annotations = []
        
        for result in scan_results:
            dates.append(pd.to_datetime(result['timestamp']))
            risk_scores.append(result.get('risk_score', 0))
            
            # Add annotations for significant events
            if result.get('significant_finding'):
                annotations.append({
                    'x': result['timestamp'],
                    'y': result['risk_score'],
                    'text': result['significant_finding'],
                    'showarrow': True
                })
        
        # Create figure
        fig = go.Figure()
        
        # Add main line
        fig.add_trace(go.Scatter(
            x=dates,
            y=risk_scores,
            mode='lines+markers',
            name='Risk Score',
            hovertemplate='Date: %{x}<br>Risk Score: %{y:.2f}<extra></extra>'
        ))
        
        # Add range selector
        fig.update_layout(
            xaxis=dict(
                rangeselector=dict(
                    buttons=list([
                        dict(count=1, label="1d", step="day", stepmode="backward"),
                        dict(count=7, label="1w", step="day", stepmode="backward"),
                        dict(count=1, label="1m", step="month", stepmode="backward"),
                        dict(step="all")
                    ])
                ),
                rangeslider=dict(visible=True),
                type="date"
            ),
            annotations=annotations
        )
        
        return fig
        
    def _create_attack_surface_3d(self, scan_results: List[Dict[str, Any]]) -> go.Figure:
        """Create a 3D visualization of the attack surface."""
        # Extract attack surface metrics
        metrics = self._extract_attack_surface_metrics(scan_results)
        
        # Create 3D scatter plot
        fig = go.Figure(data=[go.Scatter3d(
            x=metrics['exposure'],
            y=metrics['complexity'],
            z=metrics['impact'],
            mode='markers',
            marker=dict(
                size=metrics['severity'],
                color=metrics['risk_score'],
                colorscale='Viridis',
                opacity=0.8
            ),
            text=metrics['descriptions'],
            hovertemplate=
            'Exposure: %{x}<br>' +
            'Complexity: %{y}<br>' +
            'Impact: %{z}<br>' +
            'Description: %{text}<extra></extra>'
        )])
        
        # Update layout
        fig.update_layout(
            scene=dict(
                xaxis_title='Exposure',
                yaxis_title='Complexity',
                zaxis_title='Impact'
            ),
            margin=dict(l=0, r=0, b=0, t=0)
        )
        
        return fig
        
    def _create_threat_map(self, threat_intel: Dict[str, Any]) -> go.Figure:
        """Create an interactive threat map visualization."""
        # Prepare threat data
        locations = []
        sizes = []
        texts = []
        colors = []
        
        for threat in threat_intel['indicators']:
            if 'location' in threat:
                locations.append([threat['location']['lat'], threat['location']['lon']])
                sizes.append(threat['severity'] * 10)
                texts.append(threat['description'])
                colors.append(threat['risk_score'])
        
        # Create map
        fig = go.Figure(data=go.Scattergeo(
            lon=[loc[1] for loc in locations],
            lat=[loc[0] for loc in locations],
            mode='markers',
            marker=dict(
                size=sizes,
                color=colors,
                colorscale='Viridis',
                showscale=True,
                opacity=0.8
            ),
            text=texts,
            hovertemplate=
            'Location: %{lon}, %{lat}<br>' +
            'Description: %{text}<extra></extra>'
        ))
        
        # Update layout
        fig.update_layout(
            geo=dict(
                showland=True,
                showcountries=True,
                showocean=True,
                countrywidth=0.5,
                landcolor='rgb(243, 243, 243)',
                oceancolor='rgb(204, 229, 255)',
                projection_scale=1.2
            ),
            margin=dict(l=0, r=0, b=0, t=0)
        )
        
        return fig
        
    def _create_vulnerability_sunburst(self, scan_results: List[Dict[str, Any]]) -> go.Figure:
        """Create a sunburst visualization of vulnerabilities."""
        # Prepare data
        vulns = self._process_vulnerabilities(scan_results)
        
        # Create sunburst chart
        fig = go.Figure(go.Sunburst(
            ids=vulns['ids'],
            labels=vulns['labels'],
            parents=vulns['parents'],
            values=vulns['values'],
            branchvalues="total",
            marker=dict(
                colors=vulns['colors']
            ),
            hovertemplate=
            'Category: %{label}<br>' +
            'Count: %{value}<br>' +
            'Parent: %{parent}<extra></extra>'
        ))
        
        # Update layout
        fig.update_layout(
            margin=dict(l=0, r=0, b=0, t=0),
            sunburstcolorway=["#636efa","#ef553b","#00cc96"]
        )
        
        return fig
        
    def _create_compliance_radar(self,
                               scan_results: List[Dict[str, Any]],
                               company_info: Dict[str, Any]) -> go.Figure:
        """Create a radar chart of compliance status."""
        # Get compliance requirements
        compliance_reqs = company_info.get('compliance', {})
        
        # Calculate compliance scores
        scores = self._calculate_compliance_scores(scan_results, compliance_reqs)
        
        # Create radar chart
        fig = go.Figure()
        
        fig.add_trace(go.Scatterpolar(
            r=scores['current'],
            theta=scores['categories'],
            fill='toself',
            name='Current Status'
        ))
        
        fig.add_trace(go.Scatterpolar(
            r=scores['required'],
            theta=scores['categories'],
            fill='toself',
            name='Required Level'
        ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100]
                )
            ),
            showlegend=True
        )
        
        return fig 