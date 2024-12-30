import matplotlib.pyplot as plt
import seaborn as sns
from typing import List, Dict, Any
import pandas as pd
import numpy as np
from pathlib import Path
import networkx as nx

class ReportGenerator:
    def __init__(self):
        self.output_dir = Path('data/scan_results/charts')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def create_risk_summary_chart(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create a risk summary chart."""
        # Collect risk levels
        risk_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for result in scan_results:
            if 'attack_surface' in result.get('results', {}):
                risk_level = result['results']['attack_surface'].get('risk_level', 'LOW')
                risk_counts[risk_level] += 1
        
        # Create chart
        plt.figure(figsize=(10, 6))
        colors = ['#ff4444', '#ffbb33', '#00C851']
        plt.bar(risk_counts.keys(), risk_counts.values(), color=colors)
        plt.title('Risk Level Distribution')
        plt.ylabel('Number of Findings')
        
        # Save chart
        chart_path = self.output_dir / 'risk_summary.png'
        plt.savefig(chart_path)
        plt.close()
        
        return str(chart_path)
    
    def create_vulnerability_timeline(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create a timeline of vulnerabilities found."""
        dates = []
        counts = []
        
        for result in scan_results:
            timestamp = result.get('timestamp')
            if timestamp:
                dates.append(pd.to_datetime(timestamp))
                counts.append(len(result.get('results', {}).get('findings', [])))
        
        plt.figure(figsize=(12, 6))
        plt.plot(dates, counts, marker='o')
        plt.title('Vulnerability Discovery Timeline')
        plt.xlabel('Scan Date')
        plt.ylabel('Vulnerabilities Found')
        plt.xticks(rotation=45)
        
        chart_path = self.output_dir / 'vuln_timeline.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def create_attack_surface_heatmap(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create a heatmap of the attack surface."""
        # Extract attack surface metrics
        metrics = {}
        
        for result in scan_results:
            scan_type = result.get('scan_type', '')
            if 'attack_surface' in result.get('results', {}):
                metrics[scan_type] = result['results']['attack_surface']
        
        # Create heatmap data
        data = []
        labels = []
        
        for scan_type, surface in metrics.items():
            row = []
            if not labels:
                labels = list(surface.keys())
            for metric in labels:
                value = surface.get(metric, 0)
                if isinstance(value, bool):
                    value = 1 if value else 0
                elif isinstance(value, str):
                    value = {'HIGH': 1.0, 'MEDIUM': 0.5, 'LOW': 0.2}.get(value, 0)
                row.append(float(value))
            data.append(row)
        
        # Create heatmap
        plt.figure(figsize=(12, 8))
        sns.heatmap(data, 
                   xticklabels=labels,
                   yticklabels=list(metrics.keys()),
                   cmap='YlOrRd',
                   annot=True)
        plt.title('Attack Surface Analysis')
        
        chart_path = self.output_dir / 'attack_surface_heatmap.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def create_tech_stack_chart(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create a visualization of the technology stack."""
        tech_data = {}
        
        for result in scan_results:
            if result.get('scan_type') == 'tech':
                for tech in result.get('results', {}).get('findings', []):
                    category = tech.get('category', 'Other')
                    if category not in tech_data:
                        tech_data[category] = []
                    tech_data[category].append(tech['name'])
        
        # Create treemap
        plt.figure(figsize=(15, 10))
        
        def draw_rect(ax, coords, label, color):
            x, y, w, h = coords
            ax.add_patch(plt.Rectangle((x, y), w, h, facecolor=color, alpha=0.7))
            ax.text(x + w/2, y + h/2, label, ha='center', va='center')
        
        ax = plt.gca()
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        
        colors = plt.cm.Set3(np.linspace(0, 1, len(tech_data)))
        y = 0
        height = 1 / len(tech_data)
        
        for (category, techs), color in zip(tech_data.items(), colors):
            width = 1 / (len(techs) + 1)
            x = 0
            
            # Draw category
            draw_rect(ax, (x, y, width, height), category, color)
            x += width
            
            # Draw technologies
            for tech in techs:
                draw_rect(ax, (x, y, width, height), tech, color)
                x += width
                
            y += height
        
        plt.title('Technology Stack Analysis')
        plt.axis('off')
        
        chart_path = self.output_dir / 'tech_stack.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def create_vulnerability_severity_chart(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create a bubble chart of vulnerabilities by severity and category."""
        vuln_data = []
        
        for result in scan_results:
            if result.get('scan_type') == 'vulnerability':
                for vuln in result.get('results', {}).get('findings', []):
                    vuln_data.append({
                        'severity': vuln.get('severity', 'LOW'),
                        'category': vuln.get('category', 'Other'),
                        'count': 1
                    })
        
        # Aggregate data
        df = pd.DataFrame(vuln_data)
        pivot = df.pivot_table(
            index='severity',
            columns='category',
            values='count',
            aggfunc='sum',
            fill_value=0
        )
        
        # Create bubble chart
        plt.figure(figsize=(12, 8))
        
        severity_scores = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        colors = plt.cm.Set3(np.linspace(0, 1, len(pivot.columns)))
        
        for i, category in enumerate(pivot.columns):
            sizes = pivot[category] * 100  # Scale bubble sizes
            plt.scatter(
                [severity_scores[idx] for idx in pivot.index],
                [i] * len(pivot.index),
                s=sizes,
                c=[colors[i]],
                alpha=0.6,
                label=category
            )
        
        plt.yticks(range(len(pivot.columns)), pivot.columns)
        plt.xticks(
            list(severity_scores.values()),
            list(severity_scores.keys())
        )
        
        plt.title('Vulnerability Distribution by Severity and Category')
        plt.xlabel('Severity')
        plt.ylabel('Category')
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
        
        chart_path = self.output_dir / 'vuln_severity.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def create_network_topology_chart(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create a network topology visualization using networkx."""
        # Create directed graph
        G = nx.DiGraph()
        
        # Add nodes and edges from scan results
        for result in scan_results:
            if result.get('scan_type') == 'domain':
                main_domain = result.get('target')
                G.add_node(main_domain, type='main_domain')
                
                # Add subdomains
                for subdomain in result.get('results', {}).get('subdomains', []):
                    G.add_node(subdomain['name'], type='subdomain')
                    G.add_edge(main_domain, subdomain['name'])
                    
            elif result.get('scan_type') == 'port':
                target = result.get('target')
                for port in result.get('results', {}).get('open_ports', []):
                    port_node = f"{target}:{port['number']}"
                    G.add_node(port_node, type='port', service=port.get('service'))
                    G.add_edge(target, port_node)
        
        # Create layout
        pos = nx.spring_layout(G)
        
        # Plot
        plt.figure(figsize=(15, 10))
        
        # Draw nodes with different colors based on type
        node_colors = {
            'main_domain': '#ff7f0e',
            'subdomain': '#1f77b4',
            'port': '#2ca02c'
        }
        
        for node_type in node_colors:
            nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == node_type]
            nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color=node_colors[node_type],
                                 node_size=1000, alpha=0.7, label=node_type)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, edge_color='gray', arrows=True)
        
        # Add labels
        labels = {node: node.split(':')[0] if ':' not in node else f"Port {node.split(':')[1]}"
                 for node in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels, font_size=8)
        
        plt.title('Network Topology')
        plt.legend()
        plt.axis('off')
        
        chart_path = self.output_dir / 'network_topology.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def create_attack_path_visualization(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create an attack path visualization showing potential exploit chains."""
        # Create directed graph
        G = nx.DiGraph()
        
        # Add nodes and edges representing attack paths
        entry_points = set()
        vulnerabilities = []
        critical_assets = set()
        
        for result in scan_results:
            if result.get('scan_type') == 'port':
                for port in result.get('results', {}).get('open_ports', []):
                    entry_point = f"Port {port['number']}\n({port.get('service', 'unknown')})"
                    entry_points.add(entry_point)
                    G.add_node(entry_point, type='entry')
                    
            elif result.get('scan_type') == 'vulnerability':
                for vuln in result.get('results', {}).get('findings', []):
                    vuln_node = f"{vuln['name']}\n(CVSS: {vuln.get('cvss_score', 'N/A')})"
                    vulnerabilities.append((vuln_node, vuln.get('severity', 'MEDIUM')))
                    G.add_node(vuln_node, type='vulnerability')
                    
                    # Connect vulnerabilities to entry points
                    for entry in entry_points:
                        if self._is_related_entry_point(entry, vuln):
                            G.add_edge(entry, vuln_node)
                            
            elif result.get('scan_type') == 'tech':
                for tech in result.get('results', {}).get('findings', []):
                    if tech.get('critical', False):
                        asset = f"{tech['name']}\n{tech.get('version', '')}"
                        critical_assets.add(asset)
                        G.add_node(asset, type='asset')
        
        # Connect vulnerabilities to assets
        for vuln_node, severity in vulnerabilities:
            for asset in critical_assets:
                if self._could_affect_asset(vuln_node, asset):
                    G.add_edge(vuln_node, asset)
        
        # Create layout emphasizing path flow
        pos = nx.kamada_kawai_layout(G)
        
        plt.figure(figsize=(15, 10))
        
        # Draw nodes with different styles based on type
        node_styles = {
            'entry': {'color': '#1f77b4', 'shape': 's', 'size': 1000},
            'vulnerability': {'color': '#ff7f0e', 'shape': 'o', 'size': 2000},
            'asset': {'color': '#2ca02c', 'shape': 'D', 'size': 1500}
        }
        
        for node_type, style in node_styles.items():
            nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == node_type]
            nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color=style['color'],
                                 node_shape=style['shape'], node_size=style['size'],
                                 alpha=0.7, label=node_type)
        
        # Draw edges with weight based on severity
        edge_weights = []
        for u, v in G.edges():
            if G.nodes[v]['type'] == 'vulnerability':
                severity = next(s for n, s in vulnerabilities if n == v)
                weight = {'HIGH': 2.0, 'MEDIUM': 1.5, 'LOW': 1.0}.get(severity, 1.0)
            else:
                weight = 1.0
            edge_weights.append(weight)
        
        nx.draw_networkx_edges(G, pos, edge_color='gray', width=edge_weights, arrows=True)
        
        # Add labels
        nx.draw_networkx_labels(G, pos, font_size=8)
        
        plt.title('Potential Attack Paths')
        plt.legend()
        plt.axis('off')
        
        chart_path = self.output_dir / 'attack_paths.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def _is_related_entry_point(self, entry: str, vuln: Dict) -> bool:
        """Determine if a vulnerability could be exploited through an entry point."""
        entry_service = entry.lower()
        vuln_desc = vuln.get('description', '').lower()
        attack_vector = vuln.get('attack_vector', '').lower()
        
        # Common services and their related terms
        service_terms = {
            'http': ['web', 'http', 'https', 'ssl', 'tls'],
            'ftp': ['ftp', 'file transfer'],
            'ssh': ['ssh', 'remote shell'],
            'smtp': ['smtp', 'email', 'mail'],
            'dns': ['dns', 'domain'],
            'database': ['sql', 'database', 'postgres', 'mysql', 'oracle']
        }
        
        for service, terms in service_terms.items():
            if any(term in entry_service for term in [service]):
                return any(term in vuln_desc or term in attack_vector for term in terms)
        
        return False
    
    def _could_affect_asset(self, vuln_node: str, asset: str) -> bool:
        """Determine if a vulnerability could affect an asset."""
        vuln_lower = vuln_node.lower()
        asset_lower = asset.lower()
        
        # Extract technology name and version from asset
        asset_parts = asset_lower.split('\n')
        tech_name = asset_parts[0]
        tech_version = asset_parts[1] if len(asset_parts) > 1 else ''
        
        # Check if vulnerability mentions the technology
        return tech_name in vuln_lower or tech_version in vuln_lower 
    
    def create_compliance_status_chart(self, scan_results: List[Dict[str, Any]], company_info: Dict[str, Any]) -> str:
        """Create a compliance status visualization."""
        # Get compliance requirements from company info
        compliance_reqs = company_info.get('compliance', {})
        
        # Map findings to compliance controls
        compliance_status = {
            'PCI DSS': {'met': 0, 'partial': 0, 'not_met': 0},
            'HIPAA': {'met': 0, 'partial': 0, 'not_met': 0},
            'GDPR': {'met': 0, 'partial': 0, 'not_met': 0},
            'ISO 27001': {'met': 0, 'partial': 0, 'not_met': 0}
        }
        
        # Analyze findings against compliance requirements
        for result in scan_results:
            findings = result.get('results', {}).get('findings', [])
            for finding in findings:
                for framework, controls in self._map_finding_to_compliance(finding).items():
                    if framework in compliance_status:
                        for status, count in controls.items():
                            compliance_status[framework][status] += count
        
        # Create stacked bar chart
        frameworks = list(compliance_status.keys())
        met = [status['met'] for status in compliance_status.values()]
        partial = [status['partial'] for status in compliance_status.values()]
        not_met = [status['not_met'] for status in compliance_status.values()]
        
        plt.figure(figsize=(12, 6))
        width = 0.35
        
        plt.bar(frameworks, met, width, label='Met', color='#00C851')
        plt.bar(frameworks, partial, width, bottom=met, label='Partial', color='#ffbb33')
        plt.bar(frameworks, not_met, width, bottom=np.array(met) + np.array(partial),
                label='Not Met', color='#ff4444')
        
        plt.title('Compliance Status by Framework')
        plt.xlabel('Compliance Framework')
        plt.ylabel('Number of Controls')
        plt.legend()
        
        chart_path = self.output_dir / 'compliance_status.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def create_remediation_priority_chart(self, scan_results: List[Dict[str, Any]]) -> str:
        """Create a remediation priority matrix."""
        findings = []
        
        # Collect all findings
        for result in scan_results:
            for finding in result.get('results', {}).get('findings', []):
                findings.append({
                    'name': finding.get('name', 'Unknown'),
                    'severity': finding.get('severity', 'LOW'),
                    'effort': self._estimate_remediation_effort(finding),
                    'business_impact': self._assess_business_impact(finding)
                })
        
        # Create scatter plot
        plt.figure(figsize=(12, 8))
        
        # Define severity colors and sizes
        severity_props = {
            'CRITICAL': {'color': '#ff4444', 'size': 200},
            'HIGH': {'color': '#ff8800', 'size': 150},
            'MEDIUM': {'color': '#ffbb33', 'size': 100},
            'LOW': {'color': '#00C851', 'size': 50}
        }
        
        # Plot findings
        for finding in findings:
            props = severity_props.get(finding['severity'], severity_props['LOW'])
            plt.scatter(finding['effort'], finding['business_impact'],
                       c=props['color'], s=props['size'], alpha=0.6)
            plt.annotate(finding['name'], 
                        (finding['effort'], finding['business_impact']),
                        xytext=(5, 5), textcoords='offset points',
                        fontsize=8)
        
        # Add quadrant labels
        plt.axhline(y=5, color='gray', linestyle='--', alpha=0.3)
        plt.axvline(x=5, color='gray', linestyle='--', alpha=0.3)
        
        plt.text(2.5, 7.5, 'Quick Wins\n(High Impact, Low Effort)',
                 ha='center', va='center', bbox=dict(facecolor='white', alpha=0.8))
        plt.text(7.5, 7.5, 'Major Projects\n(High Impact, High Effort)',
                 ha='center', va='center', bbox=dict(facecolor='white', alpha=0.8))
        plt.text(2.5, 2.5, 'Low Priority\n(Low Impact, Low Effort)',
                 ha='center', va='center', bbox=dict(facecolor='white', alpha=0.8))
        plt.text(7.5, 2.5, 'Long Term\n(Low Impact, High Effort)',
                 ha='center', va='center', bbox=dict(facecolor='white', alpha=0.8))
        
        plt.title('Remediation Priority Matrix')
        plt.xlabel('Remediation Effort')
        plt.ylabel('Business Impact')
        
        # Add severity legend
        legend_elements = [plt.scatter([], [], c=props['color'], 
                             s=props['size'], label=severity)
                          for severity, props in severity_props.items()]
        plt.legend(handles=legend_elements)
        
        chart_path = self.output_dir / 'remediation_priority.png'
        plt.savefig(chart_path, bbox_inches='tight')
        plt.close()
        
        return str(chart_path)
    
    def _map_finding_to_compliance(self, finding: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
        """Map a finding to compliance controls."""
        compliance_mapping = {
            'PCI DSS': {
                'network_scan': ['1.1', '1.2', '1.3'],
                'vulnerability_scan': ['6.1', '6.2', '11.2'],
                'waf': ['6.6'],
                'ssl': ['4.1']
            },
            'HIPAA': {
                'network_scan': ['164.308(a)(1)', '164.308(a)(4)'],
                'vulnerability_scan': ['164.308(a)(8)'],
                'access_control': ['164.312(a)(1)'],
                'encryption': ['164.312(e)(1)']
            }
        }
        
        result = {}
        finding_type = finding.get('type', '')
        severity = finding.get('severity', 'LOW')
        
        for framework, controls in compliance_mapping.items():
            result[framework] = {'met': 0, 'partial': 0, 'not_met': 0}
            
            for control_type, control_ids in controls.items():
                if control_type in finding_type.lower():
                    if severity == 'LOW':
                        result[framework]['met'] += len(control_ids)
                    elif severity == 'MEDIUM':
                        result[framework]['partial'] += len(control_ids)
                    else:
                        result[framework]['not_met'] += len(control_ids)
        
        return result
    
    def _estimate_remediation_effort(self, finding: Dict[str, Any]) -> float:
        """Estimate the effort required to remediate a finding (1-10 scale)."""
        base_effort = {
            'CRITICAL': 8,
            'HIGH': 6,
            'MEDIUM': 4,
            'LOW': 2
        }.get(finding.get('severity', 'LOW'), 2)
        
        # Adjust based on complexity
        if 'requires_architecture_change' in finding:
            base_effort += 2
        if 'requires_third_party' in finding:
            base_effort += 1
        if 'automated_fix_available' in finding:
            base_effort -= 2
            
        return min(max(base_effort, 1), 10)
    
    def _assess_business_impact(self, finding: Dict[str, Any]) -> float:
        """Assess the business impact of a finding (1-10 scale)."""
        base_impact = {
            'CRITICAL': 9,
            'HIGH': 7,
            'MEDIUM': 5,
            'LOW': 3
        }.get(finding.get('severity', 'LOW'), 3)
        
        # Adjust based on affected assets
        if 'affects_customer_data' in finding:
            base_impact += 2
        if 'affects_financial_systems' in finding:
            base_impact += 2
        if 'public_exposure' in finding:
            base_impact += 1
            
        return min(max(base_impact, 1), 10) 