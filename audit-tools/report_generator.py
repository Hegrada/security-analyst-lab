#!/usr/bin/env python3
"""
📋 Security Report Generator

Automated security report generation tool with PDF export capabilities.
Generates professional security assessment reports from scan results.

Author: SOC Analyst
Version: 1.0.0
License: MIT
"""

import argparse
import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from html import escape

import colorama
from colorama import Fore, Style

colorama.init()


@dataclass
class Finding:
    """Security finding"""
    title: str
    severity: str
    cvss: float
    description: str
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)
    affected: str = ""
    
    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "cvss": self.cvss,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": self.references,
            "affected": self.affected
        }


@dataclass
class Report:
    """Security report"""
    title: str
    client_name: str
    assessor: str
    report_date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d"))
    scope: str = ""
    executive_summary: str = ""
    methodology: str = ""
    findings: List[Finding] = field(default_factory=list)
    risk_summary: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "client_name": self.client_name,
            "assessor": self.assessor,
            "report_date": self.report_date,
            "scope": self.scope,
            "executive_summary": self.executive_summary,
            "methodology": self.methodology,
            "findings": [f.to_dict() for f in self.findings],
            "risk_summary": self.risk_summary,
            "recommendations": self.recommendations
        }


class ReportGenerator:
    """Security Report Generator"""
    
    SEVERITY_COLORS = {
        "Critical": "#FF0000",
        "High": "#FF6600",
        "Medium": "#FFCC00",
        "Low": "#00CC00",
        "Info": "#0066FF"
    }
    
    SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger("report_generator")
        logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _generate_risk_summary(self, findings: List[Finding]) -> Dict[str, int]:
        """Generate risk summary from findings"""
        summary = {s: 0 for s in self.SEVERITY_ORDER}
        
        for finding in findings:
            if finding.severity in summary:
                summary[finding.severity] += 1
        
        return summary
    
    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Calculate overall risk score (0-10)"""
        weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 4,
            "Low": 2,
            "Info": 0
        }
        
        if not findings:
            return 0
        
        total_weight = sum(weights.get(f.severity, 0) for f in findings)
        return min(10, total_weight / (len(findings) * 2))
    
    def generate_from_scan_results(self, scan_file: str, 
                                  report_type: str = "vulnerability") -> Report:
        """Generate report from scan results file"""
        self.logger.info(f"Loading scan results from {scan_file}")
        
        with open(scan_file, 'r') as f:
            scan_data = json.load(f)
        
        # Create findings from scan data
        findings = []
        
        if report_type == "vulnerability" and "vulnerabilities" in scan_data:
            for vuln in scan_data["vulnerabilities"]:
                severity = vuln.get("severity_name", "Medium")
                
                finding = Finding(
                    title=vuln.get("name", "Unknown Vulnerability"),
                    severity=severity,
                    cvss=vuln.get("cvss", 0.0),
                    description=vuln.get("description", ""),
                    evidence=vuln.get("proof", ""),
                    remediation=vuln.get("remediation", ""),
                    references=vuln.get("references", []),
                    affected=vuln.get("url", "")
                )
                findings.append(finding)
        
        elif report_type == "portscan" and "open_ports" in scan_data:
            for port in scan_data["open_ports"]:
                finding = Finding(
                    title=f"Open Port: {port['port']}/{port['service']}",
                    severity="Medium",
                    cvss=0.0,
                    description=f"Port {port['port']} is open and running {port['service']}",
                    evidence=f"Port {port['port']}/tcp - {port['service']}",
                    remediation="Ensure this port is necessary and properly secured",
                    affected=f"Port {port['port']}"
                )
                findings.append(finding)
        
        # Create report
        report = Report(
            title=f"Security Assessment Report - {report_type.upper()}",
            client_name="Organization Name",
            assessor="Security Analyst",
            scope=scan_data.get("target", ""),
            findings=findings,
            risk_summary=self._generate_risk_summary(findings)
        )
        
        report.executive_summary = self._generate_executive_summary(findings)
        
        return report
    
    def _generate_executive_summary(self, findings: List[Finding]) -> str:
        """Generate executive summary"""
        critical = len([f for f in findings if f.severity == "Critical"])
        high = len([f for f in findings if f.severity == "High"])
        medium = len([f for f in findings if f.severity == "Medium"])
        low = len([f for f in findings if f.severity == "Low"])
        
        risk_score = self._calculate_risk_score(findings)
        
        summary = f"""
This security assessment identified {len(findings)} security findings, 
including {critical} critical and {high} high severity issues. 
The overall risk score is {risk_score:.1f}/10.

Key findings include:
- {critical} Critical severity vulnerabilities requiring immediate attention
- {high} High severity vulnerabilities requiring prompt remediation
- {medium} Medium severity vulnerabilities to be addressed
- {low} Low severity findings to be noted
"""
        return summary.strip()
    
    def generate_html_report(self, report: Report, output_file: str):
        """Generate HTML report"""
        self.logger.info(f"Generating HTML report: {output_file}")
        
        risk_score = self._calculate_risk_score(report.findings)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escape(report.title)}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .meta {{
            opacity: 0.8;
            font-size: 0.9em;
        }}
        .section {{
            margin-bottom: 30px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }}
        .section h2 {{
            color: #1a1a2e;
            border-bottom: 2px solid #1a1a2e;
            padding-bottom: 10px;
        }}
        .finding {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            border-left: 5px solid #ddd;
        }}
        .finding.Critical {{ border-left-color: #FF0000; }}
        .finding.High {{ border-left-color: #FF6600; }}
        .finding.Medium {{ border-left-color: #FFCC00; }}
        .finding.Low {{ border-left-color: #00CC00; }}
        .finding.Info {{ border-left-color: #0066FF; }}
        .finding h3 {{
            margin: 0 0 10px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }}
        .Critical .severity-badge {{ background: #FF0000; }}
        .High .severity-badge {{ background: #FF6600; }}
        .Medium .severity-badge {{ background: #FFCC00; color: #333; }}
        .Low .severity-badge {{ background: #00CC00; }}
        .Info .severity-badge {{ background: #0066FF; }}
        .evidence {{
            background: #f0f0f0;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            margin: 10px 0;
            word-break: break-all;
        }}
        .remediation {{
            background: #e8f5e9;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }}
        .risk-summary {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}
        .risk-card {{
            text-align: center;
            padding: 20px;
            border-radius: 10px;
            color: white;
        }}
        .risk-card.Critical {{ background: #FF0000; }}
        .risk-card.High {{ background: #FF6600; }}
        .risk-card.Medium {{ background: #FFCC00; color: #333; }}
        .risk-card.Low {{ background: #00CC00; }}
        .risk-card.Info {{ background: #0066FF; }}
        .risk-card .count {{
            font-size: 3em;
            font-weight: bold;
        }}
        .risk-card .label {{
            font-size: 0.9em;
        }}
        .score-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }}
        .score-card .score {{
            font-size: 4em;
            font-weight: bold;
        }}
        .references {{
            margin-top: 10px;
            font-size: 0.9em;
        }}
        .references a {{
            color: #0066FF;
            margin-right: 15px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{escape(report.title)}</h1>
        <div class="meta">
            <p><strong>Client:</strong> {escape(report.client_name)}</p>
            <p><strong>Assessor:</strong> {escape(report.assessor)}</p>
            <p><strong>Date:</strong> {report.report_date}</p>
            <p><strong>Scope:</strong> {escape(report.scope)}</p>
        </div>
    </div>
    
    <div class="score-card">
        <div class="score">{risk_score:.1f}</div>
        <div>Overall Risk Score (0-10)</div>
    </div>
    
    <div class="risk-summary">
"""
        
        for severity in self.SEVERITY_ORDER:
            count = report.risk_summary.get(severity, 0)
            html += f"""
        <div class="risk-card {severity}">
            <div class="count">{count}</div>
            <div class="label">{severity}</div>
        </div>
"""
        
        html += """
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>""" + escape(report.executive_summary).replace('\n', '<br>') + """</p>
    </div>
"""
        
        if report.methodology:
            html += f"""
    <div class="section">
        <h2>Methodology</h2>
        <p>{escape(report.methodology)}</p>
    </div>
"""
        
        html += """
    <div class="section">
        <h2>Detailed Findings</h2>
"""
        
        for i, finding in enumerate(sorted(report.findings, 
                                           key=lambda x: self.SEVERITY_ORDER.index(x.severity))):
            html += f"""
        <div class="finding {finding.severity}">
            <h3>
                <span>{i+1}. {escape(finding.title)}</span>
                <span class="severity-badge">{finding.severity}</span>
            </h3>
"""
            
            if finding.affected:
                html += f"            <p><strong>Affected:</strong> {escape(finding.affected)}</p>\n"
            
            if finding.cvss > 0:
                html += f"            <p><strong>CVSS Score:</strong> {finding.cvss}</p>\n"
            
            html += f"""
            <p><strong>Description:</strong> {escape(finding.description)}</p>
"""
            
            if finding.evidence:
                html += f"""
            <div class="evidence">{escape(finding.evidence)}</div>
"""
            
            html += f"""
            <div class="remediation">
                <strong>Remediation:</strong> {escape(finding.remediation)}
            </div>
"""
            
            if finding.references:
                html += """
            <div class="references">
                <strong>References:</strong>
"""
                for ref in finding.references:
                    html += f"                <a href=\"{escape(ref)}\">{escape(ref)}</a>\n"
                html += "            </div>\n"
            
            html += "        </div>\n"
        
        html += """
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ol>
"""
        
        for rec in report.recommendations:
            html += f"            <li>{escape(rec)}</li>\n"
        
        html += """
        </ol>
    </div>
    
    <div class="section">
        <h2>Appendices</h2>
        <p>Raw scan data and detailed technical findings are available in the accompanying JSON file.</p>
    </div>
    
    <footer style="text-align: center; padding: 20px; color: #666; font-size: 0.8em;">
        <p>Generated by Security Audit Lab - Report Generator</p>
        <p>© {0} Security Assessment Report</p>
    </footer>
</body>
</html>
""".format(datetime.now().year)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        self.logger.info(f"HTML report saved to {output_file}")
    
    def generate_json_report(self, report: Report, output_file: str):
        """Generate JSON report"""
        self.logger.info(f"Generating JSON report: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report.to_dict(), f, indent=2)
        
        self.logger.info(f"JSON report saved to {output_file}")
    
    def generate_markdown_report(self, report: Report, output_file: str):
        """Generate Markdown report"""
        self.logger.info(f"Generating Markdown report: {output_file}")
        
        risk_score = self._calculate_risk_score(report.findings)
        
        md = f"""# {report.title}

## Report Metadata

| Field | Value |
|-------|-------|
| Client | {report.client_name} |
| Assessor | {report.assessor} |
| Date | {report.report_date} |
| Scope | {report.scope} |

## Risk Summary

| Severity | Count |
|----------|-------|
| Critical | {report.risk_summary.get('Critical', 0)} |
| High | {report.risk_summary.get('High', 0)} |
| Medium | {report.risk_summary.get('Medium', 0)} |
| Low | {report.risk_summary.get('Low', 0)} |
| Info | {report.risk_summary.get('Info', 0)} |

**Overall Risk Score:** {risk_score:.1f}/10

## Executive Summary

{report.executive_summary}
"""
        
        if report.methodology:
            md += f"\n## Methodology\n\n{report.methodology}\n"
        
        md += "\n## Detailed Findings\n\n"
        
        for i, finding in enumerate(sorted(report.findings,
                                           key=lambda x: self.SEVERITY_ORDER.index(x.severity)), 1):
            md += f"### {i}. {finding.title} ({finding.severity})\n\n"
            
            if finding.affected:
                md += f"**Affected:** {finding.affected}\n\n"
            
            if finding.cvss > 0:
                md += f"**CVSS Score:** {finding.cvss}\n\n"
            
            md += f"**Description:** {finding.description}\n\n"
            
            if finding.evidence:
                md += f"**Evidence:**\n```\n{finding.evidence}\n```\n\n"
            
            md += f"**Remediation:** {finding.remediation}\n\n"
            
            if finding.references:
                md += "**References:**\n"
                for ref in finding.references:
                    md += f"- [{ref}]({ref})\n"
                md += "\n"
        
        if report.recommendations:
            md += "\n## Recommendations\n\n"
            for rec in report.recommendations:
                md += f"- {rec}\n"
            md += "\n"
        
        md += f"""
---

*Generated by Security Audit Lab - Report Generator*
*Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}*
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md)
        
        self.logger.info(f"Markdown report saved to {output_file}")
    
    def save_results(self, report: Report, output_file: str, format: str = "html"):
        """Save report in specified format"""
        if format == "html":
            self.generate_html_report(report, output_file)
        elif format == "json":
            self.generate_json_report(report, output_file)
        elif format == "md" or format == "markdown":
            self.generate_markdown_report(report, output_file)
        else:
            self.logger.error(f"Unsupported format: {format}")
    
    def print_report_summary(self, report: Report):
        """Print report summary"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}REPORT SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Title: {report.title}")
        print(f"Client: {report.client_name}")
        print(f"Assessor: {report.assessor}")
        print(f"Date: {report.report_date}\n")
        
        risk_score = self._calculate_risk_score(report.findings)
        print(f"Risk Score: {risk_score:.1f}/10\n")
        
        print("Findings by Severity:")
        for severity in self.SEVERITY_ORDER:
            count = report.risk_summary.get(severity, 0)
            color = getattr(Fore, severity.upper(), Fore.WHITE)
            print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
        
        print(f"\nTotal Findings: {len(report.findings)}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Security Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i scan_results.json -o report.html --format html
  %(prog)s -i vuln_results.json -o report.md --format markdown
  %(prog)s -i portscan_results.json -o report.pdf --format html
        """
    )
    
    parser.add_argument('-i', '--input', required=True,
                       help="Input JSON file with scan results")
    parser.add_argument('-o', '--output', default="security_report",
                       help="Output file name (without extension)")
    parser.add_argument('--format', choices=['html', 'json', 'markdown', 'md'], 
                       default='html', help="Output format (default: html)")
    parser.add_argument('--type', choices=['vulnerability', 'portscan', 'log'],
                       default='vulnerability', help="Scan result type")
    parser.add_argument('-v', '--verbose', action='store_true',
                       help="Enable verbose output")
    parser.add_argument('--no-color', action='store_true',
                       help="Disable colored output")
    
    args = parser.parse_args()
    
    if args.no_color:
        colorama.deinit()
    
    generator = ReportGenerator(verbose=args.verbose)
    
    # Generate report from scan results
    report = generator.generate_from_scan_results(args.input, args.type)
    
    # Print summary
    generator.print_report_summary(report)
    
    # Save report
    output_file = f"{args.output}.{args.format}"
    generator.save_results(report, output_file, args.format)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
