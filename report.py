import json
import csv
import os
from datetime import datetime
from typing import Dict, List
from config import config


class ReportGenerator:
    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir or config.OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)

    def export_json(self, results: Dict, filename: str = None) -> str:
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.json"

        filepath = os.path.join(self.output_dir, filename)
        output = {
            "metadata": {
                "tool": "Secret Hunter V2",
                "version": "2.0.0",
                "timestamp": datetime.utcnow().isoformat(),
                "scan_type": results.get("scan_type", "unknown"),
                "target": results.get("target", "unknown"),
            },
            "stats": results.get("stats", {}),
            "findings": results.get("findings", []),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False, default=str)

        return filepath

    def export_sarif(self, results: Dict, filename: str = None) -> str:
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.sarif"

        filepath = os.path.join(self.output_dir, filename)

        runs = []
        findings = results.get("findings", [])
        tool_rules = {}
        tool_results = []

        for finding in findings:
            rule_id = finding.get("pattern", "unknown").replace(" ", "_").lower()
            if rule_id not in tool_rules:
                tool_rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.get("pattern", "unknown"),
                    "shortDescription": {"text": finding.get("description", "")},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(finding.get("severity", "MEDIUM"))
                    },
                    "properties": {
                        "severity": finding.get("severity", "MEDIUM"),
                        "group": finding.get("group", "generic"),
                    },
                }

            result_item = {
                "ruleId": rule_id,
                "message": {
                    "text": finding.get("description", "Secret detected"),
                    "markdown": f"**{finding.get('pattern', 'Unknown')}**: {finding.get('match', '')[:100]}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("file", "unknown"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.get("line", 1),
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": finding.get("severity", "MEDIUM"),
                    "match": finding.get("match", "")[:200],
                    "line_content": finding.get("line_content", "")[:200],
                },
            }
            tool_results.append(result_item)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Secret Hunter V2",
                            "version": "2.0.0",
                            "informationUri": "https://github.com/secret-hunter-v2",
                            "rules": list(tool_rules.values()),
                        }
                    },
                    "results": tool_results,
                }
            ],
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False, default=str)

        return filepath

    def export_html(self, results: Dict, filename: str = None) -> str:
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.html"

        filepath = os.path.join(self.output_dir, filename)
        findings = results.get("findings", [])
        stats = results.get("stats", {})
        scan_type = results.get("scan_type", "unknown")
        target = results.get("target", "unknown")

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }

        findings_html = ""
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "UNKNOWN")
            color = severity_colors.get(sev, "#6b7280")
            file_link = f.get("file", "unknown")
            line = f.get("line", "-")
            match_text = f.get("match", "")[:100]
            description = f.get("description", "")
            pattern = f.get("pattern", "Unknown")

            findings_html += f"""
            <tr>
                <td>{i}</td>
                <td><span class="severity-badge" style="background-color: {color};">{sev}</span></td>
                <td>{pattern}</td>
                <td class="file-path">{file_link}:{line}</td>
                <td class="match-text"><code>{match_text}</code></td>
                <td>{description}</td>
            </tr>
            """

        severity_chart_html = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            color = severity_colors.get(sev, "#6b7280")
            if count > 0:
                severity_chart_html += f"""
                <div class="severity-item">
                    <div class="severity-color" style="background-color: {color};"></div>
                    <span class="severity-label">{sev}</span>
                    <span class="severity-count">{count}</span>
                </div>
                """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Hunter V2 - Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 2rem; }}
        .header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border: 1px solid #334155; border-radius: 12px; padding: 2rem; margin-bottom: 2rem; }}
        .header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; color: #f8fafc; }}
        .header .subtitle {{ color: #94a3b8; font-size: 1rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; text-align: center; }}
        .stat-card .value {{ font-size: 2rem; font-weight: 700; color: #f8fafc; }}
        .stat-card .label {{ color: #94a3b8; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .severity-section {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }}
        .severity-item {{ display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0; }}
        .severity-color {{ width: 12px; height: 12px; border-radius: 50%; }}
        .severity-label {{ flex: 1; font-weight: 500; }}
        .severity-count {{ font-size: 1.25rem; font-weight: 700; }}
        .table-container {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; overflow: hidden; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; text-align: left; padding: 1rem; }}
        td {{ padding: 0.75rem 1rem; border-top: 1px solid #334155; font-size: 0.875rem; }}
        tr:hover {{ background: #334155; }}
        .severity-badge {{ padding: 0.25rem 0.75rem; border-radius: 9999px; color: white; font-size: 0.75rem; font-weight: 600; }}
        .file-path {{ color: #60a5fa; font-family: monospace; font-size: 0.8rem; word-break: break-all; }}
        .match-text {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        code {{ background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }}
        .footer {{ text-align: center; color: #64748b; margin-top: 2rem; padding: 1rem; font-size: 0.875rem; }}
        .no-findings {{ text-align: center; padding: 3rem; color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Secret Hunter V2 - Security Report</h1>
            <div class="subtitle">Scan Type: {scan_type} | Target: {target} | Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{len(findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="value">{severity_counts.get('CRITICAL', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="value">{severity_counts.get('HIGH', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card">
                <div class="value">{severity_counts.get('MEDIUM', 0)}</div>
                <div class="label">Medium</div>
            </div>
        </div>

        <div class="severity-section">
            <h3 style="margin-bottom: 1rem; color: #f8fafc;">Severity Distribution</h3>
            {severity_chart_html}
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Pattern</th>
                        <th>Location</th>
                        <th>Match</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_html if findings_html else '<tr><td colspan="6" class="no-findings">No findings detected</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Secret Hunter V2 v2.0.0 - Security Auditing Tool
        </div>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath

    def export_csv(self, results: Dict, filename: str = None) -> str:
        if filename is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.csv"

        filepath = os.path.join(self.output_dir, filename)
        findings = results.get("findings", [])

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Number", "Severity", "Pattern", "Group", "File", "Line",
                "Match", "Description", "Line Content",
            ])

            for i, finding in enumerate(findings, 1):
                writer.writerow([
                    i,
                    finding.get("severity", ""),
                    finding.get("pattern", ""),
                    finding.get("group", ""),
                    finding.get("file", ""),
                    finding.get("line", ""),
                    finding.get("match", ""),
                    finding.get("description", ""),
                    finding.get("line_content", ""),
                ])

        return filepath

    def _severity_to_sarif_level(self, severity: str) -> str:
        severity_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }
        return severity_map.get(severity.upper(), "warning")
