import json
import os
import sys
from datetime import datetime

def load_json(file_path):
    if not os.path.exists(file_path):
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return None

def generate_html(semgrep_data, pip_audit_data, output_path):
    # Parse Semgrep SAST results
    sast_findings = []
    sast_summary = {"ERROR": 0, "WARNING": 0, "INFO": 0, "total": 0}
    secrets_found = 0

    if semgrep_data and "results" in semgrep_data:
        for finding in semgrep_data["results"]:
            severity = finding.get("extra", {}).get("severity", "WARNING").upper()
            if severity not in sast_summary:
                severity = "WARNING"
            
            sast_summary[severity] += 1
            sast_summary["total"] += 1

            # Detect secrets from rule ID or message
            rule_id = finding.get("check_id", "")
            message = finding.get("extra", {}).get("message", "")
            if "secret" in rule_id.lower() or "secret" in message.lower() or "entropy" in rule_id.lower() or "key" in rule_id.lower():
                secrets_found += 1

            sast_findings.append({
                "file": finding.get("path", "unknown"),
                "line": finding.get("start", {}).get("line", 0),
                "col": finding.get("start", {}).get("col", 0),
                "rule_id": rule_id,
                "message": message,
                "severity": severity,
                "lines": finding.get("extra", {}).get("lines", "").strip()
            })

    # Parse pip-audit dependency results
    dep_findings = []
    dep_summary = {"vulnerable": 0, "total_vulns": 0}

    if pip_audit_data:
        # Check if it's a dict with 'dependencies' key (standard pip-audit format)
        dependencies = []
        if isinstance(pip_audit_data, dict):
            dependencies = pip_audit_data.get("dependencies", [])
        elif isinstance(pip_audit_data, list):
            dependencies = pip_audit_data

        for dep in dependencies:
            vulns = dep.get("vulns", [])
            if vulns:
                dep_summary["vulnerable"] += 1
                dep_summary["total_vulns"] += len(vulns)
                
                parsed_vulns = []
                for v in vulns:
                    parsed_vulns.append({
                        "id": v.get("id", "Unknown CVE"),
                        "fix_versions": v.get("fix_versions", []),
                        "aliases": v.get("aliases", []),
                        "description": v.get("description", "No description available.")
                    })
                
                dep_findings.append({
                    "name": dep.get("name", "unknown"),
                    "version": dep.get("version", "unknown"),
                    "vulns": parsed_vulns
                })

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build the HTML template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - POC</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-green: #4ade80;
            --accent-red: #f87171;
            --accent-yellow: #fbbf24;
            --border-color: #475569;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 2rem;
            min-height: 100vh;
        }}

        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 2rem;
            border-radius: 16px;
            border: 1px solid var(--border-color);
            margin-bottom: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .header-title h1 {{
            font-size: 1.8rem;
            font-weight: 700;
            letter-spacing: -0.025em;
            background: linear-gradient(to right, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .header-title p {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }}

        .header-meta {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}

        .grid-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }}

        .card-summary {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}

        .card-summary:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
        }}

        .card-summary::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }}

        .card-blue::before {{ background-color: var(--accent-blue); }}
        .card-red::before {{ background-color: var(--accent-red); }}
        .card-yellow::before {{ background-color: var(--accent-yellow); }}
        .card-green::before {{ background-color: var(--accent-green); }}

        .card-title {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }}

        .card-value {{
            font-size: 2rem;
            font-weight: 700;
        }}

        .card-detail {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 0.5rem;
        }}

        .tabs {{
            display: flex;
            gap: 1rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 1.5rem;
        }}

        .tab-btn {{
            background: none;
            border: none;
            color: var(--text-secondary);
            padding: 0.75rem 1.5rem;
            font-weight: 500;
            font-size: 0.95rem;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.2s ease;
        }}

        .tab-btn:hover {{
            color: var(--text-primary);
        }}

        .tab-btn.active {{
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
        }}

        .tab-content {{
            display: none;
        }}

        .tab-content.active {{
            display: block;
        }}

        .table-container {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            font-size: 0.9rem;
        }}

        th {{
            background-color: rgba(15, 23, 42, 0.6);
            color: var(--text-primary);
            font-weight: 600;
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }}

        td {{
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        tr.expandable-row {{
            cursor: pointer;
            transition: background-color 0.15s ease;
        }}

        tr.expandable-row:hover {{
            background-color: rgba(255, 255, 255, 0.03);
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.5rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-error {{
            background-color: rgba(248, 113, 113, 0.1);
            color: var(--accent-red);
            border: 1px solid rgba(248, 113, 113, 0.2);
        }}

        .badge-warning {{
            background-color: rgba(251, 191, 36, 0.1);
            color: var(--accent-yellow);
            border: 1px solid rgba(251, 191, 36, 0.2);
        }}

        .badge-info {{
            background-color: rgba(56, 189, 248, 0.1);
            color: var(--accent-blue);
            border: 1px solid rgba(56, 189, 248, 0.2);
        }}

        .badge-critical {{
            background-color: rgba(239, 68, 68, 0.15);
            color: #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}

        .detail-cell {{
            background-color: #0b0f19;
            padding: 1.5rem !important;
            border-bottom: 1px solid var(--border-color);
        }}

        .code-block {{
            background-color: #020617;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid rgba(255, 255, 255, 0.05);
            margin-top: 0.75rem;
            color: #e2e8f0;
            font-family: monospace;
            font-size: 0.85rem;
        }}

        .finding-desc {{
            color: var(--text-secondary);
            line-height: 1.5;
            margin-bottom: 0.5rem;
        }}

        .hidden-row {{
            display: none;
        }}

        .search-box {{
            width: 100%;
            max-width: 400px;
            padding: 0.6rem 1rem;
            border-radius: 8px;
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            margin-bottom: 1rem;
            font-size: 0.85rem;
        }}

        .search-box:focus {{
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
        }}

        .vuln-item {{
            margin-bottom: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 1rem;
        }}

        .vuln-item:last-child {{
            margin-bottom: 0;
            border-bottom: none;
            padding-bottom: 0;
        }}

        .vuln-meta {{
            display: flex;
            gap: 1rem;
            align-items: center;
            margin-bottom: 0.5rem;
        }}
    </style>
</head>
<body>

    <header>
        <div class="header-title">
            <h1>Security & Code Vulnerability Report</h1>
            <p>Static Analysis (SAST) & Third-Party Dependency Scanning Dashboard</p>
        </div>
        <div class="header-meta">
            <div>Report Generated: <strong>{scan_time}</strong></div>
            <div>Environment: <strong>POC Local Test</strong></div>
        </div>
    </header>

    <div class="grid-summary">
        <div class="card-summary card-blue">
            <div class="card-title">SAST Static Findings</div>
            <div class="card-value">{sast_summary["total"]}</div>
            <div class="card-detail">Error: {sast_summary["ERROR"]} | Warning: {sast_summary["WARNING"]}</div>
        </div>
        <div class="card-summary card-red">
            <div class="card-title">Dependency Vulnerabilities</div>
            <div class="card-value">{dep_summary["total_vulns"]}</div>
            <div class="card-detail">In {dep_summary["vulnerable"]} vulnerable packages</div>
        </div>
        <div class="card-summary card-yellow">
            <div class="card-title">Hardcoded Secrets</div>
            <div class="card-value">{secrets_found}</div>
            <div class="card-detail">Identified in credentials scan</div>
        </div>
        <div class="card-summary card-green">
            <div class="card-title">Security Posture</div>
            <div class="card-value">{"FAIL" if (sast_summary["ERROR"] > 0 or dep_summary["total_vulns"] > 0) else "PASS"}</div>
            <div class="card-detail">Action required if FAIL</div>
        </div>
    </div>

    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('sast')">SAST Scan (Semgrep)</button>
        <button class="tab-btn" onclick="switchTab('deps')">Dependency Audit (pip-audit)</button>
    </div>

    <!-- SAST Scan Content -->
    <div id="sast-content" class="tab-content active">
        <input type="text" class="search-box" id="sast-search" placeholder="Search SAST findings by file or description..." onkeyup="filterSast()">
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 120px;">Severity</th>
                        <th>Vulnerability & File Location</th>
                        <th>Rule ID</th>
                    </tr>
                </thead>
                <tbody id="sast-table-body">
    """

    if not sast_findings:
        html_content += """
                    <tr>
                        <td colspan="3" style="text-align: center; color: var(--text-secondary); padding: 3rem;">
                            No static analysis vulnerabilities found. Excellent job!
                        </td>
                    </tr>
        """
    else:
        for idx, f in enumerate(sast_findings):
            badge_class = "badge-error" if f["severity"] == "ERROR" else "badge-warning" if f["severity"] == "WARNING" else "badge-info"
            html_content += f"""
                    <tr class="expandable-row" onclick="toggleDetails('sast-{idx}')">
                        <td><span class="badge {badge_class}">{f["severity"]}</span></td>
                        <td>
                            <strong>{f["file"]}:{f["line"]}</strong>
                            <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem;">
                                {f["message"][:100]}{'...' if len(f["message"]) > 100 else ''}
                            </div>
                        </td>
                        <td style="color: var(--accent-blue); font-family: monospace; font-size: 0.8rem;">{f["rule_id"]}</td>
                    </tr>
                    <tr id="sast-{idx}" class="hidden-row">
                        <td colspan="3" class="detail-cell">
                            <div class="finding-desc">
                                <strong>Description:</strong> {f["message"]}
                            </div>
                            <div style="font-size: 0.85rem; margin-top: 0.5rem;">
                                <strong>File Path:</strong> <code style="color: var(--accent-blue); font-family: monospace;">{f["file"]}:{f["line"]}</code>
                            </div>
                            <div class="code-block">
                                <pre><code>{f["lines"]}</code></pre>
                            </div>
                        </td>
                    </tr>
            """

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <!-- Dependencies Scan Content -->
    <div id="deps-content" class="tab-content">
        <input type="text" class="search-box" id="deps-search" placeholder="Search packages..." onkeyup="filterDeps()">
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Package Name</th>
                        <th style="width: 150px;">Installed Version</th>
                        <th style="width: 150px;">Vulnerabilities</th>
                    </tr>
                </thead>
                <tbody id="deps-table-body">
    """

    if not dep_findings:
        html_content += """
                    <tr>
                        <td colspan="3" style="text-align: center; color: var(--text-secondary); padding: 3rem;">
                            No dependency vulnerabilities found. All third-party packages are clean!
                        </td>
                    </tr>
        """
    else:
        for idx, d in enumerate(dep_findings):
            vuln_count = len(d["vulns"])
            html_content += f"""
                    <tr class="expandable-row" onclick="toggleDetails('dep-{idx}')">
                        <td><strong>{d["name"]}</strong></td>
                        <td><code style="font-family: monospace;">{d["version"]}</code></td>
                        <td><span class="badge badge-critical">{vuln_count} found</span></td>
                    </tr>
                    <tr id="dep-{idx}" class="hidden-row">
                        <td colspan="3" class="detail-cell">
            """
            
            for v in d["vulns"]:
                fix_str = ", ".join(v["fix_versions"]) if v["fix_versions"] else "No fix version declared"
                html_content += f"""
                            <div class="vuln-item">
                                <div class="vuln-meta">
                                    <span class="badge badge-critical">{v["id"]}</span>
                                    <span style="font-size: 0.8rem; color: var(--accent-green);">Fix Version: <strong>{fix_str}</strong></span>
                                </div>
                                <div style="font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                                    {v["description"]}
                                </div>
                            </div>
                """
                
            html_content += """
                        </td>
                    </tr>
            """

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            if (tabId === 'sast') {
                document.querySelector('button[onclick="switchTab(\'sast\')"]').classList.add('active');
                document.getElementById('sast-content').classList.add('active');
            } else {
                document.querySelector('button[onclick="switchTab(\'deps\')"]').classList.add('active');
                document.getElementById('deps-content').classList.add('active');
            }
        }

        function toggleDetails(rowId) {
            const row = document.getElementById(rowId);
            if (row.classList.contains('hidden-row')) {
                row.classList.remove('hidden-row');
            } else {
                row.classList.add('hidden-row');
            }
        }

        function filterSast() {
            const query = document.getElementById('sast-search').value.toLowerCase();
            const rows = document.querySelectorAll('#sast-table-body > tr.expandable-row');
            
            rows.forEach((row, idx) => {
                const text = row.textContent.toLowerCase();
                const detailRow = document.getElementById('sast-' + idx);
                
                if (text.includes(query)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                    if (detailRow) detailRow.classList.add('hidden-row');
                }
            });
        }

        function filterDeps() {
            const query = document.getElementById('deps-search').value.toLowerCase();
            const rows = document.querySelectorAll('#deps-table-body > tr.expandable-row');
            
            rows.forEach((row, idx) => {
                const text = row.textContent.toLowerCase();
                const detailRow = document.getElementById('dep-' + idx);
                
                if (text.includes(query)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                    if (detailRow) detailRow.classList.add('hidden-row');
                }
            });
        }
    </script>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"Successfully generated HTML report at: {os.path.abspath(output_path)}")

if __name__ == "__main__":
    semgrep_json = "semgrep.json"
    pip_audit_json = "pip-audit.json"
    output_html = "security_report.html"

    if len(sys.argv) > 1:
        semgrep_json = sys.argv[1]
    if len(sys.argv) > 2:
        pip_audit_json = sys.argv[2]
    if len(sys.argv) > 3:
        output_html = sys.argv[3]

    semgrep_data = load_json(semgrep_json)
    pip_audit_data = load_json(pip_audit_json)

    generate_html(semgrep_data, pip_audit_data, output_html)
