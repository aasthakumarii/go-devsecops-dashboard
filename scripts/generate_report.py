import html
import json
import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any


# ---------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------

def read_text(path: Path | None) -> str:
    if path is None or not path.exists():
        return "No log file available."

    return path.read_text(
        encoding="utf-8",
        errors="replace",
    )


def read_json(path: Path | None) -> Any:
    if path is None or not path.exists():
        return None

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        )
    except (json.JSONDecodeError, OSError):
        return None


def safe_status(value: str | None) -> str:
    if not value:
        return "unknown"

    return value.lower()


def status_class(status: str) -> str:
    normalized = status.lower()

    if normalized == "success":
        return "pass"

    if normalized in {"failure", "cancelled"}:
        return "fail"

    if normalized == "skipped":
        return "skip"

    return "unknown"


def find_first(
    root: Path,
    filename: str,
) -> Path | None:
    matches = list(root.rglob(filename))

    if not matches:
        return None

    return matches[0]


def normalize_severity(value: str | None) -> str:
    if not value:
        return "info"

    value = value.lower().strip()

    if "critical" in value:
        return "critical"

    if "high" in value:
        return "high"

    if "medium" in value:
        return "medium"

    if "low" in value:
        return "low"

    if "info" in value:
        return "info"

    return "info"


def copy_evidence(
    source: Path | None,
    destination_dir: Path,
    destination_name: str | None = None,
) -> str | None:
    if source is None or not source.exists():
        return None

    destination_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    filename = destination_name or source.name
    destination = destination_dir / filename

    shutil.copy2(
        source,
        destination,
    )

    return filename


# ---------------------------------------------------------
# Snyk parsing
# ---------------------------------------------------------

def extract_snyk_projects(data: Any) -> list[dict]:
    if data is None:
        return []

    if isinstance(data, list):
        return [
            item
            for item in data
            if isinstance(item, dict)
        ]

    if isinstance(data, dict):
        return [data]

    return []


def parse_snyk_findings(data: Any) -> list[dict]:
    findings = []

    projects = extract_snyk_projects(data)

    for project in projects:
        vulnerabilities = project.get(
            "vulnerabilities",
            [],
        )

        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            fixed_in = vulnerability.get(
                "fixedIn",
                [],
            )

            if isinstance(fixed_in, list):
                fixed_in_text = ", ".join(
                    str(item)
                    for item in fixed_in
                )
            else:
                fixed_in_text = str(
                    fixed_in or ""
                )

            from_path = vulnerability.get(
                "from",
                [],
            )

            if isinstance(from_path, list):
                dependency_path = " → ".join(
                    str(item)
                    for item in from_path
                )
            else:
                dependency_path = str(
                    from_path or ""
                )

            findings.append(
                {
                    "severity": normalize_severity(
                        vulnerability.get(
                            "severity"
                        )
                    ),
                    "title": vulnerability.get(
                        "title",
                        "Unknown vulnerability",
                    ),
                    "package": vulnerability.get(
                        "packageName",
                        vulnerability.get(
                            "name",
                            "Unknown",
                        ),
                    ),
                    "version": vulnerability.get(
                        "version",
                        "N/A",
                    ),
                    "fixed_in": (
                        fixed_in_text
                        if fixed_in_text
                        else "No fix listed"
                    ),
                    "id": vulnerability.get(
                        "id",
                        "",
                    ),
                    "dependency_path": dependency_path,
                }
            )

    return findings


# ---------------------------------------------------------
# OWASP ZAP parsing
# ---------------------------------------------------------

def parse_zap_findings(data: Any) -> list[dict]:
    findings = []

    if not isinstance(data, dict):
        return findings

    sites = data.get(
        "site",
        [],
    )

    if isinstance(sites, dict):
        sites = [sites]

    if not isinstance(sites, list):
        return findings

    for site in sites:
        if not isinstance(site, dict):
            continue

        alerts = site.get(
            "alerts",
            [],
        )

        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            risk = normalize_severity(
                alert.get(
                    "riskdesc",
                    alert.get(
                        "risk",
                        "info",
                    ),
                )
            )

            instances = alert.get(
                "instances",
                [],
            )

            if isinstance(instances, dict):
                instances = [instances]

            urls = []

            if isinstance(instances, list):
                for instance in instances:
                    if not isinstance(
                        instance,
                        dict,
                    ):
                        continue

                    uri = instance.get(
                        "uri",
                        "",
                    )

                    if (
                        uri
                        and uri not in urls
                    ):
                        urls.append(uri)

            findings.append(
                {
                    "severity": risk,
                    "title": alert.get(
                        "alert",
                        alert.get(
                            "name",
                            "Unknown alert",
                        ),
                    ),
                    "urls": urls,
                    "description": alert.get(
                        "desc",
                        "",
                    ),
                    "solution": alert.get(
                        "solution",
                        "",
                    ),
                    "reference": alert.get(
                        "reference",
                        "",
                    ),
                }
            )

    return findings


# ---------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------

def severity_badge(
    severity: str,
) -> str:
    severity = normalize_severity(
        severity
    )

    return f"""
    <span class="severity severity-{severity}">
        {html.escape(severity.upper())}
    </span>
    """


def make_log_section(
    title: str,
    path: Path | None,
) -> str:
    escaped = html.escape(
        read_text(path)
    )

    return f"""
    <section class="panel">
        <h2>{html.escape(title)}</h2>

        <details>
            <summary>View raw log</summary>

            <pre>{escaped}</pre>
        </details>
    </section>
    """


def render_snyk_table(
    findings: list[dict],
) -> str:
    if not findings:
        return """
        <div class="empty-state success-message">
            No vulnerable dependencies were reported by Snyk.
        </div>
        """

    rows = []

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    findings = sorted(
        findings,
        key=lambda item: severity_order.get(
            item["severity"],
            99,
        ),
    )

    for finding in findings:
        rows.append(
            f"""
            <tr>
                <td>
                    {severity_badge(
                        finding["severity"]
                    )}
                </td>

                <td>
                    <strong>
                        {html.escape(
                            str(
                                finding["title"]
                            )
                        )}
                    </strong>

                    <div class="muted small">
                        {html.escape(
                            str(
                                finding["id"]
                            )
                        )}
                    </div>
                </td>

                <td>
                    {html.escape(
                        str(
                            finding["package"]
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            finding["version"]
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            finding["fixed_in"]
                        )
                    )}
                </td>
            </tr>
            """
        )

    return f"""
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Vulnerability</th>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Fixed In</th>
                </tr>
            </thead>

            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


def render_zap_table(
    findings: list[dict],
) -> str:
    if not findings:
        return """
        <div class="empty-state success-message">
            OWASP ZAP reported no alerts.
        </div>
        """

    rows = []

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    findings = sorted(
        findings,
        key=lambda item: severity_order.get(
            item["severity"],
            99,
        ),
    )

    for finding in findings:
        urls = finding.get(
            "urls",
            [],
        )

        if urls:
            url_html = "<br>".join(
                html.escape(url)
                for url in urls[:5]
            )

            if len(urls) > 5:
                url_html += (
                    f"<br>+{len(urls) - 5} more"
                )
        else:
            url_html = "N/A"

        description = str(
            finding.get(
                "description",
                "",
            )
        )

        solution = str(
            finding.get(
                "solution",
                "",
            )
        )

        rows.append(
            f"""
            <tr>
                <td>
                    {severity_badge(
                        finding["severity"]
                    )}
                </td>

                <td>
                    <strong>
                        {html.escape(
                            str(
                                finding["title"]
                            )
                        )}
                    </strong>

                    {
                        (
                            '<details class="finding-details">'
                            '<summary>Details</summary>'
                            f'<p>{html.escape(description)}</p>'
                            f'<p><strong>Recommended fix:</strong> '
                            f'{html.escape(solution)}</p>'
                            '</details>'
                        )
                        if description or solution
                        else ""
                    }
                </td>

                <td class="url-cell">
                    {url_html}
                </td>
            </tr>
            """
        )

    return f"""
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th>Risk</th>
                    <th>Alert</th>
                    <th>Affected URL</th>
                </tr>
            </thead>

            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
    """


# ---------------------------------------------------------
# Main report generation
# ---------------------------------------------------------

def main() -> None:
    run_id = os.environ[
        "GITHUB_RUN_ID"
    ]

    output_root = Path(
        "site"
    )

    report_root = (
        output_root
        / "reports"
        / f"run-{run_id}"
    )

    evidence_root = (
        report_root
        / "evidence"
    )

    output_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    evidence_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    artifacts_root = Path(
        "collected-artifacts"
    )

    statuses = {
        "Build": safe_status(
            os.getenv(
                "BUILD_STATUS"
            )
        ),
        "Unit Tests": safe_status(
            os.getenv(
                "UNIT_TEST_STATUS"
            )
        ),
        "SonarCloud": safe_status(
            os.getenv(
                "SONAR_STATUS"
            )
        ),
        "Snyk Security": safe_status(
            os.getenv(
                "SNYK_STATUS"
            )
        ),
        "Deployment": safe_status(
            os.getenv(
                "DEPLOY_STATUS"
            )
        ),
        "OWASP ZAP": safe_status(
            os.getenv(
                "ZAP_STATUS"
            )
        ),
    }

    # -----------------------------------------------------
    # Discover artifacts
    # -----------------------------------------------------

    coverage_file = find_first(
        artifacts_root,
        "coverage.txt",
    )

    unit_test_log = find_first(
        artifacts_root,
        "unit-tests.log",
    )

    sonar_log = find_first(
        artifacts_root,
        "go-test.log",
    )

    snyk_json_file = find_first(
        artifacts_root,
        "snyk-results.json",
    )

    snyk_log = find_first(
        artifacts_root,
        "snyk-results.txt",
    )

    zap_json_file = find_first(
        artifacts_root,
        "zap-report.json",
    )

    zap_html_file = find_first(
        artifacts_root,
        "zap-report.html",
    )

    zap_markdown_file = find_first(
        artifacts_root,
        "zap-report.md",
    )

    zap_log = find_first(
        artifacts_root,
        "zap.log",
    )

    # -----------------------------------------------------
    # Coverage
    # -----------------------------------------------------

    coverage = "N/A"

    if coverage_file:
        coverage_text = read_text(
            coverage_file
        )

        for line in coverage_text.splitlines():
            if line.strip().startswith(
                "total:"
            ):
                parts = line.split()

                if parts:
                    coverage = parts[-1]

                break

    # -----------------------------------------------------
    # Parse scanner results
    # -----------------------------------------------------

    snyk_data = read_json(
        snyk_json_file
    )

    zap_data = read_json(
        zap_json_file
    )

    snyk_findings = parse_snyk_findings(
        snyk_data
    )

    zap_findings = parse_zap_findings(
        zap_data
    )

    all_findings = (
        snyk_findings
        + zap_findings
    )

    severity_counts = Counter(
        finding["severity"]
        for finding in all_findings
    )

    # -----------------------------------------------------
    # Copy evidence to published report
    # -----------------------------------------------------

    evidence_links = []

    evidence_files = [
        (
            snyk_json_file,
            "snyk-results.json",
            "Download Snyk JSON",
        ),
        (
            snyk_log,
            "snyk-results.txt",
            "View Snyk Raw Log",
        ),
        (
            zap_json_file,
            "zap-report.json",
            "Download ZAP JSON",
        ),
        (
            zap_markdown_file,
            "zap-report.md",
            "View ZAP Markdown Report",
        ),
        (
            zap_log,
            "zap.log",
            "View ZAP Raw Log",
        ),
        (
            unit_test_log,
            "unit-tests.log",
            "View Unit Test Log",
        ),
        (
            sonar_log,
            "sonar-go-test.log",
            "View Sonar Coverage Log",
        ),
    ]

    for (
        source,
        destination_name,
        label,
    ) in evidence_files:
        copied = copy_evidence(
            source,
            evidence_root,
            destination_name,
        )

        if copied:
            evidence_links.append(
                f"""
                <a
                    class="button"
                    href="evidence/{html.escape(copied)}"
                >
                    {html.escape(label)}
                </a>
                """
            )

    if zap_html_file:
        copy_evidence(
            zap_html_file,
            report_root,
            "zap-report.html",
        )

        evidence_links.insert(
            0,
            """
            <a
                class="button primary"
                href="zap-report.html"
            >
                View Full ZAP HTML Report
            </a>
            """,
        )

    # -----------------------------------------------------
    # Pipeline rows
    # -----------------------------------------------------

    pipeline_rows = []

    for stage, status in statuses.items():
        pipeline_rows.append(
            f"""
            <tr>
                <td>
                    <strong>
                        {html.escape(stage)}
                    </strong>
                </td>

                <td>
                    <span
                        class="status {status_class(status)}"
                    >
                        {html.escape(
                            status.upper()
                        )}
                    </span>
                </td>
            </tr>
            """
        )

    # -----------------------------------------------------
    # Overall status
    # -----------------------------------------------------

    overall = "success"

    if any(
        status in {
            "failure",
            "cancelled",
        }
        for status in statuses.values()
    ):
        overall = "failure"

    elif any(
        status == "unknown"
        for status in statuses.values()
    ):
        overall = "unknown"

    # -----------------------------------------------------
    # Metadata
    # -----------------------------------------------------

    metadata = {
        "repository": os.getenv(
            "GITHUB_REPOSITORY",
            "",
        ),
        "run_id": run_id,
        "run_number": os.getenv(
            "GITHUB_RUN_NUMBER",
            "",
        ),
        "sha": os.getenv(
            "GITHUB_SHA",
            "",
        ),
        "branch": os.getenv(
            "GITHUB_REF_NAME",
            "",
        ),
        "event": os.getenv(
            "GITHUB_EVENT_NAME",
            "",
        ),
        "coverage": coverage,
        "overall": overall,
        "statuses": statuses,
        "security_counts": dict(
            severity_counts
        ),
        "snyk_findings": len(
            snyk_findings
        ),
        "zap_findings": len(
            zap_findings
        ),
    }

    (
        report_root
        / "metadata.json"
    ).write_text(
        json.dumps(
            metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    # -----------------------------------------------------
    # HTML
    # -----------------------------------------------------

    html_content = f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    DevSecOps Security Report
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    background: #0b1120;
    color: #e2e8f0;
    font-family:
        Inter,
        Arial,
        Helvetica,
        sans-serif;
    margin: 0;
}}

.page {{
    margin: auto;
    max-width: 1400px;
    padding: 40px 30px 80px;
}}

.hero {{
    background:
        linear-gradient(
            135deg,
            #111827,
            #1e293b
        );
    border: 1px solid #334155;
    border-radius: 18px;
    margin-bottom: 28px;
    padding: 36px;
}}

.hero h1 {{
    font-size: 34px;
    margin: 0 0 12px;
}}

.hero p {{
    color: #94a3b8;
}}

.metadata {{
    color: #94a3b8;
    display: grid;
    gap: 8px;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(220px, 1fr)
        );
    margin-top: 25px;
}}

.grid {{
    display: grid;
    gap: 18px;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(160px, 1fr)
        );
    margin-bottom: 28px;
}}

.metric {{
    background: #111827;
    border: 1px solid #334155;
    border-radius: 15px;
    padding: 22px;
}}

.metric-title {{
    color: #94a3b8;
    font-size: 13px;
    margin-bottom: 10px;
    text-transform: uppercase;
}}

.metric-value {{
    font-size: 30px;
    font-weight: 700;
}}

.critical-value {{
    color: #f87171;
}}

.high-value {{
    color: #fb7185;
}}

.medium-value {{
    color: #fbbf24;
}}

.low-value {{
    color: #60a5fa;
}}

.info-value {{
    color: #94a3b8;
}}

.panel {{
    background: #111827;
    border: 1px solid #334155;
    border-radius: 16px;
    margin-bottom: 24px;
    padding: 28px;
}}

.panel h2 {{
    margin-top: 0;
}}

.table-wrapper {{
    overflow-x: auto;
}}

table {{
    border-collapse: collapse;
    width: 100%;
}}

th,
td {{
    border-bottom: 1px solid #334155;
    padding: 15px;
    text-align: left;
    vertical-align: top;
}}

th {{
    color: #94a3b8;
    font-size: 13px;
    text-transform: uppercase;
}}

.status,
.severity {{
    border-radius: 20px;
    display: inline-block;
    font-size: 12px;
    font-weight: 700;
    padding: 6px 11px;
}}

.pass {{
    background: #14532d;
    color: #86efac;
}}

.fail {{
    background: #7f1d1d;
    color: #fecaca;
}}

.skip {{
    background: #374151;
    color: #d1d5db;
}}

.unknown {{
    background: #78350f;
    color: #fde68a;
}}

.severity-critical {{
    background: #7f1d1d;
    color: #fecaca;
}}

.severity-high {{
    background: #881337;
    color: #fecdd3;
}}

.severity-medium {{
    background: #78350f;
    color: #fde68a;
}}

.severity-low {{
    background: #1e3a8a;
    color: #bfdbfe;
}}

.severity-info {{
    background: #334155;
    color: #cbd5e1;
}}

.button {{
    background: #1e293b;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #e2e8f0;
    display: inline-block;
    margin:
        0
        8px
        10px
        0;
    padding: 10px 14px;
    text-decoration: none;
}}

.button:hover {{
    background: #334155;
}}

.button.primary {{
    background: #1d4ed8;
    border-color: #3b82f6;
}}

pre {{
    background: #020617;
    border-radius: 10px;
    color: #cbd5e1;
    max-height: 500px;
    overflow: auto;
    padding: 20px;
    white-space: pre-wrap;
}}

summary {{
    cursor: pointer;
    font-weight: 600;
    margin: 10px 0;
}}

.muted {{
    color: #94a3b8;
}}

.small {{
    font-size: 12px;
    margin-top: 6px;
}}

.url-cell {{
    max-width: 420px;
    overflow-wrap: anywhere;
}}

.empty-state {{
    border-radius: 10px;
    padding: 18px;
}}

.success-message {{
    background: #052e16;
    border: 1px solid #166534;
    color: #86efac;
}}

.section-heading {{
    align-items: center;
    display: flex;
    justify-content: space-between;
}}

.count {{
    color: #94a3b8;
    font-size: 14px;
}}

.finding-details {{
    margin-top: 8px;
}}

.finding-details p {{
    color: #cbd5e1;
    line-height: 1.5;
}}

</style>

</head>

<body>

<div class="page">

<section class="hero">

    <h1>
        DevSecOps Security Report
    </h1>

    <p>
        Consolidated CI/CD,
        static analysis,
        dependency security,
        dynamic security,
        deployment,
        and testing evidence.
    </p>

    <p>
        Overall:
        <span
            class="status {status_class(overall)}"
        >
            {overall.upper()}
        </span>
    </p>

    <div class="metadata">

        <div>
            <strong>Repository</strong><br>
            {html.escape(
                metadata["repository"]
            )}
        </div>

        <div>
            <strong>Pipeline Run</strong><br>
            #{html.escape(
                metadata["run_number"]
            )}
        </div>

        <div>
            <strong>Branch</strong><br>
            {html.escape(
                metadata["branch"]
            )}
        </div>

        <div>
            <strong>Commit</strong><br>
            {html.escape(
                metadata["sha"][:12]
            )}
        </div>

    </div>

</section>


<div class="grid">

    <div class="metric">
        <div class="metric-title">
            Critical
        </div>

        <div class="metric-value critical-value">
            {severity_counts.get(
                "critical",
                0
            )}
        </div>
    </div>

    <div class="metric">
        <div class="metric-title">
            High
        </div>

        <div class="metric-value high-value">
            {severity_counts.get(
                "high",
                0
            )}
        </div>
    </div>

    <div class="metric">
        <div class="metric-title">
            Medium
        </div>

        <div class="metric-value medium-value">
            {severity_counts.get(
                "medium",
                0
            )}
        </div>
    </div>

    <div class="metric">
        <div class="metric-title">
            Low
        </div>

        <div class="metric-value low-value">
            {severity_counts.get(
                "low",
                0
            )}
        </div>
    </div>

    <div class="metric">
        <div class="metric-title">
            Informational
        </div>

        <div class="metric-value info-value">
            {severity_counts.get(
                "info",
                0
            )}
        </div>
    </div>

    <div class="metric">
        <div class="metric-title">
            Test Coverage
        </div>

        <div class="metric-value">
            {html.escape(coverage)}
        </div>
    </div>

</div>


<section class="panel">

    <h2>
        Pipeline Status
    </h2>

    <div class="table-wrapper">

        <table>

            <thead>
                <tr>
                    <th>Stage</th>
                    <th>Status</th>
                </tr>
            </thead>

            <tbody>
                {"".join(
                    pipeline_rows
                )}
            </tbody>

        </table>

    </div>

</section>


<section class="panel">

    <div class="section-heading">

        <h2>
            Snyk Open Source Findings
        </h2>

        <span class="count">
            {len(snyk_findings)}
            finding(s)
        </span>

    </div>

    {render_snyk_table(
        snyk_findings
    )}

</section>


<section class="panel">

    <div class="section-heading">

        <h2>
            OWASP ZAP Findings
        </h2>

        <span class="count">
            {len(zap_findings)}
            finding(s)
        </span>

    </div>

    {render_zap_table(
        zap_findings
    )}

</section>


<section class="panel">

    <h2>
        Detailed Evidence
    </h2>

    {
        "".join(
            evidence_links
        )
        if evidence_links
        else (
            "<p>"
            "No downloadable evidence "
            "was found for this run."
            "</p>"
        )
    }

</section>


{make_log_section(
    "Unit Test Raw Log",
    unit_test_log,
)}

{make_log_section(
    "SonarCloud Coverage Log",
    sonar_log,
)}

{make_log_section(
    "Snyk Raw Security Log",
    snyk_log,
)}

{make_log_section(
    "OWASP ZAP Raw Log",
    zap_log,
)}

</div>

</body>

</html>
"""

    run_index = (
        report_root
        / "index.html"
    )

    run_index.write_text(
        html_content,
        encoding="utf-8",
    )

    # Root page redirects to current run.
    root_index = (
        output_root
        / "index.html"
    )

    root_index.write_text(
        f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    http-equiv="refresh"
    content="0; url=reports/run-{run_id}/index.html"
>

<title>
    DevSecOps Security Report
</title>

</head>

<body>

<a
    href="reports/run-{run_id}/index.html"
>
    Open latest DevSecOps security report
</a>

</body>

</html>
""",
        encoding="utf-8",
    )

    print(
        f"Generated security report: "
        f"{run_index}"
    )

    print(
        "Snyk findings:",
        len(snyk_findings),
    )

    print(
        "ZAP findings:",
        len(zap_findings),
    )

    print(
        "Severity counts:",
        dict(severity_counts),
    )


if __name__ == "__main__":
    main()