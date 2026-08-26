import html
import json
import os
from pathlib import Path


def read_text(path: Path) -> str:
    if not path.exists():
        return "No log file available."

    return path.read_text(encoding="utf-8", errors="replace")


def status_class(status: str) -> str:
    normalized = status.lower()

    if normalized == "success":
        return "pass"

    if normalized == "failure":
        return "fail"

    if normalized == "skipped":
        return "skip"

    if normalized == "cancelled":
        return "fail"

    return "unknown"


def safe_status(value: str | None) -> str:
    if not value:
        return "unknown"

    return value.lower()


def find_first(root: Path, filename: str) -> Path | None:
    matches = list(root.rglob(filename))

    if not matches:
        return None

    return matches[0]


def make_log_section(
    title: str,
    path: Path | None,
) -> str:
    if path is None:
        content = "No report/log available."
    else:
        content = read_text(path)

    escaped = html.escape(content)

    return f"""
    <section class="log-section">
        <h3>{html.escape(title)}</h3>

        <details>
            <summary>View log</summary>

            <pre>{escaped}</pre>
        </details>
    </section>
    """


def main() -> None:
    output_root = Path("site")
    report_root = output_root / "reports" / f"run-{os.environ['GITHUB_RUN_ID']}"

    output_root.mkdir(parents=True, exist_ok=True)
    report_root.mkdir(parents=True, exist_ok=True)

    artifacts_root = Path("collected-artifacts")

    statuses = {
        "Build": safe_status(os.getenv("BUILD_STATUS")),
        "Unit Tests": safe_status(os.getenv("UNIT_TEST_STATUS")),
        "SonarCloud": safe_status(os.getenv("SONAR_STATUS")),
        "Snyk Security": safe_status(os.getenv("SNYK_STATUS")),
        "Deployment": safe_status(os.getenv("DEPLOY_STATUS")),
        "OWASP ZAP": safe_status(os.getenv("ZAP_STATUS")),
    }

    coverage = "N/A"

    coverage_file = find_first(
        artifacts_root,
        "coverage.txt",
    )

    if coverage_file:
        coverage_text = read_text(coverage_file)

        for line in coverage_text.splitlines():
            if line.strip().startswith("total:"):
                parts = line.split()

                if parts:
                    coverage = parts[-1]

                break

    unit_test_log = find_first(
        artifacts_root,
        "unit-tests.log",
    )

    snyk_log = find_first(
        artifacts_root,
        "snyk-results.txt",
    )

    zap_log = find_first(
        artifacts_root,
        "zap.log",
    )

    zap_html = find_first(
        artifacts_root,
        "zap-report.html",
    )

    sonar_log = find_first(
        artifacts_root,
        "go-test.log",
    )

    rows = ""

    for stage, status in statuses.items():
        css_class = status_class(status)

        rows += f"""
        <tr>
            <td>{html.escape(stage)}</td>
            <td>
                <span class="status {css_class}">
                    {html.escape(status.upper())}
                </span>
            </td>
        </tr>
        """

    overall = "success"

    if any(
        status in {"failure", "cancelled"}
        for status in statuses.values()
    ):
        overall = "failure"

    elif any(
        status == "unknown"
        for status in statuses.values()
    ):
        overall = "unknown"

    links = []

    if zap_html:
        destination = report_root / "zap-report.html"
        destination.write_bytes(zap_html.read_bytes())

        links.append(
            '<a href="zap-report.html">View OWASP ZAP HTML Report</a>'
        )

    metadata = {
        "repository": os.getenv("GITHUB_REPOSITORY", ""),
        "run_id": os.getenv("GITHUB_RUN_ID", ""),
        "run_number": os.getenv("GITHUB_RUN_NUMBER", ""),
        "sha": os.getenv("GITHUB_SHA", ""),
        "ref": os.getenv("GITHUB_REF_NAME", ""),
        "event": os.getenv("GITHUB_EVENT_NAME", ""),
        "coverage": coverage,
        "overall": overall,
        "statuses": statuses,
    }

    metadata_file = report_root / "metadata.json"

    metadata_file.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>DevSecOps Pipeline Report</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            background: #0f172a;
            color: #e2e8f0;
            font-family: Arial, Helvetica, sans-serif;
            margin: 0;
            padding: 40px;
        }}

        .container {{
            margin: auto;
            max-width: 1100px;
        }}

        .header {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 16px;
            margin-bottom: 24px;
            padding: 32px;
        }}

        h1 {{
            margin-top: 0;
        }}

        .metadata {{
            color: #94a3b8;
            line-height: 1.8;
        }}

        .summary-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 16px;
            margin-bottom: 24px;
            padding: 28px;
        }}

        table {{
            border-collapse: collapse;
            width: 100%;
        }}

        th,
        td {{
            border-bottom: 1px solid #334155;
            padding: 14px;
            text-align: left;
        }}

        th {{
            color: #94a3b8;
        }}

        .status {{
            border-radius: 20px;
            display: inline-block;
            font-size: 13px;
            font-weight: bold;
            padding: 7px 12px;
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

        .log-section {{
            background: #111827;
            border: 1px solid #334155;
            border-radius: 14px;
            margin-bottom: 18px;
            padding: 22px;
        }}

        details {{
            margin-top: 12px;
        }}

        summary {{
            cursor: pointer;
            font-weight: bold;
        }}

        pre {{
            background: #020617;
            border-radius: 8px;
            color: #cbd5e1;
            max-height: 500px;
            overflow: auto;
            padding: 18px;
            white-space: pre-wrap;
        }}

        a {{
            color: #60a5fa;
        }}

        .overall {{
            font-size: 22px;
            font-weight: bold;
        }}
    </style>
</head>

<body>

<div class="container">

    <section class="header">

        <h1>DevSecOps Pipeline Report</h1>

        <p class="overall">
            Overall:
            <span class="status {status_class(overall)}">
                {overall.upper()}
            </span>
        </p>

        <div class="metadata">

            Repository:
            {html.escape(metadata["repository"])}
            <br>

            Run:
            #{html.escape(metadata["run_number"])}
            <br>

            Run ID:
            {html.escape(metadata["run_id"])}
            <br>

            Branch:
            {html.escape(metadata["ref"])}
            <br>

            Event:
            {html.escape(metadata["event"])}
            <br>

            Commit:
            {html.escape(metadata["sha"])}

        </div>

    </section>


    <section class="summary-card">

        <h2>Pipeline Summary</h2>

        <table>

            <thead>
                <tr>
                    <th>Stage</th>
                    <th>Status</th>
                </tr>
            </thead>

            <tbody>
                {rows}
            </tbody>

        </table>

        <p>
            <strong>Go Test Coverage:</strong>
            {html.escape(coverage)}
        </p>

    </section>


    <section class="summary-card">

        <h2>Detailed Reports</h2>

        {"<br><br>".join(links) if links else "No standalone HTML reports found."}

    </section>


    {make_log_section("Unit Test Log", unit_test_log)}

    {make_log_section("SonarCloud Test/Coverage Log", sonar_log)}

    {make_log_section("Snyk Security Log", snyk_log)}

    {make_log_section("OWASP ZAP Log", zap_log)}

</div>

</body>
</html>
"""

    run_index = report_root / "index.html"

    run_index.write_text(
        html_content,
        encoding="utf-8",
    )

    root_index = output_root / "index.html"

    root_index.write_text(
        f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">

    <meta
        http-equiv="refresh"
        content="0; url=reports/run-{os.environ['GITHUB_RUN_ID']}/index.html"
    >

    <title>DevSecOps Report</title>
</head>

<body>
    <a href="reports/run-{os.environ['GITHUB_RUN_ID']}/index.html">
        Open pipeline report
    </a>
</body>
</html>
""",
        encoding="utf-8",
    )

    print(f"Generated report: {run_index}")


if __name__ == "__main__":
    main()