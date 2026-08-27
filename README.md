# Go DevSecOps Dashboard

A complete DevSecOps demonstration project built with Go, GitHub Actions, SonarCloud, Snyk, OWASP ZAP, Docker, AWS EC2, and GitHub Pages.

This repository demonstrates a secure CI/CD workflow with reusable GitHub Actions, protected pull requests, static and dependency security scanning, EC2 deployment, dynamic application testing, downloadable artifacts, and a consolidated HTML security dashboard.

---

## Project Overview

The application is a lightweight Go web application with a visual frontend and health/status endpoints.

The main goal of this project is to demonstrate a production-style DevSecOps delivery flow where every code change is validated through build, testing, code quality, security scanning, review, deployment, dynamic security testing, and reporting.

Key features:

- Pull requests required before merge
- Two approving reviewers required
- Required CI checks before merge
- Go build and unit testing
- SonarCloud static analysis
- Snyk dependency/security scanning
- Docker containerization
- AWS EC2 deployment
- OWASP ZAP dynamic application security testing
- Downloadable GitHub Actions artifacts
- Consolidated HTML security report
- GitHub Pages publishing
- Reusable GitHub Actions workflows

---

## Architecture

```text
Developer
   |
   v
Feature Branch
   |
   v
Pull Request
   |
   +----------------------+
   |                      |
   v                      v
Build                 Unit Tests
   |                      |
   +----------+-----------+
              |
              v
         SonarCloud
              |
              v
         Snyk Security
              |
              v
        Required Checks
              |
              v
        2 PR Approvals
              |
              v
           Merge
              |
              v
            main
              |
              v
        Deploy to EC2
              |
              v
         OWASP ZAP
              |
              v
   Consolidated HTML Report
              |
              v
        GitHub Pages
```

---

## Technology Stack

| Area | Technology |
|---|---|
| Application | Go |
| Frontend | HTML / CSS |
| CI/CD | GitHub Actions |
| Unit Testing | Go test |
| Static Analysis | SonarCloud |
| Dependency Security | Snyk |
| DAST | OWASP ZAP |
| Containerization | Docker |
| Deployment | AWS EC2 |
| Security Reporting | Python |
| Report Hosting | GitHub Pages |
| Artifact Storage | GitHub Actions Artifacts |

---

## Application Endpoints

The application runs on port `8080`.

| Endpoint | Purpose |
|---|---|
| `/` | Main dashboard |
| `/health` | Health check |
| `/api/status` | Application status API |

Example:

```bash
curl http://localhost:8080/health
```

---

## Local Development

```bash
git clone https://github.com/aasthakumarii/go-devsecops-dashboard.git
cd go-devsecops-dashboard
go run .
```

Open:

```text
http://localhost:8080
```

Run tests:

```bash
go test ./...
```

Run tests with coverage:

```bash
go test ./... -cover
```

---

## Docker

Build the image:

```bash
docker build -t go-devsecops-dashboard .
```

Run the container:

```bash
docker run --rm -p 8080:8080 go-devsecops-dashboard
```

---

## CI/CD Workflows

```text
.github/workflows/
├── main-pipeline.yml
├── reusable-build.yml
├── reusable-unit-tests.yml
├── reusable-sonarcloud.yml
├── reusable-snyk.yml
├── reusable-deploy.yml
├── reusable-zap.yml
├── reusable-report.yml
└── reusable-pages.yml
```

`main-pipeline.yml` acts as the orchestrator.

### Pull Request Flow

```text
Build
   |
Unit Tests
   |
SonarCloud
   |
Snyk
   |
Consolidated Report
```

Deployment and OWASP ZAP are skipped during pull request validation.

### Main Branch Flow

```text
Build
   |
Unit Tests
   |
SonarCloud
   |
Snyk
   |
Deploy to EC2
   |
OWASP ZAP
   |
Consolidated Security Report
   |
GitHub Pages
```

---

## Branch Protection

The `main` branch is protected using GitHub repository rules.

Controls include:

- Pull request required before merge
- Two approving reviews required
- Required CI checks
- Successful build
- Successful unit tests
- Successful SonarCloud analysis
- Successful Snyk security scan

---

## SonarCloud

SonarCloud performs static code analysis and quality checks.

```properties
sonar.projectKey=aasthakumarii_go-devsecops-dashboard
sonar.organization=aasthakumarii
```

Checks include reliability, maintainability, security, code smells, new-code coverage, and security hotspots.

---

## Snyk Security Scanning

Snyk performs dependency and open-source vulnerability scanning.

Generated reports:

```text
snyk-results.json
snyk-results.txt
```

The consolidated dashboard parses the JSON result and can display:

- Severity
- Vulnerability name
- Package
- Installed version
- Fixed version

---

## OWASP ZAP Dynamic Testing

OWASP ZAP runs after deployment to test the live application.

```text
Deploy to EC2
     |
     v
Check /health
     |
     v
Run ZAP baseline scan
     |
     v
Generate security reports
```

Generated files:

```text
zap-report.html
zap-report.json
zap-report.md
zap.log
```

The dashboard parses ZAP findings and displays:

- Risk level
- Alert name
- Affected URL
- Description
- Recommended fix

---

## AWS EC2 Deployment

Deployment occurs only after changes are merged into `main`.

```text
Connect to EC2
     |
Update source
     |
Build Docker image
     |
Stop previous container
     |
Start new container
     |
Verify /health
```

Required GitHub secrets:

```text
EC2_HOST
EC2_USER
EC2_SSH_KEY
```

---

## Security Dashboard

The consolidated HTML report is generated by:

```text
scripts/generate_report.py
```

The dashboard contains:

- Overall pipeline status
- Critical findings
- High findings
- Medium findings
- Low findings
- Informational findings
- Test coverage
- Pipeline stage status
- Snyk findings
- OWASP ZAP findings
- Raw logs
- Downloadable security evidence

---

## GitHub Pages

The generated security dashboard is published to:

```text
https://aasthakumarii.github.io/go-devsecops-dashboard/
```

---

## Downloadable Artifacts

Pipeline runs can produce:

```text
Go build artifact
Unit test reports
Coverage reports
SonarCloud reports
Snyk reports
OWASP ZAP reports
Complete pipeline report
GitHub Pages artifact
```

The complete report artifact uses a name similar to:

```text
complete-pipeline-report-<run-id>
```

---

## Report Structure

```text
site/
├── index.html
└── reports/
    └── run-<RUN_ID>/
        ├── index.html
        ├── metadata.json
        ├── zap-report.html
        └── evidence/
            ├── snyk-results.json
            ├── snyk-results.txt
            ├── zap-report.json
            ├── zap-report.md
            ├── zap.log
            ├── unit-tests.log
            └── sonar-go-test.log
```

---

## GitHub Secrets

Configure repository secrets under:

```text
Repository
→ Settings
→ Secrets and variables
→ Actions
```

Required secrets:

```text
SONAR_TOKEN
SNYK_TOKEN
EC2_HOST
EC2_USER
EC2_SSH_KEY
```

---

## Security Controls

| Control | Implementation |
|---|---|
| Pull request enforcement | GitHub ruleset |
| Peer review | 2 approvals |
| Build validation | GitHub Actions |
| Unit testing | Go test |
| Static analysis | SonarCloud |
| Dependency scanning | Snyk |
| Dynamic testing | OWASP ZAP |
| Secret management | GitHub Secrets |
| Action integrity | Pinned GitHub Action SHAs |
| Containerized deployment | Docker |
| Deployment validation | `/health` check |
| Security evidence | GitHub Actions artifacts |
| Security dashboard | GitHub Pages |
| Pipeline concurrency | GitHub Actions concurrency |

---

## Pipeline Concurrency

```yaml
concurrency:
  group: devsecops-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

This automatically cancels outdated runs when newer commits are pushed to the same branch.

---

## Repository Structure

```text
go-devsecops-dashboard/
│
├── .github/
│   └── workflows/
│       ├── main-pipeline.yml
│       ├── reusable-build.yml
│       ├── reusable-unit-tests.yml
│       ├── reusable-sonarcloud.yml
│       ├── reusable-snyk.yml
│       ├── reusable-deploy.yml
│       ├── reusable-zap.yml
│       ├── reusable-report.yml
│       └── reusable-pages.yml
│
├── scripts/
│   └── generate_report.py
│
├── static/
│   └── style.css
│
├── templates/
│   └── index.html
│
├── Dockerfile
├── go.mod
├── main.go
├── main_test.go
├── sonar-project.properties
└── README.md
```

---

## End-to-End DevSecOps Flow

```text
CODE
 |
 v
PULL REQUEST
 |
 +-- Build
 |
 +-- Unit Tests
 |
 +-- SonarCloud
 |
 +-- Snyk
 |
 v
2 APPROVALS
 |
 v
MERGE TO MAIN
 |
 v
DOCKER BUILD
 |
 v
DEPLOY TO EC2
 |
 v
OWASP ZAP DAST
 |
 v
PARSE SECURITY RESULTS
 |
 v
GENERATE HTML DASHBOARD
 |
 +-------------------+
 |                   |
 v                   v
GitHub Artifact   GitHub Pages
```

---

## Project Goal

The goal of this repository is to demonstrate how security can be integrated throughout the software delivery lifecycle instead of being treated as a final manual step.

The pipeline continuously performs:

```text
Build
Test
Analyze
Scan
Review
Deploy
Dynamic Test
Report
```

This provides a practical example of a reusable, automated, auditable, and security-focused software delivery process.
