---
name: trivy
description: Trivy container/filesystem vulnerability scanner — image scanning, SBOM generation, secret detection, and IaC misconfiguration checks.
---

# Trivy CLI Playbook

Official docs:
- https://aquasecurity.github.io/trivy/
- https://github.com/aquasecurity/trivy

Canonical syntax:
`trivy <subcommand> [options] <target>`

High-signal flags:
- `trivy image <image>` scan a container image
- `trivy fs <path>` scan a local filesystem/project directory
- `trivy repo <url>` scan a remote git repository
- `trivy sbom <path>` scan an SBOM file
- `trivy config <path>` scan IaC files for misconfigurations
- `--severity CRITICAL,HIGH` filter by severity level
- `--format table|json|sarif|cyclonedx|spdx` output format
- `--output <file>` write results to a file
- `--exit-code <n>` exit with code N if vulnerabilities found (useful in CI)
- `--ignore-unfixed` hide vulnerabilities with no available fix
- `--skip-db-update` skip vulnerability DB update (use cached/offline DB)
- `--timeout <duration>` scan timeout (e.g., `10m`)
- `--scanners vuln,secret,misconfig` choose what to scan for
- `--list-all-pkgs` include all packages in output (not just vulnerable)
- `--db-repository <url>` custom DB mirror location
- `--cache-dir <path>` custom cache directory
- `--quiet` suppress progress output

Agent-safe baseline for automation:
`trivy image --severity CRITICAL,HIGH --ignore-unfixed --timeout 10m --format json --output /tmp/trivy_report.json <image>`

Common patterns:
- Scan container image for critical vulns:
  `trivy image --severity CRITICAL,HIGH --ignore-unfixed alpine:3.18`
- Scan local project for vulnerabilities and secrets:
  `trivy fs --scanners vuln,secret --severity CRITICAL,HIGH --format json --output /tmp/fs_scan.json .`
- Scan remote repository:
  `trivy repo --severity CRITICAL,HIGH --format table https://github.com/org/repo`
- Generate CycloneDX SBOM:
  `trivy image --format cyclonedx --output /tmp/sbom.json myapp:latest`
- IaC misconfiguration check (Terraform, Dockerfile, K8s):
  `trivy config --severity CRITICAL,HIGH --format json --output /tmp/iac_scan.json ./infra/`
- Secret detection in filesystem:
  `trivy fs --scanners secret --format json --output /tmp/secrets.json .`
- CI pipeline gate (fail on CRITICAL):
  `trivy image --severity CRITICAL --exit-code 1 --ignore-unfixed --quiet myapp:latest`
- Offline scan (skip DB download):
  `trivy image --skip-db-update --severity CRITICAL,HIGH myapp:latest`
- Scan with SARIF output for GitHub integration:
  `trivy image --format sarif --output /tmp/trivy.sarif myapp:latest`

Sandbox safety:
- Always set `--timeout` to prevent unbounded scans (5-15 minutes is reasonable).
- Use `--skip-db-update` in air-gapped or repeated scans to avoid network calls.
- Use `--severity CRITICAL,HIGH` to reduce noise in output.
- Prefer `--ignore-unfixed` to focus on actionable vulnerabilities.
- Set `--cache-dir` to a controlled location to manage disk usage.
- Use `--quiet` to suppress progress bars in automated pipelines.

Failure recovery:
- If DB download fails, use `--skip-db-update` with a pre-cached DB or set `--db-repository` to a mirror.
- If image pull fails, ensure Docker daemon is running or pre-pull the image.
- If scan times out, increase `--timeout` or narrow scope with `--scanners`.
