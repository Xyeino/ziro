---
name: bandit
description: Bandit Python security linter — static analysis to find common security issues in Python source code.
---

# Bandit CLI Playbook

Official docs:
- https://bandit.readthedocs.io/
- https://github.com/PyCQA/bandit

Canonical syntax:
`bandit [options] <target>`

High-signal flags:
- `-r <path>` recursively scan a directory
- `-f json|csv|html|xml|yaml|screen|custom` output format
- `-o <file>` output file path
- `-ll` only report issues with medium confidence or higher
- `-lll` only report issues with high confidence
- `--severity-level low|medium|high` minimum severity to report (alias: `-l`, `-ll`, `-lll`)
- `-x <paths>` comma-separated directories to exclude
- `-s <tests>` comma-separated test IDs to skip (e.g., `B101,B601`)
- `-t <tests>` comma-separated test IDs to run (only these)
- `-c <config>` path to configuration file (.bandit)
- `-n <number>` number of lines of context to show
- `--ini <file>` path to .bandit INI config
- `-a file|vuln` aggregate results by file or vulnerability type
- `-q` quiet mode (only show results, no progress)
- `-v` verbose output
- `--exit-zero` always exit with code 0 (useful for advisory-only scans)
- `-p <profile>` use a specific test profile (deprecated, use `-t`/`-s`)

Agent-safe baseline for automation:
`bandit -r /path/to/project -f json -o /tmp/bandit_results.json -ll -x tests,venv,.tox -q`

Common patterns:
- Scan a Python project recursively:
  `bandit -r /path/to/project -f json -o /tmp/bandit_all.json`
- Scan with medium+ confidence filter:
  `bandit -r /path/to/project -ll -f json -o /tmp/bandit_medium.json`
- Scan with high severity and high confidence only:
  `bandit -r /path/to/project -lll --severity-level high -f json -o /tmp/bandit_critical.json`
- Exclude test directories and virtual environments:
  `bandit -r /path/to/project -x tests,venv,.tox,node_modules -f json -o /tmp/bandit_filtered.json`
- Run only specific checks (e.g., SQL injection, shell injection):
  `bandit -r /path/to/project -t B608,B602,B603,B604 -f json -o /tmp/bandit_injection.json`
- Skip specific noisy checks:
  `bandit -r /path/to/project -s B101,B311 -f json -o /tmp/bandit_clean.json`
  (B101 = assert usage, B311 = random for crypto)
- CI pipeline gate:
  `bandit -r /path/to/project -ll --severity-level medium -f json -o /tmp/bandit_ci.json`
- HTML report for stakeholders:
  `bandit -r /path/to/project -ll -f html -o /tmp/bandit_report.html`
- Scan a single file:
  `bandit /path/to/file.py -f json -o /tmp/bandit_single.json`
- Show context lines around findings:
  `bandit -r /path/to/project -n 5 -ll`
- Aggregate by vulnerability type:
  `bandit -r /path/to/project -a vuln -f screen`

Common test IDs:
- `B101` assert used (test code leaking into prod)
- `B102` exec used
- `B103` set_bad_file_permissions
- `B105-B107` hardcoded passwords/secrets
- `B108` hardcoded tmp directory
- `B301-B303` pickle, marshal, insecure deserialization
- `B501-B504` insecure TLS/SSL settings
- `B601-B610` shell injection, SQL injection, code injection
- `B608` SQL injection via string formatting

Sandbox safety:
- Always use `-r` with a specific project directory; do not scan `/` or broad paths.
- Use `-x` to exclude test directories, virtual environments, and vendored code.
- Use `-ll` to filter low-confidence noise.
- Use `-q` in automated pipelines to suppress progress output.
- Prefer `-f json` for machine-parseable results.
- For large codebases, scope scans with `-t` to specific test categories.

Failure recovery:
- If scan is slow on large repos, exclude vendored/generated code with `-x`.
- If too many false positives, raise confidence with `-ll`/`-lll` or skip noisy tests with `-s`.
- If a test ID is unknown, run `bandit --tests --help` or check docs for valid IDs.
- If config file errors, validate the YAML/INI syntax in the config.
