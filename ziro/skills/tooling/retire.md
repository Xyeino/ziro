---
name: retire
description: Retire.js vulnerability scanner — detect known vulnerabilities in JavaScript libraries and Node.js dependencies.
---

# Retire.js CLI Playbook

Official docs:
- https://retirejs.github.io/retire.js/
- https://github.com/RetireJS/retire.js

Canonical syntax:
`retire [options]`

High-signal flags:
- `--path <path>` scan a specific directory or file
- `--node` scan node_modules for vulnerable packages
- `--js` scan JavaScript files for vulnerable client-side libraries
- `--outputformat json|text|jsonsimple|cyclonedx` output format
- `--outputpath <file>` write output to a file
- `--severity low|medium|high|critical` minimum severity to report
- `--exitwith <code>` exit with this code if vulnerabilities found (CI mode)
- `--ignorefile <file>` path to .retireignore or .retireignore.json
- `--ignore <paths>` comma-separated paths to ignore
- `--verbose` show more detail in output
- `--proxy <url>` use an HTTP proxy for fetching vulnerability data
- `--cacert <file>` custom CA certificate bundle
- `--insecure` allow insecure connections when fetching repo data
- `--jspath <path>` scan only this path for JS files
- `--nodepath <path>` scan only this path for node dependencies
- `--nocache` do not use cached vulnerability repository

Agent-safe baseline for automation:
`retire --path /path/to/project --outputformat json --outputpath /tmp/retire_results.json --severity medium`

Common patterns:
- Scan a project for all vulnerable JS and Node dependencies:
  `retire --path /path/to/project --outputformat json --outputpath /tmp/retire_all.json`
- Scan only node_modules:
  `retire --node --nodepath /path/to/project --outputformat json --outputpath /tmp/retire_node.json`
- Scan only client-side JS files:
  `retire --js --jspath /path/to/project/static --outputformat json --outputpath /tmp/retire_js.json`
- Filter by severity (high and critical only):
  `retire --path /path/to/project --severity high --outputformat json --outputpath /tmp/retire_high.json`
- CI pipeline gate (fail build on vulnerabilities):
  `retire --path /path/to/project --severity high --exitwith 1`
- Scan with ignore file (suppress known false positives):
  `retire --path /path/to/project --ignorefile /path/to/.retireignore.json --outputformat json --outputpath /tmp/retire_filtered.json`
- Generate CycloneDX SBOM:
  `retire --path /path/to/project --outputformat cyclonedx --outputpath /tmp/retire_sbom.json`
- Verbose scan for debugging:
  `retire --path /path/to/project --verbose`
- Scan specific directory, excluding vendor:
  `retire --path /path/to/project --ignore node_modules/some-excluded-pkg --outputformat json --outputpath /tmp/retire_scoped.json`

Sandbox safety:
- Always use `--path` to target a specific directory; do not scan the entire filesystem.
- Use `--severity medium` or `--severity high` to filter out low-noise findings.
- Prefer `--outputformat json` for machine-parseable output.
- Use `--ignorefile` to suppress known false positives and accepted risks.
- Avoid `--insecure` unless testing in a controlled network environment.
- For large projects, scan `--node` and `--js` separately to isolate issues.

Failure recovery:
- If scan finds nothing, verify the path contains JS files or a node_modules directory.
- If vulnerability repo fetch fails, check network connectivity or use `--proxy`.
- If too many results, raise `--severity` threshold or add entries to `.retireignore.json`.
- If exit code is unexpected, check `--exitwith` is set correctly for CI pipelines.
