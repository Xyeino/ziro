---
name: trufflehog
description: TruffleHog secret scanner — detect leaked credentials in git repos, filesystems, and GitHub orgs with verification.
---

# TruffleHog CLI Playbook

Official docs:
- https://github.com/trufflesecurity/trufflehog
- https://trufflesecurity.com/trufflehog

Canonical syntax:
`trufflehog <source> [options] <target>`

High-signal flags:
- `trufflehog git <repo_url>` scan a git repository (all branches/commits)
- `trufflehog filesystem <path>` scan a local directory
- `trufflehog github --org <org>` scan all repos in a GitHub organization
- `trufflehog s3 --bucket <name>` scan an S3 bucket
- `--only-verified` only report secrets that were verified as active/valid
- `--json` output results as JSON (one object per line)
- `--concurrency <n>` number of concurrent workers
- `--no-update` skip self-update check
- `--results=verified,unknown,unverified` control which result types to show
- `--include-detectors <list>` only run specific detectors
- `--exclude-detectors <list>` skip specific detectors
- `--exclude-paths <file>` file containing path patterns to skip
- `--since-commit <hash>` only scan commits after this hash
- `--branch <name>` scan a specific branch only
- `--max-depth <n>` max commit depth for git scanning
- `--fail` exit with non-zero code if secrets found (CI mode)

Agent-safe baseline for automation:
`trufflehog git --only-verified --json --concurrency 4 --max-depth 500 <repo_url>`

Common patterns:
- Scan local git repo for verified secrets:
  `trufflehog git --only-verified --json file:///path/to/repo`
- Scan remote repo:
  `trufflehog git --only-verified --json https://github.com/org/repo.git`
- Scan filesystem directory:
  `trufflehog filesystem --only-verified --json /path/to/project`
- Scan entire GitHub org:
  `trufflehog github --org myorg --only-verified --json --concurrency 4`
- Scan with path exclusions:
  `trufflehog git --only-verified --json --exclude-paths /tmp/excludes.txt file:///path/to/repo`
  (excludes.txt contains patterns like `vendor/`, `node_modules/`, `*.min.js`)
- Scan recent commits only:
  `trufflehog git --only-verified --json --since-commit abc1234 file:///path/to/repo`
- Scan single branch:
  `trufflehog git --only-verified --json --branch main file:///path/to/repo`
- CI gate (fail if verified secrets found):
  `trufflehog git --only-verified --fail file:///path/to/repo`
- Include all results (verified + unverified):
  `trufflehog git --results=verified,unknown --json file:///path/to/repo`

Sandbox safety:
- Always use `--only-verified` to reduce false positives and focus on real leaks.
- Set `--concurrency` to 2-5 to avoid excessive resource usage.
- Use `--max-depth` to limit how far back in git history to scan.
- Use `--exclude-paths` to skip vendored, generated, or third-party code.
- Avoid scanning very large orgs without `--concurrency` limits.
- Use `--json` for machine-parseable output in automation.
- Add `--no-update` to skip network calls for version checks.

Failure recovery:
- If scan is slow, reduce `--concurrency` or add `--max-depth`.
- If too many false positives, switch to `--only-verified`.
- If git clone fails, ensure credentials/tokens are available or scan as `filesystem` instead.
- If specific detectors are noisy, use `--exclude-detectors` to skip them.
