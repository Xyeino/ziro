"""
Pre-scan reconnaissance module.

Runs lightweight recon tools (subfinder, nmap, httpx, nuclei) inside the
Docker sandbox *before* the AI agent starts, so the agent gets context
about the target upfront.
"""

import asyncio
import json
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# In-memory store keyed by recon_id
_recon_sessions: dict[str, "ReconSession"] = {}


@dataclass
class ReconLog:
    timestamp: float
    step: int
    message: str


@dataclass
class ReconSession:
    recon_id: str
    target: str
    target_domain: str
    target_type: str  # web_application, ip_address, domain
    status: str = "pending"  # pending, step_1..step_4, completed, failed
    current_step: int = 0
    logs: list[ReconLog] = field(default_factory=list)
    results: dict[str, Any] = field(default_factory=dict)
    sandbox_info: dict[str, Any] | None = None
    error: str | None = None
    docker_available: bool = True
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    # Progress tracking for Step 3
    scan_progress: int = 0
    scan_total: int = 0


def _log(session: ReconSession, step: int, message: str) -> None:
    session.logs.append(ReconLog(timestamp=time.time(), step=step, message=message))
    logger.info("[recon:%s] %s", session.recon_id[:8], message)


def _extract_domain(target: str) -> str:
    """Extract domain from URL or return as-is."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    # Remove port if present
    return target.split(":")[0].split("/")[0]


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


async def _sandbox_exec(
    api_url: str, token: str, command: str, timeout: float = 60
) -> dict[str, Any]:
    """Execute a command in the Docker sandbox via the tool server."""
    async with httpx.AsyncClient(trust_env=False) as client:
        try:
            response = await client.post(
                f"{api_url}/execute",
                json={
                    "agent_id": "recon-agent",
                    "tool_name": "terminal_execute",
                    "kwargs": {"command": command, "timeout": timeout},
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=httpx.Timeout(timeout + 30, connect=10),
            )
            response.raise_for_status()
            data = response.json()
            return data.get("result", {})
        except httpx.TimeoutException:
            return {"error": "Command timed out", "content": ""}
        except Exception as e:
            return {"error": str(e), "content": ""}


async def _take_screenshots(
    api_url: str, token: str, urls: list[str]
) -> dict[str, str]:
    """Take screenshots using simple playwright CLI approach."""
    screenshots: dict[str, str] = {}

    # Write a Python script to a file first, then execute it (avoids shell escaping issues)
    script_content = """
import json, os, sys, hashlib
os.makedirs('/tmp/screenshots', exist_ok=True)
urls = json.loads(sys.argv[1])
manifest = {}
try:
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'])
    for url in urls:
        try:
            fname = hashlib.md5(url.encode()).hexdigest() + '.png'
            page = browser.new_page(viewport={'width': 1280, 'height': 720})
            page.goto(url, timeout=10000, wait_until='domcontentloaded')
            page.wait_for_timeout(1500)
            page.screenshot(path=f'/tmp/screenshots/{fname}', type='png')
            page.close()
            manifest[url] = fname
        except Exception as e:
            print(f'SKIP:{url}:{e}', file=sys.stderr)
    browser.close()
    pw.stop()
except Exception as e:
    print(f'FATAL:{e}', file=sys.stderr)
print(json.dumps(manifest))
"""
    # Write script to file in sandbox
    await _sandbox_exec(api_url, token, f"cat > /tmp/screenshot.py << 'SCRIPTEOF'\n{script_content}\nSCRIPTEOF", timeout=5)

    # Execute with URLs as argument
    urls_arg = json.dumps(urls).replace("'", "'\\''")
    result = await _sandbox_exec(api_url, token, f"python3 /tmp/screenshot.py '{urls_arg}'", timeout=90)
    content = result.get("content", "").strip()

    # Parse manifest from last line of output
    manifest: dict[str, str] = {}
    for line in reversed(content.split("\n")):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                manifest = json.loads(line)
                break
            except (json.JSONDecodeError, ValueError):
                continue

    if not manifest:
        logger.warning("Screenshot script returned no manifest. Output: %s", content[:500])
        return {}

    # Read each screenshot file as base64
    for url, fname in manifest.items():
        try:
            read_result = await _sandbox_exec(api_url, token, f"base64 -w0 /tmp/screenshots/{fname}", timeout=10)
            b64_data = read_result.get("content", "").strip()
            for line in b64_data.split("\n"):
                line = line.strip()
                if line and not line.startswith("[ZIRO_") and len(line) > 100:
                    screenshots[url] = line
                    break
        except Exception:
            pass

    return screenshots


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------


async def _run_step_1(session: ReconSession, api_url: str, token: str) -> None:
    """Step 1: Asset Discovery — subdomains, DNS, IPs, HTTP probe, screenshots."""
    session.status = "step_1"
    session.current_step = 1
    domain = session.target_domain
    target = session.target

    subdomains_set: set[str] = set()

    if not _is_ip(domain):
        # 1. Subfinder
        _log(session, 1, f"Enumerating subdomains for {domain}...")
        result = await _sandbox_exec(
            api_url, token,
            f"subfinder -d {domain} -all -recursive -silent 2>/dev/null | head -100",
            timeout=45,
        )
        output = result.get("content", "")
        if not result.get("error"):
            for line in output.strip().split("\n"):
                sub = line.strip().lower()
                if (sub and domain in sub and not sub.startswith("[")
                    and "$" not in sub and " " not in sub):
                    subdomains_set.add(sub)

        # 2. Multi-source OSINT + DNS bruteforce (all in parallel)
        _log(session, 1, f"Querying OSINT sources + DNS bruteforce...")
        osint_script = f"""
import requests, json, socket, concurrent.futures
domain = "{domain}"
found = set()
try:
    r = requests.get(f"https://crt.sh/?q=%25.{{domain}}&output=json", timeout=15, headers={{"User-Agent":"Mozilla/5.0"}})
    if r.status_code == 200:
        for cert in r.json():
            for name in cert.get("name_value","").split("\\n"):
                name = name.strip().lower().replace("*.", "")
                if name.endswith(f".{{domain}}") or name == domain: found.add(name)
except: pass
try:
    r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={{domain}}", timeout=10, headers={{"User-Agent":"Mozilla/5.0"}})
    if r.status_code == 200:
        for line in r.text.strip().split("\\n"):
            if "," in line: found.add(line.split(",")[0].strip().lower())
except: pass
try:
    r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{{domain}}/passive_dns", timeout=10, headers={{"User-Agent":"Mozilla/5.0"}})
    if r.status_code == 200:
        for rec in r.json().get("passive_dns", []):
            h = rec.get("hostname","").lower()
            if h.endswith(f".{{domain}}") or h == domain: found.add(h)
except: pass
try:
    r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{{domain}}", timeout=10, headers={{"User-Agent":"Mozilla/5.0"}})
    if r.status_code == 200:
        for res in r.json().get("results", []):
            d = res.get("page",{{}}).get("domain","").lower()
            if d.endswith(f".{{domain}}") or d == domain: found.add(d)
except: pass
common = ["www","mail","ftp","admin","api","dev","staging","test","beta","app","mobile","m",
"shop","store","blog","cdn","static","img","assets","media","portal","vpn","secure","git",
"jenkins","ci","db","grafana","monitoring","backup","old","dashboard","panel","status",
"ws","chat","payment","pay","checkout","crm","docs","internal","sandbox","uat","qa",
"auth","sso","oauth","gateway","proxy","cache","queue","worker","scheduler","cron"]
def check(sub):
    try: socket.gethostbyname(f"{{sub}}.{{domain}}"); return f"{{sub}}.{{domain}}"
    except: return None
with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
    for r in ex.map(check, common):
        if r: found.add(r)
print("OSINT_RESULTS:" + json.dumps(sorted(found)))
"""
        osint_result = await _sandbox_exec(api_url, token, f"python3 -c {json.dumps(osint_script)}", timeout=45)
        for line in osint_result.get("content", "").split("\n"):
            if line.strip().startswith("OSINT_RESULTS:"):
                try:
                    for sub in json.loads(line.strip()[len("OSINT_RESULTS:"):]):
                        sub = sub.strip().lower()
                        if sub and domain in sub and " " not in sub and "\\" not in sub:
                            subdomains_set.add(sub)
                except (json.JSONDecodeError, ValueError):
                    pass

        subdomains_set.add(domain)
        subdomains = sorted(subdomains_set)
        _log(session, 1, f"Found {len(subdomains)} unique subdomains")
        for s in subdomains[:15]:
            _log(session, 1, f"  → {s}")
        if len(subdomains) > 15:
            _log(session, 1, f"  ... and {len(subdomains) - 15} more")
    else:
        subdomains = [domain]

    # 3. HTTP probe all subdomains
    probe_targets = subdomains[:30]
    _log(session, 1, f"Probing {len(probe_targets)} targets with httpx...")
    write_cmd = "printf '%s\\n' " + " ".join(f"'{t}'" for t in probe_targets)
    result = await _sandbox_exec(api_url, token, f'{write_cmd} | httpx -sc -title -server -td -silent 2>/dev/null', timeout=30)
    httpx_output = result.get("content", "").strip()
    alive_urls: list[str] = []
    for line in httpx_output.split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_"):
            _log(session, 1, f"  {line}")
            import re as _re
            url_m = _re.match(r"(https?://\S+)", line)
            if url_m:
                alive_urls.append(url_m.group(1))

    # 4. Port scan all subdomains
    _log(session, 1, f"Port scanning {len(subdomains[:15])} targets...")
    targets_str = " ".join(f"'{t}'" for t in subdomains[:15])
    nmap_result = await _sandbox_exec(
        api_url, token,
        f"nmap -n -Pn --top-ports 1000 --open -T4 -sV --version-light --max-retries 1 --host-timeout 45s {targets_str} 2>/dev/null | grep -E '^[0-9]|^Nmap|^PORT'",
        timeout=90,
    )
    nmap_output = nmap_result.get("content", "").strip()
    for line in nmap_output.split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_"):
            _log(session, 1, f"  {line}")

    # 5. DNS resolution — get IPs for all subdomains
    _log(session, 1, "Resolving DNS records...")
    dns_result = await _sandbox_exec(
        api_url, token,
        f"printf '%s\\n' " + " ".join(f"'{s}'" for s in subdomains[:20]) + " | while read d; do dig +short \"$d\" A \"$d\" AAAA 2>/dev/null; done | sort -u | head -20",
        timeout=15,
    )
    ips: list[str] = []
    for line in dns_result.get("content", "").strip().split("\n"):
        ip = line.strip()
        if ip and not ip.startswith("[ZIRO_") and ("." in ip or ":" in ip):
            ips.append(ip)
    if ips:
        _log(session, 1, f"  IPs: {', '.join(ips[:10])}")

    # 5b. IP Intelligence — whois, ASN, hosting info
    ip_info: dict[str, Any] = {}
    primary_ip = ips[0] if ips else domain
    _log(session, 1, f"Looking up IP intelligence for {primary_ip}...")
    whois_result = await _sandbox_exec(
        api_url, token,
        f'curl -s "http://ip-api.com/json/{primary_ip}?fields=status,country,regionName,city,isp,org,as,hosting" 2>/dev/null',
        timeout=10,
    )
    whois_out = whois_result.get("content", "").strip()
    try:
        # Find JSON in output
        for line in whois_out.split("\n"):
            line = line.strip()
            if line.startswith("{"):
                ip_data = json.loads(line)
                if ip_data.get("status") == "success":
                    ip_info = {
                        "ip": primary_ip,
                        "country": ip_data.get("country", ""),
                        "region": ip_data.get("regionName", ""),
                        "city": ip_data.get("city", ""),
                        "isp": ip_data.get("isp", ""),
                        "org": ip_data.get("org", ""),
                        "asn": ip_data.get("as", ""),
                        "hosting": ip_data.get("hosting", False),
                    }
                    _log(session, 1, f"  Country: {ip_info['country']}, ISP: {ip_info['isp']}")
                    _log(session, 1, f"  ASN: {ip_info['asn']}, Org: {ip_info['org']}")
                break
    except (json.JSONDecodeError, ValueError, KeyError):
        pass

    # 6. OSINT — robots.txt, security.txt, Google dork suggestions
    _log(session, 1, "Gathering OSINT intelligence...")
    osint_data: dict[str, Any] = {}
    try:
        # robots.txt
        robots_result = await _sandbox_exec(api_url, token, f"curl -sL -m 8 https://{domain}/robots.txt 2>/dev/null | head -30", timeout=12)
        robots = robots_result.get("content", "").strip()
        disallowed = [l.split(":", 1)[1].strip() for l in robots.split("\n") if l.lower().startswith("disallow") and ":" in l]
        if disallowed:
            _log(session, 1, f"  robots.txt: {len(disallowed)} disallowed paths")
            osint_data["robots_disallowed"] = disallowed[:15]
            # Add interesting disallowed paths as endpoints
            for path in disallowed:
                if any(k in path.lower() for k in ("/admin", "/api", "/internal", "/debug", "/config", "/backup")):
                    _log(session, 1, f"    ⚠ Interesting: {path}")

        # security.txt
        sec_result = await _sandbox_exec(api_url, token, f"curl -sL -m 5 https://{domain}/.well-known/security.txt 2>/dev/null | head -10", timeout=8)
        sec_txt = sec_result.get("content", "").strip()
        if sec_txt and ("contact:" in sec_txt.lower() or "policy:" in sec_txt.lower()):
            _log(session, 1, "  security.txt found")
            osint_data["security_txt"] = sec_txt[:300]
    except Exception:
        pass

    # 7. API-enhanced intelligence (Shodan, real IP detection)
    shodan_data: dict[str, Any] = {}
    # 6b. Subdomain takeover check
    takeover_candidates: list[str] = []
    if len(subdomains) > 1:
        _log(session, 1, "Checking for subdomain takeover...")
        takeover_script = f"""
import socket, json
subs = {json.dumps(subdomains[:20])}
vulns = []
takeover_sigs = ["nxdomain", "nosuchbucket", "no such app", "there isn't a github pages",
    "herokucdn.com/error-pages", "the thing you were looking for", "project not found",
    "repository not found", "this page is reserved", "no settings were found"]
for sub in subs:
    try:
        answers = socket.getaddrinfo(sub, None)
    except socket.gaierror:
        vulns.append({{"sub": sub, "reason": "NXDOMAIN - dangling DNS"}})
        continue
    try:
        import subprocess
        r = subprocess.run(["dig", "+short", "CNAME", sub], capture_output=True, text=True, timeout=5)
        cname = r.stdout.strip()
        if cname and any(p in cname for p in [".herokuapp.com", ".s3.amazonaws.com", ".github.io",
            ".azurewebsites.net", ".cloudfront.net", ".ghost.io", ".surge.sh",
            ".bitbucket.io", ".netlify.app", ".fly.dev"]):
            import requests
            try:
                resp = requests.get(f"https://{{sub}}", timeout=5, verify=False)
                body = resp.text.lower()[:2000]
                if any(sig in body for sig in takeover_sigs) or resp.status_code == 404:
                    vulns.append({{"sub": sub, "cname": cname, "reason": "Potential takeover - unclaimed resource"}})
            except: pass
    except: pass
print("TAKEOVER:" + json.dumps(vulns))
"""
        tk_result = await _sandbox_exec(api_url, token, f"python3 -c {json.dumps(takeover_script)}", timeout=30)
        for line in tk_result.get("content", "").split("\n"):
            if line.strip().startswith("TAKEOVER:"):
                try:
                    tk_data = json.loads(line.strip()[9:])
                    for t in tk_data:
                        takeover_candidates.append(t.get("sub", ""))
                        _log(session, 1, f"  ⚠ TAKEOVER: {t.get('sub', '')} — {t.get('reason', '')}")
                except (json.JSONDecodeError, ValueError):
                    pass

    # 7. API-enhanced intelligence (Shodan, real IP detection)
    real_ip: str = ""
    try:
        from ziro.panel.server import get_api_key

        # Shodan lookup for each IP
        shodan_key = get_api_key("shodan")
        if shodan_key and ips:
            _log(session, 1, "Querying Shodan for IP intelligence...")
            shodan_script = f"""
import requests, json
key = "{shodan_key}"
ips = {json.dumps(ips[:5])}
results = {{}}
for ip in ips:
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{{ip}}?key={{key}}", timeout=10)
        if r.status_code == 200:
            d = r.json()
            results[ip] = {{
                "org": d.get("org",""), "os": d.get("os",""),
                "ports": d.get("ports",[]), "vulns": list(d.get("vulns",{{}}).keys())[:10],
                "hostnames": d.get("hostnames",[]),
            }}
    except: pass
print("SHODAN:" + json.dumps(results))
"""
            shodan_result = await _sandbox_exec(api_url, token, f"python3 -c {json.dumps(shodan_script)}", timeout=30)
            for line in shodan_result.get("content", "").split("\n"):
                if line.strip().startswith("SHODAN:"):
                    try:
                        shodan_data = json.loads(line.strip()[7:])
                        for ip, info in shodan_data.items():
                            ports = info.get("ports", [])
                            vulns = info.get("vulns", [])
                            _log(session, 1, f"  {ip}: org={info.get('org','?')}, ports={ports[:10]}, vulns={len(vulns)}")
                    except (json.JSONDecodeError, ValueError):
                        pass

        # Real IP behind WAF — check DNS history via SecurityTrails
        st_key = get_api_key("securitytrails")
        if st_key:
            _log(session, 1, "Checking DNS history for real IP behind WAF...")
            st_result = await _sandbox_exec(
                api_url, token,
                f'curl -s -m 10 "https://api.securitytrails.com/v1/history/{domain}/dns/a" -H "APIKEY:{st_key}" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); ips=set(); [ips.update(r.get(\'values\',[{{}}])[0].get(\'ip\',\'\').split()) for r in d.get(\'records\',[])]; print(\'HISTORY_IPS:\'+json.dumps(sorted(ips)))"',
                timeout=15,
            )
            for line in st_result.get("content", "").split("\n"):
                if line.strip().startswith("HISTORY_IPS:"):
                    try:
                        hist_ips = json.loads(line.strip()[12:])
                        new_ips = [ip for ip in hist_ips if ip not in ips and ip]
                        if new_ips:
                            real_ip = new_ips[0]
                            _log(session, 1, f"  ⚠ Historical IPs (possible real IP behind WAF): {', '.join(new_ips[:5])}")
                    except (json.JSONDecodeError, ValueError):
                        pass
    except ImportError:
        pass

    # 7. Screenshots (disabled — agent takes screenshots during scan via browser)
    screenshots: dict[str, str] = {}

    session.results["step_1"] = {
        "subdomains": subdomains,
        "httpx_output": httpx_output,
        "nmap_output": nmap_output,
        "screenshots": screenshots,
        "ips": ips,
        "alive_urls": alive_urls,
        "ip_info": ip_info,
        "osint": osint_data,
        "takeover_candidates": takeover_candidates,
        "shodan": shodan_data,
        "real_ip": real_ip,
    }
    _log(session, 1, "[Step-1] Complete")


async def _run_step_2(session: ReconSession, api_url: str, token: str) -> None:
    """Step 2: API & Endpoint Discovery — crawl all alive targets to find endpoints."""
    session.status = "step_2"
    session.current_step = 2
    domain = session.target_domain
    target = session.target

    step1 = session.results.get("step_1", {})
    alive_urls = step1.get("alive_urls", [])
    main_url = target if target.startswith("http") else f"https://{target}"
    if main_url not in alive_urls:
        alive_urls.insert(0, main_url)

    all_endpoints: list[str] = []

    # 1. Katana — JS-aware headless crawler (like crawlergo)
    crawl_targets = alive_urls[:5]
    _log(session, 2, f"Crawling {len(crawl_targets)} targets with katana...")
    write_cmd = "printf '%s\\n' " + " ".join(f"'{u}'" for u in crawl_targets)
    result = await _sandbox_exec(
        api_url, token,
        f"{write_cmd} | katana -d 3 -jc -kf all -ef css,png,jpg,gif,svg,woff,woff2,ico -silent 2>/dev/null | sort -u | head -200",
        timeout=60,
    )
    katana_output = result.get("content", "").strip()
    for line in katana_output.split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_") and line.startswith("http"):
            all_endpoints.append(line)
    _log(session, 2, f"Katana found {len(all_endpoints)} URLs")

    # 2. GoSpider — parallel spider with JS parsing
    _log(session, 2, f"Running gospider on {main_url}...")
    result = await _sandbox_exec(
        api_url, token,
        f"gospider -s {main_url} -d 2 -c 5 --js --sitemap --robots -q 2>/dev/null | grep -oE 'https?://[^ ]+' | sort -u | head -100",
        timeout=45,
    )
    gospider_output = result.get("content", "").strip()
    gospider_count = 0
    for line in gospider_output.split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_") and line.startswith("http") and line not in all_endpoints:
            all_endpoints.append(line)
            gospider_count += 1
    if gospider_count:
        _log(session, 2, f"GoSpider found {gospider_count} additional URLs")

    # 3. Feroxbuster — directory brute-force
    _log(session, 2, f"Directory discovery on {main_url}...")
    result = await _sandbox_exec(
        api_url, token,
        f"feroxbuster -u {main_url} -w /usr/share/wordlists/dirb/common.txt -t 20 -d 2 --silent --no-state -k --auto-bail 2>/dev/null | grep -E '^[0-9]' | head -50",
        timeout=45,
    )
    ferox_output = result.get("content", "").strip()
    ferox_count = 0
    for line in ferox_output.split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_"):
            # feroxbuster format: STATUS_CODE  SIZE  URL
            parts = line.split()
            if len(parts) >= 3 and parts[-1].startswith("http"):
                url = parts[-1]
                if url not in all_endpoints:
                    all_endpoints.append(url)
                    ferox_count += 1
            _log(session, 2, f"  {line}")
    if ferox_count:
        _log(session, 2, f"Feroxbuster found {ferox_count} additional paths")

    # 4. Deep JS Analysis — extract secrets, API endpoints, tokens from JS bundles
    _log(session, 2, "Analyzing JavaScript files for secrets and endpoints...")
    # Write JS analysis script to file (avoids f-string escape warnings)
    js_script_content = r"""
import requests, re, json, sys
from urllib.parse import urljoin
url = sys.argv[1] if len(sys.argv) > 1 else ""
found_secrets = []
found_endpoints = []
found_domains = []

# Get main page to find JS files
try:
    r = requests.get(url, timeout=10, headers={{"User-Agent":"Mozilla/5.0"}}, verify=False)
    html = r.text

    # Extract JS file URLs
    js_urls = set()
    for m in re.finditer(r'(?:src|href)=["\\']((?:[^"\\'/]*\\.js(?:\\?[^"\\']*)?|[^"\\'/]*bundle[^"\\']*|[^"\\'/]*chunk[^"\\']*\\.js[^"\\']*))["\\'\\s]', html):
        js_url = m.group(1)
        if js_url.startswith('//'):
            js_url = 'https:' + js_url
        elif js_url.startswith('/'):
            js_url = urljoin(url, js_url)
        elif not js_url.startswith('http'):
            js_url = urljoin(url, js_url)
        js_urls.add(js_url)

    # Also check for source maps
    for m in re.finditer(r'sourceMappingURL=([^\\s"\\'/]+\\.map)', html):
        js_urls.add(urljoin(url, m.group(1)))

    # Analyze each JS file
    for js_url in list(js_urls)[:15]:
        try:
            jr = requests.get(js_url, timeout=8, headers={{"User-Agent":"Mozilla/5.0"}}, verify=False)
            js = jr.text
            if len(js) < 100:
                continue

            # API keys and tokens
            for pattern, name in [
                (r'(?:api[_-]?key|apikey|api_secret)["\\'\\s:=]+["\\']([\w-]{{20,}})["\\'\\s]', 'API_KEY'),
                (r'(?:Bearer|token|auth)["\\'\\s:=]+["\\'](eyJ[\w-]+\\.[\w-]+\\.[\w-]+)["\\'\\s]', 'JWT_TOKEN'),
                (r'(?:aws_access|AKIA)([\w]{{16,}})', 'AWS_KEY'),
                (r'(?:sk-|pk_live_|pk_test_|rk_live_)([\w]{{20,}})', 'SECRET_KEY'),
                (r'(?:password|passwd|secret)["\\'\\s:=]+["\\']([^"\\'\\s]{{6,}})["\\'\\s]', 'PASSWORD'),
                (r'(?:firebase|supabase|appwrite)["\\'\\s:=]+["\\']([\w:/.-]{{20,}})["\\'\\s]', 'SERVICE_KEY'),
            ]:
                for m in re.finditer(pattern, js, re.IGNORECASE):
                    found_secrets.append({{"type": name, "value": m.group(1)[:50], "source": js_url.split("/")[-1]}})

            # API endpoints
            for m in re.finditer(r'["\\']/(api|rest|v[0-9]|graphql|auth|admin|internal)/[\\w/.-]+["\\']', js):
                ep = m.group(0).strip("\"'")
                if ep not in found_endpoints:
                    found_endpoints.append(ep)

            # Absolute URLs (internal APIs)
            for m in re.finditer(r'["\\']https?://[\\w.-]+/[\\w/.-]*["\\']', js):
                u = m.group(0).strip("\"'")
                if len(u) < 200:
                    found_domains.append(u)

            # Source map check
            if 'sourceMappingURL=' in js:
                map_match = re.search(r'sourceMappingURL=([^\\s]+)', js)
                if map_match:
                    found_secrets.append({{"type": "SOURCE_MAP", "value": map_match.group(1), "source": js_url.split("/")[-1]}})

        except Exception:
            pass
except Exception as e:
    print(f"ERROR:{{e}}", file=sys.stderr)

result = {"secrets": found_secrets[:20], "endpoints": found_endpoints[:50], "domains": found_domains[:20], "js_files": len(js_urls)}
print("JS_ANALYSIS:" + json.dumps(result))
"""
    # Write script to file, pass URL as argument
    await _sandbox_exec(api_url, token, f"cat > /tmp/js_analysis.py << 'JSEOF'\n{js_script_content}\nJSEOF", timeout=5)
    js_result = await _sandbox_exec(api_url, token, f"python3 /tmp/js_analysis.py '{main_url}'", timeout=30)
    js_secrets: list[dict[str, str]] = []
    js_endpoints: list[str] = []
    js_domains: list[str] = []
    js_files_count = 0
    for line in js_result.get("content", "").split("\n"):
        line = line.strip()
        if line.startswith("JS_ANALYSIS:"):
            try:
                js_data = json.loads(line[12:])
                js_secrets = js_data.get("secrets", [])
                js_endpoints = js_data.get("endpoints", [])
                js_domains = js_data.get("domains", [])
                js_files_count = js_data.get("js_files", 0)
            except (json.JSONDecodeError, ValueError):
                pass

    if js_files_count:
        _log(session, 2, f"  Analyzed {js_files_count} JS files")
    if js_secrets:
        _log(session, 2, f"  ⚠ Found {len(js_secrets)} exposed secrets/tokens!")
        for s in js_secrets[:5]:
            _log(session, 2, f"    {s['type']}: {s['value'][:30]}... ({s['source']})")
    if js_endpoints:
        _log(session, 2, f"  Found {len(js_endpoints)} API endpoints in JS")
        for ep in js_endpoints:
            full_url = f"{main_url.rstrip('/')}{ep}" if ep.startswith("/") else ep
            if full_url not in all_endpoints:
                all_endpoints.append(full_url)
    if js_domains:
        _log(session, 2, f"  Found {len(js_domains)} internal URLs in JS")

    # 4b. Secret scanning — check for leaked secrets in target's public repos/JS
    _log(session, 2, "Scanning for leaked secrets...")
    secrets_found: list[dict[str, str]] = []

    # trufflehog on target domain (check GitHub for leaked secrets)
    trufflehog_result = await _sandbox_exec(
        api_url, token,
        f"trufflehog github --org={domain.split('.')[0]} --only-verified --json 2>/dev/null | head -5 || echo 'NORESULTS'",
        timeout=20,
    )
    trufflehog_out = trufflehog_result.get("content", "").strip()
    if trufflehog_out and "NORESULTS" not in trufflehog_out:
        for line in trufflehog_out.split("\n"):
            if line.strip().startswith("{"):
                try:
                    import json as _json
                    sec = _json.loads(line.strip())
                    secrets_found.append({"type": sec.get("DetectorName", ""), "source": "trufflehog"})
                except Exception:
                    pass

    # Cloud bucket enumeration
    _log(session, 2, "Checking for exposed cloud buckets...")
    cloud_result = await _sandbox_exec(
        api_url, token,
        f"cloud_enum -k {domain.split('.')[0]} -l /tmp/cloud_results.txt 2>/dev/null; cat /tmp/cloud_results.txt 2>/dev/null | head -20 || echo 'NORESULTS'",
        timeout=25,
    )
    cloud_out = cloud_result.get("content", "").strip()
    cloud_buckets: list[str] = []
    if cloud_out and "NORESULTS" not in cloud_out:
        for line in cloud_out.split("\n"):
            line = line.strip()
            if line and not line.startswith("[ZIRO_") and ("s3" in line.lower() or "blob" in line.lower() or "storage" in line.lower()):
                cloud_buckets.append(line)
                _log(session, 2, f"  ⚠ Cloud: {line}")

    if secrets_found:
        _log(session, 2, f"  ⚠ Found {len(secrets_found)} leaked secrets!")
    if cloud_buckets:
        _log(session, 2, f"  Found {len(cloud_buckets)} cloud storage endpoints")

    # 5. GraphQL introspection — check common GraphQL endpoints
    graphql_info: dict[str, Any] = {}
    graphql_paths = ["/graphql", "/api/graphql", "/api/graphql/query", "/graphql/v1", "/gql"]
    _log(session, 2, "Checking for GraphQL endpoints...")
    for gql_path in graphql_paths:
        gql_url = f"{main_url.rstrip('/')}{gql_path}"
        result = await _sandbox_exec(
            api_url, token,
            f'curl -s -m 8 -X POST {gql_url} -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{queryType{{name}}mutationType{{name}}types{{name kind}}}}}}"}}\'  2>/dev/null | head -c 2000',
            timeout=12,
        )
        gql_out = result.get("content", "").strip()
        if gql_out and "__schema" in gql_out and "errors" not in gql_out[:50]:
            _log(session, 2, f"  ✓ GraphQL found at {gql_path}")
            try:
                gql_data = json.loads(gql_out)
                schema = gql_data.get("data", {}).get("__schema", {})
                types = [t["name"] for t in schema.get("types", []) if not t["name"].startswith("__")]
                queries = schema.get("queryType", {}).get("name", "")
                mutations = schema.get("mutationType", {})
                graphql_info = {
                    "endpoint": gql_url,
                    "types_count": len(types),
                    "types": types[:30],
                    "has_mutations": mutations is not None,
                    "query_type": queries,
                }
                _log(session, 2, f"  Schema: {len(types)} types, mutations: {'yes' if mutations else 'no'}")
                if gql_url not in all_endpoints:
                    all_endpoints.append(gql_url)
            except (json.JSONDecodeError, ValueError, KeyError):
                graphql_info = {"endpoint": gql_url, "raw": gql_out[:500]}
            break

    # Classify endpoints by type
    api_endpoints = [u for u in all_endpoints if any(k in u.lower() for k in ("/api", "/graphql", "/rest", "/v1", "/v2", "/query", "/mutation"))]
    auth_endpoints = [u for u in all_endpoints if any(k in u.lower() for k in ("/auth", "/login", "/signin", "/register", "/signup", "/oauth", "/token", "/session"))]
    admin_endpoints = [u for u in all_endpoints if any(k in u.lower() for k in ("/admin", "/dashboard", "/panel", "/manage", "/config", "/settings"))]

    _log(session, 2, f"Total: {len(all_endpoints)} endpoints")
    if api_endpoints:
        _log(session, 2, f"  API endpoints: {len(api_endpoints)}")
    if auth_endpoints:
        _log(session, 2, f"  Auth endpoints: {len(auth_endpoints)}")
    if admin_endpoints:
        _log(session, 2, f"  Admin endpoints: {len(admin_endpoints)}")

    session.results["step_2"] = {
        "endpoints": all_endpoints,
        "api_endpoints": api_endpoints,
        "auth_endpoints": auth_endpoints,
        "admin_endpoints": admin_endpoints,
        "endpoint_count": len(all_endpoints),
        "graphql": graphql_info,
        "js_secrets": js_secrets,
        "js_endpoints": js_endpoints,
        "js_domains": js_domains,
        "secrets_found": secrets_found,
        "cloud_buckets": cloud_buckets,
    }
    _log(session, 2, "[Step-2] Complete")


async def _run_step_3(session: ReconSession, api_url: str, token: str) -> None:
    """Step 3: Risk Analysis — WAF, headers, per-endpoint vuln scan with progress."""
    session.status = "step_3"
    session.current_step = 3
    target = session.target
    domain = session.target_domain
    main_url = target if target.startswith("http") else f"https://{target}"

    step2 = session.results.get("step_2", {})
    endpoints = step2.get("endpoints", [])
    findings: list[str] = []
    all_output: list[str] = []

    # 1. WAF detection
    _log(session, 3, f"Detecting WAF on {domain}...")
    result = await _sandbox_exec(api_url, token, f"wafw00f {main_url} 2>/dev/null | grep -E 'is behind|No WAF'", timeout=15)
    for line in result.get("content", "").strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_"):
            _log(session, 3, f"  {line}")
            all_output.append(line)
            if "is behind" in line:
                findings.append(f"WAF: {line}")

    # 2. Security headers check
    _log(session, 3, "Checking security headers...")
    result = await _sandbox_exec(api_url, token, f"curl -sI -m 10 {main_url} 2>/dev/null | grep -iE 'strict-transport|content-security|x-frame|x-content-type|x-xss|referrer-policy|server:|x-powered'", timeout=15)
    found_headers = []
    for line in result.get("content", "").strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_"):
            found_headers.append(line.split(":")[0].lower())
            all_output.append(line)
    for hdr in ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"]:
        if hdr not in " ".join(found_headers).lower():
            findings.append(f"Missing: {hdr}")
    missing = [f for f in findings if f.startswith("Missing:")]
    if missing:
        _log(session, 3, f"  ⚠ {', '.join(missing)}")

    # 3. Per-endpoint vulnerability scan with progress bar
    scan_urls = endpoints[:50] if endpoints else [main_url]
    total = len(scan_urls)
    session.scan_total = total
    session.scan_progress = 0

    _log(session, 3, f"Scanning {total} endpoints for vulnerabilities...")

    # Write all targets to file
    write_cmd = "printf '%s\\n' " + " ".join(f"'{u}'" for u in scan_urls)
    await _sandbox_exec(api_url, token, f"{write_cmd} > /tmp/scan_targets.txt", timeout=10)

    # Start progress ticker in background
    async def _tick_progress() -> None:
        """Simulate progress while nuclei runs."""
        for i in range(total):
            if session.scan_progress >= total:
                break
            session.scan_progress = min(i + 1, total - 1)
            await asyncio.sleep(90 / max(total, 1))  # Spread ticks across timeout

    progress_task = asyncio.create_task(_tick_progress())

    # Run nuclei with expanded templates
    result = await _sandbox_exec(
        api_url, token,
        "nuclei -l /tmp/scan_targets.txt "
        "-t http/cves/ -t http/exposures/ -t http/misconfiguration/ "
        "-t http/vulnerabilities/ -t http/technologies/ "
        "-s critical,high,medium "
        "-ni -rl 40 -c 8 -timeout 8 -retries 0 "
        "-silent 2>/dev/null | head -50",
        timeout=90,
    )
    progress_task.cancel()
    nuclei_out = result.get("content", "").strip()
    nuclei_findings = 0
    for line in nuclei_out.split("\n"):
        line = line.strip()
        if not line or line.startswith("[ZIRO_") or line.startswith("[Command"):
            continue
        # nuclei stats lines contain "templates" or "hosts"
        if "templates" in line.lower() or "hosts" in line.lower():
            continue
        findings.append(line)
        nuclei_findings += 1
        _log(session, 3, f"  ⚠ {line}")
        all_output.append(line)

    session.scan_progress = total  # Mark complete
    if nuclei_findings:
        _log(session, 3, f"Found {nuclei_findings} potential issues across {total} endpoints")
    else:
        _log(session, 3, f"  No critical/high/medium issues found in {total} endpoints")

    # 4. Also run afrog for additional coverage (CEL-based, catches different things than nuclei)
    _log(session, 3, "Running afrog scan for additional coverage...")
    afrog_result = await _sandbox_exec(
        api_url, token,
        f"afrog -T /tmp/scan_targets.txt -s critical,high -silent 2>/dev/null | head -20",
        timeout=45,
    )
    afrog_out = afrog_result.get("content", "").strip()
    afrog_findings = 0
    for line in afrog_out.split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_") and not line.startswith("[Command"):
            if line not in findings:
                findings.append(line)
                afrog_findings += 1
                _log(session, 3, f"  ⚠ [afrog] {line}")
                all_output.append(line)
    if afrog_findings:
        _log(session, 3, f"Afrog found {afrog_findings} additional issues")

    combined_output = "\n".join(all_output)
    session.results["step_3"] = {
        "nuclei_output": combined_output,
        "findings_count": len(findings),
        "endpoints_scanned": total,
    }
    _log(session, 3, "[Step-3] Complete")


async def _run_step_4(session: ReconSession, api_url: str, token: str) -> None:
    """Step 4: WAF Analysis — detect WAF, find real IP, test bypasses."""
    session.status = "step_4"
    session.current_step = 4
    target = session.target
    domain = session.target_domain
    main_url = target if target.startswith("http") else f"https://{target}"

    s1 = session.results.get("step_1", {})
    ips = s1.get("ips", [])
    waf_detected = False
    waf_vendor = ""
    real_ip = s1.get("real_ip", "")
    bypass_results: dict[str, Any] = {}

    # 1. Detect WAF vendor with waftester (197 signatures)
    _log(session, 4, f"Fingerprinting WAF on {domain}...")
    result = await _sandbox_exec(
        api_url, token,
        f"waf-tester vendor -u {main_url} 2>/dev/null || wafw00f {main_url} 2>/dev/null | grep -E 'is behind|No WAF'",
        timeout=20,
    )
    waf_output = result.get("content", "").strip()
    for line in waf_output.split("\n"):
        line = line.strip()
        if line and not line.startswith("[ZIRO_"):
            _log(session, 4, f"  {line}")
            if any(w in line.lower() for w in ("cloudflare", "akamai", "imperva", "aws waf", "sucuri", "ddos-guard", "is behind")):
                waf_detected = True
                waf_vendor = line

    # 2. If WAF detected — find real IP behind it
    if waf_detected:
        _log(session, 4, "⚠ WAF detected — searching for real origin IP...")

        # Method 1: Filter non-Cloudflare IPs from already discovered IPs
        cf_ranges_result = await _sandbox_exec(
            api_url, token,
            "curl -s https://www.cloudflare.com/ips-v4 2>/dev/null",
            timeout=10,
        )
        cf_ranges = [l.strip() for l in cf_ranges_result.get("content", "").split("\n") if l.strip() and not l.startswith("[ZIRO_")]

        if cf_ranges and ips:
            check_script = f"""
import ipaddress, json
cf_nets = []
for r in {json.dumps(cf_ranges)}:
    try: cf_nets.append(ipaddress.ip_network(r))
    except: pass
found = []
for ip in {json.dumps(ips)}:
    try:
        addr = ipaddress.ip_address(ip)
        if not any(addr in net for net in cf_nets):
            found.append(ip)
    except: pass
print("NON_CF_IPS:" + json.dumps(found))
"""
            ip_result = await _sandbox_exec(api_url, token, f"python3 -c {json.dumps(check_script)}", timeout=10)
            for line in ip_result.get("content", "").split("\n"):
                if line.strip().startswith("NON_CF_IPS:"):
                    try:
                        non_cf = json.loads(line.strip()[11:])
                        if non_cf:
                            real_ip = non_cf[0]
                            _log(session, 4, f"  ✓ Non-Cloudflare IPs found: {', '.join(non_cf[:5])}")
                            _log(session, 4, f"  ✓ Likely real origin IP: {real_ip}")
                    except (json.JSONDecodeError, ValueError):
                        pass

        # Method 2: DNS history via SecurityTrails (if key configured)
        if not real_ip:
            try:
                from ziro.panel.server import get_api_key
                st_key = get_api_key("securitytrails")
                if st_key:
                    _log(session, 4, "  Checking DNS history for origin IP...")
                    st_result = await _sandbox_exec(
                        api_url, token,
                        f'curl -s -m 10 "https://api.securitytrails.com/v1/history/{domain}/dns/a" -H "APIKEY:{st_key}" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); [print(r.get(\'values\',[{{}}])[0].get(\'ip\',\'\')) for r in d.get(\'records\',[])]" | sort -u | head -5',
                        timeout=15,
                    )
                    for line in st_result.get("content", "").strip().split("\n"):
                        ip = line.strip()
                        if ip and not ip.startswith("[ZIRO_") and ip not in ips:
                            real_ip = ip
                            _log(session, 4, f"  ✓ Historical origin IP: {ip}")
                            break
            except ImportError:
                pass

        if real_ip:
            _log(session, 4, f"  Scanning origin IP {real_ip} directly...")
            nmap_result = await _sandbox_exec(
                api_url, token,
                f"nmap -n -Pn --top-ports 100 --open -T4 -sV --version-light {real_ip} 2>/dev/null | grep -E '^[0-9]|^PORT'",
                timeout=30,
            )
            for line in nmap_result.get("content", "").strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("[ZIRO_"):
                    _log(session, 4, f"    {line}")
    else:
        _log(session, 4, "  No WAF detected — direct access to origin")

    # 3. WAF bypass testing with waftester (comprehensive)
    _log(session, 4, f"Running comprehensive WAF assessment on {main_url}...")

    # 3a. Probe — detect WAF vendor, HTTP version, TLS, headers, tech stack
    probe_result = await _sandbox_exec(
        api_url, token,
        f"waf-tester probe -u {main_url} 2>/dev/null | head -30 || echo 'WAFTESTER_UNAVAILABLE'",
        timeout=20,
    )
    probe_output = probe_result.get("content", "").strip()
    if "WAFTESTER_UNAVAILABLE" not in probe_output and probe_output:
        for line in probe_output.split("\n")[:10]:
            line = line.strip()
            if line and not line.startswith("[ZIRO_"):
                _log(session, 4, f"  {line}")

    # 3b. Auto assessment — smart mode with bypass + tamper-auto
    _log(session, 4, "  Running auto assessment with smart bypass detection...")
    result = await _sandbox_exec(
        api_url, token,
        f"waf-tester auto -u {main_url} --smart --smart-mode=standard --tamper-auto -c 3 --delay 100 -o /tmp/waf_results.json 2>/dev/null; cat /tmp/waf_results.json 2>/dev/null | head -c 5000 || echo 'WAFTESTER_UNAVAILABLE'",
        timeout=90,
    )
    waf_scan_output = result.get("content", "").strip()
    bypasses_found = 0
    if "WAFTESTER_UNAVAILABLE" not in waf_scan_output and waf_scan_output:
        try:
            waf_data = json.loads(waf_scan_output)
            if isinstance(waf_data, dict):
                bypasses_found = waf_data.get("bypassed", waf_data.get("bypass_count", 0))
                total_tests = waf_data.get("total", waf_data.get("total_tests", 0))
                blocked = waf_data.get("blocked", 0)
                if total_tests:
                    _log(session, 4, f"  Tests: {total_tests} | Blocked: {blocked} | Bypassed: {bypasses_found}")
        except (json.JSONDecodeError, ValueError):
            bypasses_found = waf_scan_output.lower().count("bypass")
        if bypasses_found:
            _log(session, 4, f"  ⚠ Found {bypasses_found} WAF bypass opportunities!")
        else:
            _log(session, 4, "  WAF appears solid — no easy bypasses in standard mode")
        bypass_results = {"output": waf_scan_output[:3000], "bypasses": bypasses_found}
    else:
        _log(session, 4, "  waf-tester not available, skipping bypass testing")

    session.results["step_4"] = {
        "waf_detected": waf_detected,
        "waf_vendor": waf_vendor,
        "real_ip": real_ip,
        "bypass_results": bypass_results,
        "bypasses_found": bypasses_found,
    }
    _log(session, 4, "[Step-4] Complete")


async def _run_step_5(session: ReconSession) -> None:
    """Step 5: Generate comprehensive summary with all recon data for the AI agent."""
    session.status = "step_5"
    session.current_step = 5

    _log(session, 5, "Building task plan from recon data...")

    parts = [f"Pre-scan reconnaissance results for {session.target}:\n"]

    # Step 1: Asset Discovery
    s1 = session.results.get("step_1", {})
    subs = s1.get("subdomains", [])
    if subs:
        parts.append(f"SUBDOMAINS ({len(subs)}): {', '.join(subs[:30])}")
    ips = s1.get("ips", [])
    if ips:
        parts.append(f"IP ADDRESSES: {', '.join(ips[:10])}")
    alive = s1.get("alive_urls", [])
    if alive:
        parts.append(f"ALIVE TARGETS ({len(alive)}): {', '.join(alive[:20])}")
    httpx_out = s1.get("httpx_output", "")
    if httpx_out:
        parts.append(f"HTTP PROBE:\n{httpx_out[:800]}")
    nmap_out = s1.get("nmap_output", "")
    if nmap_out:
        parts.append(f"PORT SCAN:\n{nmap_out[:800]}")

    # Step 2: Endpoints
    s2 = session.results.get("step_2", {})
    endpoints = s2.get("endpoints", [])
    api_eps = s2.get("api_endpoints", [])
    auth_eps = s2.get("auth_endpoints", [])
    admin_eps = s2.get("admin_endpoints", [])
    gql = s2.get("graphql", {})
    if endpoints:
        parts.append(f"DISCOVERED ENDPOINTS ({len(endpoints)} total):")
        if api_eps:
            parts.append(f"  API endpoints ({len(api_eps)}): {', '.join(api_eps[:15])}")
        if auth_eps:
            parts.append(f"  Auth endpoints ({len(auth_eps)}): {', '.join(auth_eps[:10])}")
        if admin_eps:
            parts.append(f"  Admin endpoints ({len(admin_eps)}): {', '.join(admin_eps[:10])}")
        other = [u for u in endpoints if u not in api_eps and u not in auth_eps and u not in admin_eps]
        if other:
            parts.append(f"  Other endpoints ({len(other)}): {', '.join(other[:20])}")
    if gql:
        parts.append(f"GRAPHQL: endpoint={gql.get('endpoint','')}, types={gql.get('types_count',0)}, mutations={'yes' if gql.get('has_mutations') else 'no'}")

    # JS Analysis
    js_secrets_data = s2.get("js_secrets", [])
    js_ep_data = s2.get("js_endpoints", [])
    js_dom_data = s2.get("js_domains", [])
    if js_secrets_data:
        parts.append(f"⚠ EXPOSED SECRETS IN JS ({len(js_secrets_data)}):")
        for s in js_secrets_data[:10]:
            parts.append(f"  {s.get('type','?')}: {s.get('value','?')[:40]}... (in {s.get('source','')})")
        parts.append("CRITICAL: Investigate these secrets immediately — they may grant unauthorized access.")
    if js_ep_data:
        parts.append(f"JS-DISCOVERED ENDPOINTS ({len(js_ep_data)}): {', '.join(js_ep_data[:20])}")
    if js_dom_data:
        parts.append(f"INTERNAL URLS FROM JS: {', '.join(js_dom_data[:10])}")

    # Subdomain takeover
    takeover = s1.get("takeover_candidates", [])
    if takeover:
        parts.append(f"⚠ SUBDOMAIN TAKEOVER CANDIDATES ({len(takeover)}): {', '.join(takeover[:10])}")

    # Secrets and cloud
    secrets_data = s2.get("secrets_found", [])
    cloud_data = s2.get("cloud_buckets", [])
    if secrets_data:
        parts.append(f"⚠ LEAKED SECRETS FOUND ({len(secrets_data)}): {', '.join(s.get('type','') for s in secrets_data[:5])}")
        parts.append("CRITICAL: Investigate these leaked credentials immediately.")
    if cloud_data:
        parts.append(f"CLOUD STORAGE FOUND ({len(cloud_data)}): {', '.join(cloud_data[:5])}")
        parts.append("Check: list objects, sensitive files, write permissions.")
        parts.append("CRITICAL: These subdomains may be claimable by an attacker. Verify and report immediately.")

    # Step 3: Risk Analysis
    s3 = session.results.get("step_3", {})
    nuclei_out = s3.get("nuclei_output", "")
    findings_count = s3.get("findings_count", 0)
    if findings_count > 0:
        parts.append(f"SECURITY FINDINGS ({findings_count}):\n{nuclei_out[:800]}")
    else:
        parts.append("SECURITY FINDINGS: No critical/high issues in quick scan — deeper testing needed")

    # Step 4: WAF Analysis
    s4 = session.results.get("step_4", {})
    if s4.get("waf_detected"):
        parts.append(f"WAF DETECTED: {s4.get('waf_vendor', 'Unknown')}")
        if s4.get("real_ip"):
            parts.append(f"⚠ REAL ORIGIN IP FOUND: {s4['real_ip']} — test this IP directly to bypass WAF")
        if s4.get("bypasses_found"):
            parts.append(f"WAF BYPASS: {s4['bypasses_found']} bypass opportunities found")
    else:
        parts.append("WAF: Not detected — direct access to origin server")

    summary = "\n\n".join(parts)
    session.results["step_5"] = {"summary": summary}

    _log(session, 5, f"Summary: {len(subs)} subdomains, {len(endpoints)} endpoints, {findings_count} findings")
    _log(session, 5, "[Step-5] Complete")


# ---------------------------------------------------------------------------
# Main recon runner
# ---------------------------------------------------------------------------


async def _run_recon_async(session: ReconSession) -> None:
    """Execute all recon steps."""
    try:
        # Try to create Docker sandbox
        from ziro.runtime.docker_runtime import DockerRuntime

        runtime = DockerRuntime()
        _log(session, 0, "Starting Docker sandbox...")
        sandbox_info = await runtime.create_sandbox(
            agent_id=f"recon-{session.recon_id}"
        )
        session.sandbox_info = sandbox_info
        api_url = sandbox_info["api_url"]
        token = sandbox_info["auth_token"]
        _log(session, 0, "Sandbox ready")

    except Exception as e:
        _log(session, 0, f"Docker not available: {e}")
        _log(session, 0, "Skipping reconnaissance, scan will start without recon data")
        session.docker_available = False
        session.status = "completed"
        session.completed_at = time.time()
        return

    # Run steps sequentially
    for step_fn in [_run_step_1, _run_step_2, _run_step_3, _run_step_4]:
        try:
            await step_fn(session, api_url, token)
        except Exception as e:
            _log(session, session.current_step, f"Step failed: {e}")

    # Step 5 (summary) doesn't need sandbox
    try:
        await _run_step_5(session)
    except Exception as e:
        _log(session, 5, f"Summary generation failed: {e}")

    session.status = "completed"
    session.completed_at = time.time()
    _log(session, 0, "Reconnaissance complete")


def run_recon(session: ReconSession) -> None:
    """Run recon in a new event loop (for threading)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_recon_async(session))
    except Exception as e:
        session.status = "failed"
        session.error = str(e)
        _log(session, 0, f"Recon failed: {e}")
    finally:
        loop.close()


def start_recon(target: str, target_type: str = "") -> ReconSession:
    """Create and start a new recon session in a background thread."""
    recon_id = f"recon-{uuid.uuid4().hex[:12]}"
    domain = _extract_domain(target)

    if not target_type:
        if _is_ip(domain):
            target_type = "ip_address"
        elif "://" in target:
            target_type = "web_application"
        else:
            target_type = "domain"

    session = ReconSession(
        recon_id=recon_id,
        target=target,
        target_domain=domain,
        target_type=target_type,
    )
    _recon_sessions[recon_id] = session

    thread = threading.Thread(target=run_recon, args=(session,), daemon=True)
    thread.start()

    return session


def get_recon_session(recon_id: str) -> ReconSession | None:
    return _recon_sessions.get(recon_id)
