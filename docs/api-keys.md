# API Keys Configuration

Adding API keys improves Ziro's capabilities. All keys are optional — Ziro works without them, but results improve significantly with keys.

---

## LLM Provider (Required — pick one)

### Option A: ChatGPT Subscription (Recommended — no API costs)

```bash
export ZIRO_LLM="chatgpt/gpt-5.4"
```

Uses your ChatGPT Plus ($20/mo) or Pro ($200/mo) subscription. First run will ask you to authorize via browser.

### Option B: Anthropic Claude API

```bash
export ZIRO_LLM="anthropic/claude-sonnet-4-20250514"
export LLM_API_KEY="sk-ant-api03-..."
```

Get key: https://console.anthropic.com/settings/keys

### Option C: OpenAI API

```bash
export ZIRO_LLM="openai/gpt-4o"
export LLM_API_KEY="sk-proj-..."
```

Get key: https://platform.openai.com/api-keys

---

## Subdomain Discovery Keys (Optional, Free)

These go into the Docker container's subfinder config. Each one adds more subdomain sources.

### SecurityTrails (Best free source)
- **Free**: 50 requests/month
- **Sign up**: https://securitytrails.com/app/signup
- After signup, API key is on the dashboard

### Shodan
- **Free**: 100 queries/month
- **Sign up**: https://account.shodan.io/register
- Key at: https://account.shodan.io

### VirusTotal
- **Free**: 500 requests/day (generous!)
- **Sign up**: https://www.virustotal.com/gui/join-us
- Key at: Profile → API Key

### Censys
- **Free**: 250 queries/month
- **Sign up**: https://search.censys.io/register
- Uses `API_ID:API_SECRET` format (colon-separated)
- Keys at: https://search.censys.io/account/api

### BinaryEdge
- **Free**: 250 requests/month
- **Sign up**: https://app.binaryedge.io/sign-up
- Key at: https://app.binaryedge.io/account/api

### GitHub Personal Access Token
- **Free**: Unlimited
- **Create**: https://github.com/settings/tokens
- Create a "Fine-grained" token with NO scopes (public access only)
- Multiple tokens supported for rate limiting

### FullHunt
- **Free**: 100 queries/month
- **Sign up**: https://fullhunt.io/sign-up

### Chaos (ProjectDiscovery)
- **Free**: For security researchers
- **Sign up**: https://chaos.projectdiscovery.io/

---

## How to Add Subfinder Keys

### Quick method (lost on container restart):

```bash
# Find your running container
docker ps | grep ziro

# Enter it
docker exec -it ziro-scan-XXXX bash

# Write config
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/provider-config.yaml << 'EOF'
securitytrails:
  - YOUR_KEY_HERE
shodan:
  - YOUR_KEY_HERE
virustotal:
  - YOUR_KEY_HERE
censys:
  - YOUR_ID:YOUR_SECRET
github:
  - ghp_YOUR_TOKEN
EOF
```

### Persistent method (survives rebuilds):

1. Create file `containers/subfinder-config.yaml`:

```yaml
securitytrails:
  - YOUR_KEY_HERE
shodan:
  - YOUR_KEY_HERE
virustotal:
  - YOUR_KEY_HERE
censys:
  - YOUR_ID:YOUR_SECRET
binaryedge:
  - YOUR_KEY_HERE
github:
  - ghp_YOUR_TOKEN_1
  - ghp_YOUR_TOKEN_2
fullhunt:
  - YOUR_KEY_HERE
```

2. Add to `containers/Dockerfile` (before the ENTRYPOINT line):

```dockerfile
COPY containers/subfinder-config.yaml /home/pentester/.config/subfinder/provider-config.yaml
```

3. Rebuild:

```bash
docker build -t ziro-sandbox containers/
```

---

## Web Search Key (Optional)

Enables the `web_search` tool for agents to search the internet during scans.

### Perplexity API
- **Pricing**: Pay-per-use
- **Sign up**: https://www.perplexity.ai/settings/api
- ```bash
  export PERPLEXITY_API_KEY="pplx-..."
  ```

---

## Verify Keys Are Working

After adding subfinder keys, test inside the container:

```bash
docker exec -it ziro-scan-XXXX bash
subfinder -d example.com -all -silent | wc -l
```

Without keys: ~5-10 subdomains. With keys: ~50-500+ subdomains.
