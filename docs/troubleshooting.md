# Troubleshooting

## Common Issues

### Panel won't start: "the following arguments are required: -t/--target"

The installed package is outdated. Reinstall:

```bash
cd ~/ziro && poetry install
# Then retry:
poetry run ziro --panel
```

### Poetry lock error: "lock file might not be compatible"

```bash
cd ~/ziro && poetry lock --no-update && poetry install
```

### Frontend not building

```bash
# Make sure Node.js 20+ is installed
node --version

# If not installed:
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Then build:
cd ziro/panel/frontend && npm install && npx vite build
```

### Docker containers not stopping after Ctrl+C

Force cleanup:

```bash
docker ps -q --filter name=ziro-scan- | xargs -r docker rm -f
```

### Chromium processes lingering

```bash
pkill -f "chromium.*headless"
pkill -f "camoufox"
```

### ChatGPT provider: "device code" not appearing

Make sure `ZIRO_LLM` is set correctly:

```bash
export ZIRO_LLM="chatgpt/gpt-5.4"
```

The device code appears in the terminal when the first LLM call is made (when a scan starts, not when the panel launches).

### Pydantic serialization warnings

These are harmless warnings from the ChatGPT provider. They're suppressed in the latest version. Update:

```bash
cd ~/ziro && git pull && poetry install
```

### Subdomains showing shell prompts ([ZIRO_0]$)

Update to the latest version — this is fixed:

```bash
cd ~/ziro && git pull
```

### Screenshots not loading

Screenshots are captured during the recon phase (before AI agent starts). If you skipped recon or it failed, screenshots won't be available. The gradient placeholder is shown instead.

### Attack Surface graph empty

The graph auto-generates from agent activity. If the scan just started, wait for agents to execute tools — nodes will appear automatically.

### Port 8420 already in use

```bash
# Find what's using it
lsof -i :8420

# Kill it
kill -9 <PID>

# Or use a different port
poetry run ziro --panel --panel-port 8421
```

---

## Performance

### Scan is slow

- Use **Quick Scan** mode for fast results
- ChatGPT subscription can be slower than direct API — try `openai/gpt-4o` with API key
- Check Docker container resources: `docker stats`

### High memory usage

Multiple Chromium instances can consume RAM. The panel cleanup kills them on Ctrl+C. If you see orphaned processes:

```bash
# Inside the container
docker exec -it ziro-scan-XXXX bash
ps aux | grep chrom | wc -l
pkill -f chromium
```

---

## Getting Help

- Check panel logs in the terminal where you ran `poetry run ziro --panel`
- Agent Terminal tab shows real-time agent activity
- HTTP Log tab shows all tool executions
