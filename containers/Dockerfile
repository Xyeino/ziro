FROM kalilinux/kali-rolling:latest

LABEL description="AI Agent Penetration Testing Environment with Comprehensive Automated Tools"

RUN apt-get update && \
    apt-get install -y kali-archive-keyring sudo && \
    apt-get update && \
    apt-get upgrade -y

RUN useradd -m -s /bin/bash pentester && \
    usermod -aG sudo pentester && \
    echo "pentester ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    touch /home/pentester/.hushlogin

RUN mkdir -p /home/pentester/configs \
             /home/pentester/wordlists \
             /home/pentester/output \
             /home/pentester/scripts \
             /home/pentester/tools \
             /app/runtime \
             /app/tools \
             /app/certs && \
    chown -R pentester:pentester /app/certs /home/pentester/tools

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl git vim nano unzip tar \
    apt-transport-https ca-certificates gnupg lsb-release \
    build-essential software-properties-common \
    gcc libc6-dev pkg-config libpcap-dev libssl-dev \
    python3 python3-pip python3-dev python3-venv python3-setuptools \
    golang-go \
    net-tools dnsutils whois \
    jq parallel ripgrep grep \
    less man-db procps htop \
    iproute2 iputils-ping netcat-traditional \
    nmap ncat ndiff masscan nikto hydra \
    sqlmap nuclei subfinder naabu ffuf amass \
    nodejs npm pipx traceroute \
    libcap2-bin \
    gdb \
    tmux \
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libatspi2.0-0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libpango-1.0-0 libcairo2 libasound2t64 \
    fonts-unifont fonts-noto-color-emoji fonts-freefont-ttf fonts-dejavu-core ttf-bitstream-vera \
    libnss3-tools


RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

USER pentester
RUN openssl ecparam -name prime256v1 -genkey -noout -out /app/certs/ca.key && \
    openssl req -x509 -new -key /app/certs/ca.key \
    -out /app/certs/ca.crt \
    -days 3650 \
    -subj "/C=US/ST=CA/O=Security Testing/CN=Testing Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" && \
    openssl pkcs12 -export \
    -out /app/certs/ca.p12 \
    -inkey /app/certs/ca.key \
    -in /app/certs/ca.crt \
    -passout pass:"" \
    -name "Testing Root CA" && \
    chmod 644 /app/certs/ca.crt && \
    chmod 600 /app/certs/ca.key && \
    chmod 600 /app/certs/ca.p12

USER root
RUN cp /app/certs/ca.crt /usr/local/share/ca-certificates/ca.crt && \
    update-ca-certificates

RUN curl -sSL https://install.python-poetry.org | POETRY_HOME=/opt/poetry python3 - && \
    ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry && \
    chmod +x /usr/local/bin/poetry && \
    python3 -m venv /app/venv && \
    chown -R pentester:pentester /app/venv /opt/poetry

USER pentester
WORKDIR /tmp

RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/cvemap/cmd/vulnx@latest && \
    go install -v github.com/jaeles-project/gospider@latest && \
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest && \
    go install -v github.com/tsenart/vegeta@latest

RUN nuclei -update-templates

RUN pipx install arjun && \
    pipx install dirsearch && \
    pipx inject dirsearch setuptools && \
    pipx install wafw00f

RUN pip install --break-system-packages theHarvester commix XSStrike slither-analyzer

ENV NPM_CONFIG_PREFIX=/home/pentester/.npm-global
RUN mkdir -p /home/pentester/.npm-global

RUN npm install -g retire@latest && \
    npm install -g eslint@latest && \
    npm install -g js-beautify@latest && \
    npm install -g @waftester/cli@latest

WORKDIR /home/pentester/tools
RUN git clone https://github.com/aravind0x7/JS-Snooper.git && \
    chmod +x JS-Snooper/js_snooper.sh && \
    git clone https://github.com/xchopath/jsniper.sh.git && \
    chmod +x jsniper.sh/jsniper.sh && \
    git clone https://github.com/ticarpi/jwt_tool.git && \
    chmod +x jwt_tool/jwt_tool.py

USER root

RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks (secret scanning)
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.27.2_linux_${ARCH}.tar.gz" | tar xz -C /usr/local/bin gitleaks || true

# Mobile reverse engineering — jadx + apktool for APK decompile
RUN apt-get update && apt-get install -y --no-install-recommends default-jre-headless && \
    rm -rf /var/lib/apt/lists/*

# jadx — fetch latest release tag dynamically (asset name embeds version)
RUN set -eux; \
    mkdir -p /opt/jadx; \
    JADX_VER=$(curl -fsSL https://api.github.com/repos/skylot/jadx/releases/latest | grep '"tag_name"' | head -1 | sed -E 's/.*"v?([^"]+)".*/\1/'); \
    JADX_VER="${JADX_VER:-1.5.5}"; \
    echo "Installing jadx ${JADX_VER}"; \
    curl -fsSL --retry 3 "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" -o /tmp/jadx.zip; \
    test -s /tmp/jadx.zip; \
    unzip -q -o /tmp/jadx.zip -d /opt/jadx; \
    chmod +x /opt/jadx/bin/jadx; \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    rm /tmp/jadx.zip; \
    /usr/local/bin/jadx --version || true

# apktool — also fetch latest dynamically
RUN set -eux; \
    APKTOOL_VER=$(curl -fsSL https://api.bitbucket.org/2.0/repositories/iBotPeaches/apktool/downloads/ 2>/dev/null | grep -oE 'apktool_[0-9]+\.[0-9]+\.[0-9]+\.jar' | head -1 | sed -E 's/apktool_([0-9.]+)\.jar/\1/' || echo ""); \
    APKTOOL_VER="${APKTOOL_VER:-2.10.0}"; \
    echo "Installing apktool ${APKTOOL_VER}"; \
    curl -fsSL --retry 3 "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VER}.jar" -o /usr/local/bin/apktool.jar; \
    test -s /usr/local/bin/apktool.jar; \
    curl -fsSL --retry 3 https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /usr/local/bin/apktool; \
    chmod +x /usr/local/bin/apktool; \
    /usr/local/bin/apktool --version || true

# Frida + objection for dynamic mobile analysis
RUN pip install --break-system-packages frida-tools objection || true

RUN apt-get update && apt-get install -y zaproxy

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN apt-get install -y wapiti

# Feroxbuster (fast Rust content discovery)
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin

# Sliver C2 client (post-exploitation command & control)
# Installs the client binary only — the team server is optional and runs in
# a separate docker-compose service when ZIRO_SLIVER_SERVER_URL is set.
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) SLIVER_ARCH=linux ;; \
        arm64) SLIVER_ARCH=linux-arm64 ;; \
        *) SLIVER_ARCH=linux ;; \
    esac && \
    curl -sSfL "https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_${SLIVER_ARCH}" \
        -o /usr/local/bin/sliver-client && \
    chmod +x /usr/local/bin/sliver-client || true

USER pentester


RUN pipx install semgrep && \
    pipx install bandit

RUN npm install -g jshint

USER root

RUN apt-get autoremove -y && \
    apt-get autoclean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENV PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:/app/venv/bin:$PATH"
ENV VIRTUAL_ENV="/app/venv"
ENV POETRY_HOME="/opt/poetry"

WORKDIR /app

RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        CAIDO_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then \
        CAIDO_ARCH="aarch64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    wget -O caido-cli.tar.gz https://caido.download/releases/v0.48.0/caido-cli-v0.48.0-linux-${CAIDO_ARCH}.tar.gz && \
    tar -xzf caido-cli.tar.gz && \
    chmod +x caido-cli && \
    rm caido-cli.tar.gz && \
    mv caido-cli /usr/local/bin/

ENV ZIRO_SANDBOX_MODE=true
ENV PYTHONPATH=/app
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN mkdir -p /workspace && chown -R pentester:pentester /workspace /app

COPY pyproject.toml poetry.lock ./

USER pentester
RUN poetry install --no-root --without dev --extras sandbox

# Install Camoufox (anti-detect Firefox) — preferred for bypassing WAF/captcha
# Falls back to Playwright Chromium if Camoufox is not available
RUN /app/venv/bin/pip install camoufox && \
    /app/venv/bin/python -m camoufox fetch || true
# Also keep Playwright Chromium as fallback
RUN poetry run playwright install chromium

RUN /app/venv/bin/pip install -r /home/pentester/tools/jwt_tool/requirements.txt && \
    ln -s /home/pentester/tools/jwt_tool/jwt_tool.py /home/pentester/.local/bin/jwt_tool

RUN echo "# Sandbox Environment" > README.md

COPY ziro/__init__.py ziro/
COPY ziro/config/ /app/ziro/config/
COPY ziro/utils/ /app/ziro/utils/
COPY ziro/telemetry/ /app/ziro/telemetry/
COPY ziro/runtime/tool_server.py ziro/runtime/__init__.py ziro/runtime/runtime.py /app/ziro/runtime/
COPY ziro/tools/ /app/ziro/tools/

# Modules imported by tools at runtime — must all be present in sandbox
# or imports fail with `No module named 'ziro.X'` and tools crash.
COPY ziro/engagement/ /app/ziro/engagement/
COPY ziro/knowledge_graph/ /app/ziro/knowledge_graph/
COPY ziro/vector_memory/ /app/ziro/vector_memory/
COPY ziro/persistence/ /app/ziro/persistence/
COPY ziro/scope/ /app/ziro/scope/
COPY ziro/dryrun/ /app/ziro/dryrun/
COPY ziro/payloads/ /app/ziro/payloads/
COPY ziro/skills/ /app/ziro/skills/
COPY ziro/personas/ /app/ziro/personas/
COPY ziro/threat_actors/ /app/ziro/threat_actors/
COPY ziro/playbooks/ /app/ziro/playbooks/

RUN echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.bashrc && \
    echo 'export PATH="/home/pentester/go/bin:/home/pentester/.local/bin:/home/pentester/.npm-global/bin:$PATH"' >> /home/pentester/.profile

USER root
COPY containers/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER pentester
WORKDIR /workspace

ENTRYPOINT ["docker-entrypoint.sh"]
