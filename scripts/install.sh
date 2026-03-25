#!/usr/bin/env bash

set -euo pipefail

REPO="Xyeino/ziro"
INSTALL_DIR="$HOME/.ziro"
VENV_DIR="$INSTALL_DIR/venv"
BIN_DIR="$INSTALL_DIR/bin"

MUTED='\033[0;2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- checks ---

if [ "$(uname -s)" != "Linux" ]; then
    echo -e "${RED}Ziro only supports Linux.${NC}"
    exit 1
fi

for cmd in python3 pip git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo -e "${RED}Error: '$cmd' is required but not installed.${NC}"
        exit 1
    fi
done

python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if python3 -c "import sys; exit(0 if sys.version_info >= (3,12) else 1)" 2>/dev/null; then
    :
else
    echo -e "${RED}Python 3.12+ required. Found: $python_version${NC}"
    exit 1
fi

# --- install ---

echo ""
echo -e "${CYAN}⚡ Installing Ziro${NC}"
echo ""

# clean previous install
if [ -d "$VENV_DIR" ]; then
    echo -e "${MUTED}Removing previous installation...${NC}"
    rm -rf "$VENV_DIR"
fi

# create venv
echo -e "${MUTED}Creating virtual environment...${NC}"
python3 -m venv "$VENV_DIR"

# install from github
echo -e "${MUTED}Installing ziro-agent from GitHub...${NC}"
"$VENV_DIR/bin/pip" install --quiet "git+https://github.com/$REPO.git"

# create bin wrapper
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/ziro" << 'WRAPPER'
#!/usr/bin/env bash
exec "$HOME/.ziro/venv/bin/ziro" "$@"
WRAPPER
chmod +x "$BIN_DIR/ziro"

echo -e "${GREEN}✓ Ziro installed to $INSTALL_DIR${NC}"

# --- PATH setup ---

add_to_path() {
    local config_file=$1
    local command=$2

    if grep -Fxq "$command" "$config_file" 2>/dev/null; then
        return
    elif [[ -w $config_file ]]; then
        echo -e "\n# ziro" >> "$config_file"
        echo "$command" >> "$config_file"
        echo -e "${MUTED}Added ziro to PATH in ${NC}$config_file"
    fi
}

current_shell=$(basename "${SHELL:-bash}")

case $current_shell in
    fish)
        config_file="$HOME/.config/fish/config.fish"
        path_cmd="fish_add_path $BIN_DIR"
        ;;
    zsh)
        config_file="${ZDOTDIR:-$HOME}/.zshrc"
        path_cmd="export PATH=$BIN_DIR:\$PATH"
        ;;
    *)
        config_file="$HOME/.bashrc"
        [ ! -f "$config_file" ] && config_file="$HOME/.profile"
        path_cmd="export PATH=$BIN_DIR:\$PATH"
        ;;
esac

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    if [ -f "$config_file" ]; then
        add_to_path "$config_file" "$path_cmd"
    else
        echo -e "${YELLOW}Add to PATH manually:${NC} $path_cmd"
    fi
fi

if [ -n "${GITHUB_ACTIONS-}" ] && [ "${GITHUB_ACTIONS}" = "true" ]; then
    echo "$BIN_DIR" >> "$GITHUB_PATH"
fi

# --- docker check ---

echo ""
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Docker not found${NC}"
    echo -e "${MUTED}Ziro requires Docker for the sandbox. Install: https://docs.docker.com/get-docker/${NC}"
elif ! docker info >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Docker daemon not running${NC}"
else
    echo -e "${GREEN}✓ Docker detected${NC}"
fi

# --- verify ---

export PATH="$BIN_DIR:$PATH"
version=$("$BIN_DIR/ziro" --version 2>/dev/null | awk '{print $2}' || echo "1.0.0")

echo ""
echo -e "${CYAN}"
echo "   ███████╗██╗██████╗  ██████╗ "
echo "   ╚══███╔╝██║██╔══██╗██╔═══██╗"
echo "     ███╔╝ ██║██████╔╝██║   ██║"
echo "    ███╔╝  ██║██╔══██╗██║   ██║"
echo "   ███████╗██║██║  ██║╚██████╔╝"
echo "   ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ "
echo -e "${NC}"
echo -e "  ${GREEN}v${version}${NC} ${MUTED}— AI Penetration Testing Agent${NC}"
echo ""
echo -e "  ${CYAN}1.${NC} Configure:"
echo -e "     ${MUTED}export ZIRO_LLM='openai/gpt-5.4'${NC}"
echo -e "     ${MUTED}export LLM_API_KEY='your-api-key'${NC}"
echo ""
echo -e "  ${CYAN}2.${NC} Scan:"
echo -e "     ${MUTED}ziro --target https://example.com${NC}"
echo ""
echo -e "${YELLOW}→${NC} Run ${MUTED}source ~/.$( basename "${SHELL:-bash}" )rc${NC} or open a new terminal"
echo ""
