#!/usr/bin/env bash
# REAPER installer for GNU/Linux
set -euo pipefail

RED='\033[0;31m' GRN='\033[0;32m' YEL='\033[1;33m' CYN='\033[0;36m' NC='\033[0m'
info()  { echo -e "${CYN}[*]${NC} $*"; }
ok()    { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YEL}[!]${NC} $*"; }
err()   { echo -e "${RED}[!]${NC} $*" >&2; }

REAPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── System check ─────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && warn "Not running as root — system tool installation will be skipped"
[[ "$(uname -s)" != "Linux" ]] && { err "REAPER is designed for GNU/Linux"; exit 1; }

python_bin=""
for py in python3.11 python3.12 python3.13 python3; do
    if command -v "$py" &>/dev/null; then
        ver=$("$py" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null)
        if "$py" -c 'import sys; assert sys.version_info >= (3,11)' 2>/dev/null; then
            python_bin="$py"; break
        fi
    fi
done
[[ -z "$python_bin" ]] && { err "Python 3.11+ is required. Install it first."; exit 1; }
ok "Python: $("$python_bin" --version)"

# ── Python dependencies ───────────────────────────────────────────────────────
info "Installing REAPER (pip install -e .) …"
"$python_bin" -m pip install --quiet --upgrade pip
"$python_bin" -m pip install --quiet -e "$REAPER_DIR"
ok "REAPER Python package installed"

# ── Optional Go-based tools (root or in PATH) ─────────────────────────────────
if [[ "$EUID" -eq 0 ]]; then
    apt_install() {
        info "apt install $1"
        apt-get install -y --no-install-recommends "$1" &>/dev/null && ok "  $1 installed" || warn "  $1 not in apt — install manually"
    }
    for pkg in nmap masscan hydra nikto; do
        command -v "$pkg" &>/dev/null || apt_install "$pkg"
    done
fi

install_go_tool() {
    local name="$1" url="$2"
    if command -v "$name" &>/dev/null; then
        ok "  $name already in PATH"
        return
    fi
    if command -v go &>/dev/null; then
        info "  go install $url …"
        go install "$url" &>/dev/null && ok "  $name installed" || warn "  $name install failed — install manually"
    else
        warn "  $name not found and Go not installed — skip"
    fi
}

info "Checking Go-based tools …"
install_go_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
install_go_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
install_go_tool "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
install_go_tool "katana"     "github.com/projectdiscovery/katana/cmd/katana@latest"
install_go_tool "ffuf"       "github.com/ffuf/ffuf/v2@latest"
install_go_tool "dalfox"     "github.com/hahwul/dalfox/v2@latest"
install_go_tool "kerbrute"   "github.com/ropnop/kerbrute@latest"

info "Checking Python-based tools …"
pip_install() {
    local name="$1" pkg="${2:-$1}"
    command -v "$name" &>/dev/null && { ok "  $name already in PATH"; return; }
    info "  pip install $pkg …"
    "$python_bin" -m pip install --quiet "$pkg" && ok "  $name installed" || warn "  $name install failed"
}
pip_install "trufflehog"    "trufflehog"  # note: official binary preferred
pip_install "bloodhound-python" "bloodhound"
pip_install "certipy"       "certipy-ad"
pip_install "netexec"       "netexec"
pip_install "prowler"       "prowler"
pip_install "pacu"          "pacu"

# ── Nuclei templates ──────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
    info "Updating Nuclei templates …"
    nuclei -update-templates &>/dev/null && ok "Nuclei templates updated" || warn "Nuclei template update failed"
fi

# ── Final ─────────────────────────────────────────────────────────────────────
echo ""
ok "REAPER installed successfully!"
echo ""
echo "  Quick start:"
echo "    reaper session new my-pentest 192.168.1.0/24"
echo "    reaper run auto"
echo "    reaper findings"
echo "    reaper report"
echo "    reaper web"
echo ""
