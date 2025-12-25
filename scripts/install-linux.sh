#!/bin/bash
# install-linux.sh - Linux installation script for agentsh
#
# Usage:
#   curl -fsSL https://get.agentsh.dev/linux | bash
#   ./install-linux.sh [version]
#
# Environment variables:
#   AGENTSH_VERSION - version to install (default: latest)
#   AGENTSH_INSTALL_DIR - installation directory (default: /usr/local/bin)

set -e

VERSION="${AGENTSH_VERSION:-${1:-latest}}"
INSTALL_DIR="${AGENTSH_INSTALL_DIR:-/usr/local/bin}"
GITHUB_REPO="agentsh/agentsh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if running as root for system-wide install
check_privileges() {
    if [[ "$INSTALL_DIR" == "/usr/local/bin" ]] && [[ $EUID -ne 0 ]]; then
        error "Installation to $INSTALL_DIR requires root privileges."
        error "Run with sudo or set AGENTSH_INSTALL_DIR to a user directory."
        exit 1
    fi
}

# Detect package manager
detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v zypper &> /dev/null; then
        echo "zypper"
    elif command -v apk &> /dev/null; then
        echo "apk"
    else
        echo "unknown"
    fi
}

# Check and install FUSE3
check_fuse() {
    if command -v fusermount3 &> /dev/null; then
        info "FUSE3 is already installed"
        return 0
    fi

    info "Installing FUSE3..."
    local pm=$(detect_package_manager)

    case $pm in
        apt)
            sudo apt-get update
            sudo apt-get install -y fuse3 libfuse3-dev
            ;;
        dnf)
            sudo dnf install -y fuse3 fuse3-devel
            ;;
        yum)
            sudo yum install -y fuse3 fuse3-devel
            ;;
        pacman)
            sudo pacman -S --noconfirm fuse3
            ;;
        zypper)
            sudo zypper install -y fuse3 fuse3-devel
            ;;
        apk)
            sudo apk add fuse3 fuse3-dev
            ;;
        *)
            warn "Unknown package manager. Please install fuse3 manually."
            return 1
            ;;
    esac

    info "FUSE3 installed successfully"
}

# Check and install iptables
check_iptables() {
    if command -v iptables &> /dev/null; then
        info "iptables is already installed"
        return 0
    fi

    info "Installing iptables..."
    local pm=$(detect_package_manager)

    case $pm in
        apt)
            sudo apt-get install -y iptables
            ;;
        dnf)
            sudo dnf install -y iptables
            ;;
        yum)
            sudo yum install -y iptables
            ;;
        pacman)
            sudo pacman -S --noconfirm iptables
            ;;
        zypper)
            sudo zypper install -y iptables
            ;;
        apk)
            sudo apk add iptables
            ;;
        *)
            warn "Unknown package manager. Please install iptables manually."
            return 1
            ;;
    esac

    info "iptables installed successfully"
}

# Check cgroups v2
check_cgroups() {
    if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
        info "cgroups v2 is available"
    else
        warn "cgroups v2 not detected. Resource limits may be limited."
    fi
}

# Detect system architecture
detect_arch() {
    local arch=$(uname -m)

    case $arch in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        armv7l|armv7)
            echo "arm"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Get the latest version from GitHub
get_latest_version() {
    local latest
    latest=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$latest" ]]; then
        error "Failed to fetch latest version"
        exit 1
    fi

    echo "$latest"
}

# Download and install agentsh
install_agentsh() {
    local version="$VERSION"
    local arch=$(detect_arch)

    if [[ "$version" == "latest" ]]; then
        version=$(get_latest_version)
    fi

    info "Installing agentsh ${version} for linux/${arch}..."

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/agentsh-linux-${arch}"
    local tmp_file="/tmp/agentsh-$$"

    if ! curl -fsSL "$download_url" -o "$tmp_file"; then
        error "Failed to download agentsh from ${download_url}"
        exit 1
    fi

    chmod +x "$tmp_file"

    # Create install directory if it doesn't exist
    if [[ ! -d "$INSTALL_DIR" ]]; then
        mkdir -p "$INSTALL_DIR"
    fi

    # Move to install directory
    if [[ $EUID -eq 0 ]] || [[ -w "$INSTALL_DIR" ]]; then
        mv "$tmp_file" "${INSTALL_DIR}/agentsh"
    else
        sudo mv "$tmp_file" "${INSTALL_DIR}/agentsh"
    fi

    info "agentsh installed to ${INSTALL_DIR}/agentsh"
}

# Download and install envshim helper
install_envshim() {
    local version="$VERSION"
    local arch=$(detect_arch)

    if [[ "$version" == "latest" ]]; then
        version=$(get_latest_version)
    fi

    info "Installing envshim helper..."

    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/envshim-linux-${arch}"
    local tmp_file="/tmp/envshim-$$"

    if curl -fsSL "$download_url" -o "$tmp_file" 2>/dev/null; then
        chmod +x "$tmp_file"

        if [[ $EUID -eq 0 ]] || [[ -w "$INSTALL_DIR" ]]; then
            mv "$tmp_file" "${INSTALL_DIR}/envshim"
        else
            sudo mv "$tmp_file" "${INSTALL_DIR}/envshim"
        fi

        info "envshim installed to ${INSTALL_DIR}/envshim"
    else
        warn "envshim not available for this release (optional component)"
    fi
}

# Verify installation
verify_installation() {
    if command -v agentsh &> /dev/null; then
        info "Verification successful!"
        agentsh version 2>/dev/null || true
    else
        warn "agentsh not found in PATH. You may need to add ${INSTALL_DIR} to your PATH."
    fi
}

# Print post-install instructions
print_instructions() {
    echo ""
    echo "============================================"
    echo "  agentsh installed successfully!"
    echo "============================================"
    echo ""
    echo "Quick start:"
    echo "  agentsh server        # Start the agentsh server"
    echo "  agentsh status        # Check server status"
    echo "  agentsh --help        # Show available commands"
    echo ""
    echo "Configuration:"
    echo "  Default config: ~/.config/agentsh/config.yml"
    echo "  Default policy: ~/.config/agentsh/policy.yml"
    echo ""
    echo "Documentation:"
    echo "  https://github.com/${GITHUB_REPO}"
    echo ""
}

# Main installation flow
main() {
    echo "agentsh Linux Installer"
    echo "======================="
    echo ""

    check_privileges

    info "Checking prerequisites..."
    check_fuse
    check_iptables
    check_cgroups

    echo ""
    install_agentsh
    install_envshim

    echo ""
    verify_installation
    print_instructions
}

main "$@"
