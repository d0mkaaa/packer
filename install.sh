#!/bin/bash
set -e

REPO_URL="https://github.com/d0mkaaa/packer"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="packer"
CONFIG_DIR="$HOME/.config/packer"

print_header() {
    echo "================================================"
    echo "          Packer Installation Script"
    echo "================================================"
    echo
}

print_status() {
    echo "🔷 $1"
}

print_success() {
    echo "✅ $1"
}

print_error() {
    echo "❌ $1"
    exit 1
}

check_dependencies() {
    print_status "Checking dependencies..."
    
    if ! command -v git &> /dev/null; then
        print_error "Git is required but not installed"
    fi
    
    if ! command -v cargo &> /dev/null; then
        print_error "Rust/Cargo is required but not installed. Install from https://rustup.rs/"
    fi
    
    if ! command -v makepkg &> /dev/null; then
        print_error "makepkg is required but not installed. This tool is for Arch Linux only."
    fi
    
    print_success "All dependencies found"
}

check_rust_version() {
    print_status "Checking Rust version..."
    
    RUST_VERSION=$(rustc --version | awk '{print $2}' | cut -d'.' -f1,2)
    REQUIRED_VERSION="1.75"
    
    if ! awk "BEGIN {exit !($RUST_VERSION >= $REQUIRED_VERSION)}"; then
        print_error "Rust $REQUIRED_VERSION or higher is required. Current version: $RUST_VERSION"
    fi
    
    print_success "Rust version is compatible"
}

clone_repository() {
    print_status "Cloning repository..."
    
    if [ -d "packer" ]; then
        rm -rf packer
    fi
    
    git clone "$REPO_URL"
    cd packer
    
    print_success "Repository cloned"
}

build_binary() {
    print_status "Building Packer (this may take a few minutes)..."
    
    cargo build --release
    
    if [ ! -f "target/release/$BINARY_NAME" ]; then
        print_error "Build failed - binary not found"
    fi
    
    print_success "Build completed"
}

install_binary() {
    print_status "Installing binary to $INSTALL_DIR..."
    
    if [ ! -w "$INSTALL_DIR" ]; then
        print_status "Installing with sudo (requires admin privileges)..."
        sudo cp "target/release/$BINARY_NAME" "$INSTALL_DIR/"
        sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
    else
        cp "target/release/$BINARY_NAME" "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/$BINARY_NAME"
    fi
    
    print_success "Binary installed"
}

create_config_dir() {
    print_status "Creating configuration directory..."
    
    mkdir -p "$CONFIG_DIR"
    
    if [ ! -f "$CONFIG_DIR/config.toml" ]; then
        cat > "$CONFIG_DIR/config.toml" << 'EOF'
[repositories]
arch_official = { enabled = true, url = "https://archlinux.org/packages/" }
aur = { enabled = true, url = "https://aur.archlinux.org" }

[settings]
parallel_downloads = 4
auto_confirm = false
check_signatures = true
cache_dir = "~/.cache/packer"

[security]
gpg_verify = true
checksum_verify = true
max_package_size = "1GB"
EOF
        print_success "Default configuration created"
    else
        print_success "Configuration directory exists"
    fi
}

verify_installation() {
    print_status "Verifying installation..."
    
    if ! command -v packer &> /dev/null; then
        print_error "Installation verification failed - packer command not found"
    fi
    
    VERSION_OUTPUT=$(packer --version 2>/dev/null || echo "failed")
    if [ "$VERSION_OUTPUT" = "failed" ]; then
        print_error "Installation verification failed - packer command failed"
    fi
    
    print_success "Installation verified"
}

cleanup() {
    if [ -d "../packer" ]; then
        cd ..
        rm -rf packer
        print_success "Cleanup completed"
    fi
}

print_completion() {
    echo
    echo "================================================"
    echo "          Installation Complete! 🎉"
    echo "================================================"
    echo
    echo "Next steps:"
    echo "1. Run 'packer --help' to see available commands"
    echo "2. Try 'packer search firefox' to test search"
    echo "3. Configure repositories with 'packer repos'"
    echo "4. Edit config at: $CONFIG_DIR/config.toml"
    echo
    echo "Documentation:"
    echo "- README: https://github.com/d0mkaaa/packer#readme"
    echo "- Issues: https://github.com/d0mkaaa/packer/issues"
    echo
}

main() {
    print_header
    
    check_dependencies
    check_rust_version
    
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    clone_repository
    build_binary
    install_binary
    create_config_dir
    verify_installation
    
    cd /
    rm -rf "$TEMP_DIR"
    
    print_completion
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi 