# Packer Setup Guide

This guide will help you set up the Packer project for development, testing, or deployment.

## 📋 Prerequisites

Before setting up Packer, ensure you have:

### Required
- **Arch Linux** (current target platform)
- **Rust 1.88+** - Install from [rustup.rs](https://rustup.rs/)
- **Git** - For cloning and version control
- **makepkg** - For building AUR packages (usually pre-installed on Arch)

### Development Tools (Optional)
- **VS Code** or **RustRover** - For development
- **cargo-audit** - For security auditing
- **cargo-clippy** - For linting (included with Rust)
- **cargo-fmt** - For formatting (included with Rust)

## 🚀 Quick Setup

### For Users (Installation)

```bash
# Clone the repository
git clone https://github.com/d0mkaaa/packer.git
cd packer

# Run the installation script
chmod +x install.sh
./install.sh
```

The install script will:
- Check all dependencies
- Build the project
- Install the binary to `/usr/local/bin`
- Create default configuration
- Verify the installation

### For Developers

```bash
# Clone the repository
git clone https://github.com/d0mkaaa/packer.git
cd packer

# Install Rust components
rustup component add rustfmt clippy

# Build and test
cargo build
cargo test

# Run the project
cargo run -- --help
```

## 🔧 Manual Setup

### 1. Clone the Repository

```bash
git clone https://github.com/d0mkaaa/packer.git
cd packer
```

### 2. Install Dependencies

```bash
# Ensure Rust is installed and up to date
rustup update

# Install additional tools
cargo install cargo-audit
```

### 3. Build the Project

```bash
# Debug build (faster compilation)
cargo build

# Release build (optimized)
cargo build --release
```

### 4. Run Tests

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific tests
cargo test search
```

### 5. Install Binary (Optional)

```bash
# Install to system
sudo cp target/release/packer /usr/local/bin/

# Or add to PATH
export PATH="$PWD/target/release:$PATH"
```

## ⚙️ Configuration

### Default Configuration

Packer will create a default configuration at `~/.config/packer/config.toml`:

```toml
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
```

### Custom Configuration

Edit the configuration file to customize behavior:

```bash
# Edit configuration
$EDITOR ~/.config/packer/config.toml

# Test configuration
packer repos
```

## 🧪 Testing

### Basic Functionality Test

```bash
# Test help system
./target/release/packer --help

# Test search functionality
./target/release/packer search firefox

# Test repository listing
./target/release/packer repos
```

### Security Features Test

```bash
# Test security commands
./target/release/packer security --help

# Run security audit
./target/release/packer security audit
```

## 🔍 Development Workflow

### 1. Make Changes

```bash
# Create a feature branch
git checkout -b feature/my-feature

# Make your changes
$EDITOR src/main.rs
```

### 2. Test Changes

```bash
# Format code
cargo fmt

# Check for issues
cargo clippy

# Run tests
cargo test

# Test manually
cargo run -- search firefox
```

### 3. Commit Changes

```bash
# Add changes
git add .

# Commit with descriptive message
git commit -m "feat: add new search feature"

# Push to your fork
git push origin feature/my-feature
```

## 📁 Project Structure

```
packer/
├── src/                    # Source code
│   ├── main.rs            # CLI entry point
│   ├── lib.rs             # Library exports
│   ├── config.rs          # Configuration management
│   ├── package.rs         # Package operations
│   ├── repository.rs      # Repository management
│   ├── resolver.rs        # Dependency resolution
│   ├── storage.rs         # Database and storage
│   ├── error.rs           # Error handling
│   ├── utils.rs           # Utility functions
│   └── dependency.rs      # Dependency handling
├── completions/           # Shell completions
│   └── packer_completion.bash
├── .github/               # GitHub Actions
│   └── workflows/
│       └── ci.yml
├── target/                # Build artifacts (auto-generated)
├── Cargo.toml             # Project metadata and dependencies
├── Cargo.lock             # Dependency lock file
├── README.md              # Main documentation
├── CHANGELOG.md           # Version history
├── CONTRIBUTING.md        # Development guidelines
├── SECURITY.md            # Security policy
├── LICENSE                # MIT license
├── install.sh             # Installation script
└── SETUP.md               # This file
```

## 🛠️ Shell Completions

### Install Bash Completions

```bash
# Copy to system completion directory
sudo cp completions/packer_completion.bash /etc/bash_completion.d/packer

# Or for user-only installation
mkdir -p ~/.local/share/bash-completion/completions
cp completions/packer_completion.bash ~/.local/share/bash-completion/completions/packer

# Reload bash completions
source ~/.bashrc
```

### Test Completions

```bash
# Type and press TAB
packer <TAB>
packer search <TAB>
```

## 🚨 Troubleshooting

### Build Issues

```bash
# Clean and rebuild
cargo clean
cargo build

# Check Rust version
rustc --version

# Update dependencies
cargo update
```

### Runtime Issues

```bash
# Check logs
RUST_LOG=debug packer search firefox

# Verify configuration
packer repos

# Check permissions
ls -la ~/.config/packer/
```

### Common Problems

**Problem**: "cargo: command not found"
**Solution**: Install Rust from https://rustup.rs/

**Problem**: "makepkg: command not found"
**Solution**: Install base-devel package: `sudo pacman -S base-devel`

**Problem**: Permission denied when installing
**Solution**: Use sudo or install to user directory

## 🔐 Security Setup

### GPG Configuration

```bash
# Import keys (if needed)
gpg --recv-keys <key-id>

# List trusted keys
gpg --list-keys

# Test GPG functionality
packer security import-keys --help
```

### Security Auditing

```bash
# Install cargo-audit
cargo install cargo-audit

# Run security audit
cargo audit

# Check for vulnerabilities
packer security audit
```

## 📊 Performance

### Monitoring

```bash
# Enable debug logging
RUST_LOG=debug packer search firefox

# Monitor resource usage
htop  # or top
```

### Optimization

```bash
# Build with full optimizations
cargo build --release

# Profile the application
cargo install cargo-profiler
cargo profiler callgrind --bin packer -- search firefox
```

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

## 📞 Support

- 📖 [Documentation](README.md)
- 🐛 [Bug Reports](https://github.com/d0mkaaa/packer/issues)
- 💡 [Feature Requests](https://github.com/d0mkaaa/packer/issues)
- 🛡️ [Security Issues](SECURITY.md)

---

**Ready to start? Run `./install.sh` and you'll be up and running in minutes!** 