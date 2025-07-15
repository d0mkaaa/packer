# Packer 📦

A modern, fast package manager for Arch Linux written in Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/d0mkaaa/packer)

## ✨ Features

- 🔍 **Fast Package Search** - Search across AUR and official repositories
- 📦 **Package Installation** - Install packages from multiple sources
- 🔄 **Dependency Resolution** - Automatic dependency handling
- 🛡️ **Security First** - GPG verification and checksum validation
- ⚡ **Parallel Operations** - Concurrent downloads and installations
- 🎯 **AUR Support** - Full Arch User Repository integration
- 📊 **Progress Tracking** - Real-time progress indicators
- 🔧 **Configurable** - Flexible TOML-based configuration
- 📁 **Multi-format Support** - Extract tar, zip, bzip2, xz, zstd archives

## 🚀 Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/d0mkaaa/packer.git
cd packer
cargo build --release
sudo cp target/release/packer /usr/local/bin/
```

#### Prerequisites
- Arch Linux
- Rust 1.75+ (for building from source)
- `makepkg` (for AUR packages)
- `git` (for AUR packages)

### Basic Usage

```bash
# Search for packages
packer search firefox

# Install a package
packer install neofetch

# Remove a package
packer remove package-name

# Update package database
packer update

# Show package information
packer info firefox

# List repositories
packer repos

# Show help
packer --help
```

## 📋 Commands

| Command | Description | Example |
|---------|-------------|---------|
| `search <query>` | Search for packages | `packer search vim` |
| `install <package>` | Install a package | `packer install git` |
| `remove <package>` | Remove a package | `packer remove vim` |
| `update` | Update package database | `packer update` |
| `upgrade` | Upgrade all packages | `packer upgrade` |
| `info <package>` | Show package information | `packer info firefox` |
| `list` | List installed packages | `packer list` |
| `repos` | List configured repositories | `packer repos` |
| `clean` | Clean package cache | `packer clean` |

## ⚙️ Configuration

Packer uses TOML configuration files located at `~/.config/packer/config.toml`:

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

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │───▶│  Package Manager│───▶│  Repository     │
│                 │    │                 │    │  Manager        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Dependency     │    │  Security       │
                       │  Resolver       │    │  Scanner        │
                       └─────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │  Storage        │    │  Database       │
                       │  Manager        │    │  Manager        │
                       └─────────────────┘    └─────────────────┘
```

## 🛡️ Security

Packer prioritizes security with multiple verification layers:

- **GPG Signature Verification** - Validates package authenticity
- **Checksum Validation** - Ensures package integrity
- **Secure Downloads** - Uses HTTPS with certificate validation
- **Safe Extraction** - Prevents path traversal attacks
- **Input Sanitization** - Validates all user inputs

## 🔧 Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Generate documentation
cargo doc --open
```

### Testing

```bash
# Run all tests
cargo test

# Run specific test
cargo test search

# Run with output
cargo test -- --nocapture
```

### Features

Packer supports feature flags for different build configurations:

```bash
# Build with all features (default)
cargo build --features git

# Minimal build
cargo build --features minimal
```

## 📊 Performance

Packer is designed for performance:

- **Parallel Downloads** - Concurrent package downloads
- **Efficient Caching** - Smart cache management
- **Memory Efficient** - Streaming operations for large files
- **Fast Search** - Optimized package database queries

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure tests pass (`cargo test`)
6. Commit your changes (`git commit -am 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Bug Reports

Found a bug? Please report it on our [Issues page](https://github.com/d0mkaaa/packer/issues).

## 📈 Roadmap

- [ ] GUI interface
- [ ] Multi-distro support (Debian, Fedora)
- [ ] Plugin system
- [ ] Advanced dependency resolution
- [ ] Package signing tools
- [ ] Integration with system package managers

## 💬 Support

- 🐛 [Bug Reports](https://github.com/d0mkaaa/packer/issues)
- 💡 [Feature Requests](https://github.com/d0mkaaa/packer/issues)

---

**Made with ❤️ in Rust** 