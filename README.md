# Packer 📦

A modern, **completely independent** package manager for Arch Linux written in Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/d0mkaaa/packer)

## ✨ Features

- 🚫 **100% Pacman-Free** - No dependency on pacman or sudo required
- 🏠 **Native Package Format** - Uses custom `.pck` format for user-space installation  
- 📁 **User-Space Installation** - Installs to `~/.local/usr/` (no root required)
- 🔍 **Fast Package Search** - Search across AUR and official repositories
- 📦 **Direct HTTP Downloads** - Downloads packages directly from Arch mirrors
- 🔄 **Native Dependency Resolution** - Built-in dependency handling
- 🛡️ **Security First** - Checksum validation and secure extraction
- ⚡ **Transaction System** - Atomic operations with rollback support
- 🎯 **Multi-Source Support** - Arch official repositories and AUR
- 📊 **Progress Tracking** - Real-time progress indicators
- 🔧 **Desktop Integration** - Proper .desktop file and PATH integration
- 📁 **Multi-format Support** - Extract tar, zip, bzip2, xz, zstd archives

## 🚀 Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/d0mkaaa/packer.git
cd packer
cargo build --release
# Copy to your local bin directory (no sudo needed!)
mkdir -p ~/.local/bin
cp target/release/packer ~/.local/bin/
# Add to PATH in your shell config (.bashrc, .zshrc, etc.)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Prerequisites
- Arch Linux (or any system with access to Arch package repositories)
- Rust 1.88+ (for building from source)
- `git` (for AUR packages)
- No sudo or pacman required!

### Basic Usage

```bash
# Search for packages
packer search firefox

# Install a package (installs to ~/.local/usr/)
packer install curl

# Remove a package  
packer remove curl

# Update package database
packer update

# Show package information
packer info firefox

# List installed packages
packer list

# Show help
packer --help
```

**Note:** All packages are installed to `~/.local/usr/` and integrated with your desktop environment. Binaries are automatically added to PATH via `~/.local/usr/bin`.

## 📋 Commands

| Command | Description | Example |
|---------|-------------|---------|
| `search <query>` | Search for packages | `packer search vim` |
| `install <package>` | Install a package to ~/.local/usr/ | `packer install git` |
| `remove <package>` | Remove a package | `packer remove vim` |
| `update` | Update package database | `packer update` |
| `upgrade` | Upgrade all packages | `packer upgrade` |
| `info <package>` | Show package information | `packer info firefox` |
| `list` | List installed packages | `packer list` |

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
install_root = "~/.local/usr"  # User-space installation directory

[security]
checksum_verify = true
max_package_size = "1GB"
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Interface │───▶│  Native Package │───▶│  Repository     │
│                 │    │  Manager        │    │  Manager        │
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
                       │  Native Storage │    │  Local Database │
                       │  Manager        │    │  (.pck format)  │
                       └─────────────────┘    └─────────────────┘
```

## 🔄 How It Works

Packer operates completely independently from the system package manager:

1. **Download**: Fetches packages directly from Arch mirrors via HTTP
2. **Extract**: Safely extracts package contents with path validation  
3. **Convert**: Converts to native `.pck` format with metadata
4. **Install**: Places files in `~/.local/usr/` with proper permissions
5. **Integrate**: Sets up PATH, desktop files, and environment

No pacman, no sudo, no system dependencies - just pure user-space package management!

## 🛡️ Security

Packer prioritizes security with multiple verification layers:

- **Checksum Validation** - Ensures package integrity using official checksums
- **Secure Downloads** - Uses HTTPS with certificate validation  
- **Safe Extraction** - Prevents path traversal attacks during extraction
- **User-Space Isolation** - All operations in user directory, no system modification
- **Input Sanitization** - Validates all user inputs and package data

## 🔧 Development

### Building

```bash
# Debug build
cargo build

# Release build  
cargo build --release

# Run tests
cargo test

# Check for issues
cargo check

# Generate documentation
cargo doc --open
```

### Testing

```bash
# Run all tests
cargo test

# Test basic functionality
./target/release/packer search firefox
./target/release/packer install curl
./target/release/packer list
./target/release/packer remove curl
```

## 📊 Performance

Packer is designed for performance and independence:

- **No Sudo Overhead** - No privilege escalation required
- **Direct Downloads** - Bypasses system package manager bottlenecks
- **Efficient Caching** - Smart cache management in user space
- **Memory Efficient** - Streaming operations for large files
- **Fast Search** - Direct repository API integration
- **Parallel Operations** - Concurrent downloads and processing

## 🎯 Use Cases

Perfect for:
- **Non-root users** who want to install software
- **Development environments** where you can't modify the system
- **Containers** and isolated environments
- **Testing packages** without affecting the system
- **Portable installations** that travel with your user account

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

- [x] Complete pacman independence
- [x] Native package format  
- [x] User-space installation
- [x] Desktop integration
- [ ] GUI interface
- [ ] Multi-distro support (Debian, Fedora)
- [ ] Plugin system
- [ ] Advanced dependency resolution
- [ ] Package creation tools

## 💬 Support

- 🐛 [Bug Reports](https://github.com/d0mkaaa/packer/issues)
- 💡 [Feature Requests](https://github.com/d0mkaaa/packer/issues)
- 📚 [Documentation](https://github.com/d0mkaaa/packer/wiki)

---

**Made with ❤️ in Rust - Completely Pacman-Free!** 🦀 