# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-07-18

### Security
- **CRITICAL FIX**: Fixed TOCTOU (Time-of-Check-Time-of-Use) vulnerability in GPG signature verification
- **Signature Validation**: Added atomic file operations to prevent race condition attacks
- **Path Security**: Implemented path canonicalization to prevent traversal attacks
- **Content Validation**: Added signature format validation to prevent malicious file substitution
- **CVE-2025-0718**: GPG signature verification race condition vulnerability
- **Signature File Handling**: Atomic file operations prevent signature file swapping attacks
- **Path Traversal**: Canonical path validation prevents directory traversal attacks

### Added
- **Complete Pacman Independence**: Packer now operates entirely without pacman or sudo
- **Native Package Format**: Custom `.pck` format for user-space package management
- **User-Space Installation**: All packages install to `~/.local/usr/` (no root required)
- **Direct HTTP Downloads**: Downloads packages directly from Arch mirrors
- **Desktop Integration**: Automatic .desktop file setup and PATH integration
- **Transaction System**: Atomic operations with rollback support
- **Native Database**: Local package database independent of pacman
- **Symlink Resolution**: Proper symlink handling for package files within install root
- **Improved User Feedback**: Better messages for already-installed packages
- **Comprehensive Test Suite**: Full test coverage for all package manager operations

### Changed
- **Installation Method**: Now installs to user directory instead of system-wide
- **Dependency Resolution**: Native implementation replacing pacman dependency
- **Package Search**: Direct repository API integration instead of pacman queries
- **Package Removal**: File-based removal without pacman
- **Security Model**: Checksum validation without GPG dependency
- **Symlink Creation**: Absolute symlinks now point to install root locations
- **Error Messages**: Removed pacman references from fallback messages

### Fixed
- **File Exists Error**: Fixed symlink creation failing with "File exists" error
- **Symlink Targets**: Symlinks now correctly point to installed files
- **Package Functionality**: Installed packages now work correctly (tested with htop, tree, wget, curl, unzip, zip)
- **User Feedback**: Clear messages when packages are already installed
- **Binary Permissions**: Proper executable permissions for installed binaries

### Removed
- **Pacman Dependency**: Completely removed all pacman subprocess calls
- **Sudo Requirement**: No longer requires root privileges for any operation
- **System Integration**: No longer modifies system directories
- **Symlink Handling**: Robust absolute path symlink support
- **Permission Management**: Non-fatal permission setting for user-space installs
- **Compilation Errors**: Cleaned up unused imports, variables, and dead code
- **Method Signatures**: Fixed async function recursion and type mismatches

### Security
- **User-Space Isolation**: All operations contained within user directory
- **Path Validation**: Enhanced security against path traversal attacks
- **Direct Downloads**: Eliminates privilege escalation attack vectors

## [0.1.0] - 2025-07-15

### Added
- Initial release of Packer package manager
- Command-line interface with multiple subcommands (search, install, remove, update, etc.)
- Package search functionality with support for multiple repositories
- AUR (Arch User Repository) integration for building packages
- Configuration system with TOML-based settings
- Multi-format archive extraction (tar, zip, bzip2, xz, zstd)
- JSON-based package database storage
- Dependency resolution framework
- Security scanning framework (placeholder implementation)
- Parallel package operations support
- Repository management system
- Package installation and removal
- System snapshot capabilities
- Comprehensive error handling and logging
- Cross-platform support framework (currently focused on Arch Linux)

### Technical Features
- Asynchronous operations using Tokio
- Robust error handling with anyhow and thiserror
- Secure HTTP/HTTPS networking with rustls
- GPG signature verification support
- Progress indicators for long-running operations
- Concurrent package processing with rayon
- Memory-efficient operations with streaming
- Comprehensive test suite

### Security
- GPG signature verification for packages
- Checksum validation for downloaded files
- Secure temporary file handling
- Input validation and sanitization
- Safe archive extraction with path traversal protection

### Documentation
- README with usage examples
- API documentation with rustdoc
- Configuration file examples
- Installation and setup guide

[Unreleased]: https://github.com/d0mkaaa/packer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/d0mkaaa/packer/releases/tag/v0.1.0 