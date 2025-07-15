# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Nothing yet

### Changed
- Nothing yet

### Deprecated
- Nothing yet

### Removed
- Nothing yet

### Fixed
- Nothing yet

### Security
- Nothing yet

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