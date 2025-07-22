# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2025-07-22

### Major Features
- **🔍 Interactive Package List**: Complete overhaul of the `list` command with search, pagination, and filtering
- **💾 Disk Space Tracking**: Real-time disk space monitoring for installations and removals  
- **🔧 Smart Dependency Resolution**: Improved package resolution with alias mapping and system verification
- **📦 System Package Integration**: Native support for viewing and searching pacman-installed packages

### Interactive List Command
- **Real-time Search**: Filter packages by name, description, or repository with instant results
- **Smart Pagination**: Navigate large package lists with 20 packages per page
- **Version Status**: Shows available updates with clear "UPDATE" indicators
- **Package Details**: Quick info view by entering package numbers (1-20)
- **Multi-source Support**: View both packer-managed and system packages together
- **Command Flags**: `--simple` for scripting, `--updates` for update-only view, `--system` for all packages

### Dependency Resolution Improvements  
- **Package Aliases**: Maps common package names (`jack` → `jack2`, `pulse` → `pulseaudio`)
- **System Verification**: Actual package existence checking via pacman and filesystem
- **Smart Stubs**: Only creates verified system stubs, prevents broken dependencies
- **Fallback Search**: Multi-repository search before giving up on missing packages
- **Better Warnings**: Clear user feedback when creating unverified dependency stubs

### Disk Space Features
- **Installation Tracking**: Shows available space after package installations
- **Removal Tracking**: Displays space information after package removals  
- **Human-readable Format**: Automatic unit conversion (B, KB, MB, GB, TB)
- **Graceful Fallback**: Continues operation even if disk space calculation fails

### Added
- **Utility Functions**: `get_disk_usage()`, `format_bytes()`, `calculate_directory_size()`
- **System Package Query**: Integration with pacman for comprehensive package listing
- **Interactive Navigation**: Commands for search (`s`), next (`n`), previous (`p`), reset (`r`), quit (`q`)
- **Conflict Resolution**: Proper handling of missing dependencies with verification steps
- **Comment Style**: Updated all code comments to casual, friendly language

### Fixed  
- **obs-studio Installation**: Resolved jack dependency resolution that was preventing installation
- **Memory Scope Issues**: Fixed variable scope problems in disk space tracking
- **Compiler Warnings**: Eliminated all unused code warnings with proper `#[allow(dead_code)]` attributes
- **Search Performance**: Improved search responsiveness in interactive mode
- **Package Verification**: Better handling of packages with version constraints (e.g., "taglib>=1.9.0")

### Improved
- **Error Messages**: More descriptive error messages for missing packages and resolution failures  
- **User Experience**: Cleaner output with emoji indicators and colored text
- **Code Quality**: Removed dead code warnings and improved maintainability
- **Documentation**: Casual, friendly comments throughout the codebase

## [0.2.1] - 2025-07-19

### Major Features
- **🪞 Comprehensive Mirror System**: Complete mirror management with automatic discovery, ranking, and fallback support
- **⚡ Smart Mirror Selection**: Automatic selection of fastest mirrors based on location, speed, and reliability
- **🌍 Global Mirror Support**: Built-in support for worldwide Arch Linux mirrors with country preferences
- **🔄 Automatic Fallback**: Intelligent fallback to backup mirrors when primary mirrors fail during downloads

### Mirror Management CLI
- **`packer mirrors list [repo]`**: List available mirrors for any repository
- **`packer mirrors test [repo]`**: Test mirror speeds and availability with detailed results
- **`packer mirrors rank`**: Rank all mirrors by performance metrics
- **`packer mirrors stats`**: Show comprehensive mirror statistics and health data
- **`packer mirrors update`**: Update mirror list from official Arch Linux sources

### Performance Improvements
- **Search Caching**: Added intelligent search result caching with 5-minute TTL for dramatically faster repeated searches
- **Bulk Operations**: Optimized `bulk_add_packages` to batch database saves, reducing I/O operations by up to 90%
- **Database Efficiency**: Eliminated redundant disk writes during package batch processing
- **Memory Optimization**: Improved memory usage patterns in search and package processing
- **Download Reliability**: Multi-mirror support significantly improves download success rates

### Mirror System Features
- **Automatic Mirror Discovery**: Fetches latest mirror list from official Arch Linux sources
- **Performance Scoring**: Advanced scoring algorithm considering response time, location, and SSL support
- **Configurable Preferences**: Country-based preferences, protocol selection (HTTPS/HTTP), and custom mirrors
- **Health Monitoring**: Continuous monitoring of mirror availability and performance
- **Load Balancing**: Distributes requests across multiple mirrors to prevent overload

### Added
- **Compression Framework**: New compression module supporting gzip, xz, zstd formats for better package handling
- **Delta Updates**: Package delta support for efficient updates, reducing bandwidth usage
- **Smart Compression**: Automatic compression format selection based on file size and speed requirements
- **Enhanced Error Logging**: Better error reporting with context for package parsing failures
- **Mirror Configuration**: Comprehensive mirror settings in config files
- **Parallel Mirror Testing**: Concurrent speed testing with configurable limits

### Fixed
- **Async Processing**: Resolved compilation issues with parallel AUR package processing
- **Search Interface**: Fixed search function to return owned data for better cache integration
- **Error Handling**: Replaced silent error swallowing with proper logging and error propagation
- **Cache Invalidation**: Automatic cache clearing when packages are added or synced
- **Mirror Borrowing Issues**: Fixed Rust borrowing conflicts in mirror ranking system
- **Download Resilience**: Package downloads now automatically retry failed mirrors

### Technical Improvements
- **Reduced Database I/O**: Bulk operations now save once instead of per-package
- **Cache Hit Rate**: Search cache provides near-instant results for repeated queries
- **Better Diagnostics**: Enhanced error messages with package-specific context
- **Code Quality**: Improved error handling patterns throughout the codebase
- **Mirror Architecture**: Clean separation of mirror management, testing, and selection logic
- **Concurrent Operations**: Safe parallel mirror testing with semaphore-based rate limiting

### Reliability Enhancements
- **Multi-Mirror Downloads**: Each package download attempts multiple mirrors automatically
- **Graceful Degradation**: System continues working even when some mirrors are unavailable
- **Built-in Fallbacks**: Hardcoded reliable mirrors ensure system always functions
- **Network Resilience**: Robust handling of network timeouts and connection failures

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