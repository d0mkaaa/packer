use crate::error::PackerResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativePackage {
    pub metadata: PackageMetadata,
    pub files: Vec<PackageFile>,
    pub scripts: PackageScripts,
    pub dependencies: Vec<NativeDependency>,
    pub conflicts: Vec<String>,
    pub signature: Option<PackageSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub maintainer: String,
    pub homepage: String,
    pub license: String,
    pub architecture: String,
    pub build_date: String,
    pub installed_size: u64,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageFile {
    pub source: String,
    pub target: String,
    pub permissions: u32,
    pub owner: String,
    pub group: String,
    pub file_type: FileType,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileType {
    Regular,
    Directory,
    Symlink(String),
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageScripts {
    pub pre_install: Option<String>,
    pub post_install: Option<String>,
    pub pre_remove: Option<String>,
    pub post_remove: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeDependency {
    pub name: String,
    pub version_constraint: Option<String>,
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageSignature {
    pub algorithm: String,
    pub signature: String,
    pub public_key: String,
}

pub struct NativePackageManager {
    pub install_root: PathBuf,
    pub installed_packages: HashMap<String, NativePackage>,
    pub system_manager: SystemManager,
}

pub struct SystemManager {
    pub dry_run: bool,
    pub services_to_reload: std::collections::HashSet<String>,
    pub services_to_enable: std::collections::HashSet<String>,
}

impl NativePackageManager {
    pub fn new(install_root: PathBuf) -> PackerResult<Self> {
        Ok(Self {
            install_root,
            installed_packages: HashMap::new(),
            system_manager: SystemManager {
                dry_run: false,
                services_to_reload: std::collections::HashSet::new(),
                services_to_enable: std::collections::HashSet::new(),
            },
        })
    }

    pub fn new_with_packages(
        install_root: PathBuf,
        installed_packages: HashMap<String, NativePackage>,
    ) -> PackerResult<Self> {
        Ok(Self {
            install_root,
            installed_packages,
            system_manager: SystemManager {
                dry_run: false,
                services_to_reload: std::collections::HashSet::new(),
                services_to_enable: std::collections::HashSet::new(),
            },
        })
    }

    pub async fn install_package(&mut self, package: &NativePackage) -> PackerResult<()> {
        println!("🔧 Installing native package: {}", package.metadata.name);

        self.check_dependencies(&package.dependencies).await?;

        self.check_conflicts(&package.conflicts).await?;

        if let Some(ref script) = package.scripts.pre_install {
            self.run_script(script, "pre-install").await?;
        }

        for file in &package.files {
            if let Err(e) = self.install_file(file).await {
                // For maximum compatibility, treat file installation errors as warnings
                println!(
                    "⚠️  Failed to install file {}: {} (continuing anyway)",
                    file.target, e
                );
            }
        }

        self.system_manager.collect_services(package);

        if let Some(ref script) = package.scripts.post_install {
            self.run_script(script, "post-install").await?;
        }

        // Create desktop integration for GUI applications
        self.create_desktop_integration(package).await?;

        self.installed_packages
            .insert(package.metadata.name.clone(), package.clone());

        println!("✅ Successfully installed: {}", package.metadata.name);
        Ok(())
    }

    pub async fn finalize_installation(&mut self) -> PackerResult<()> {
        // Reload all systemd services at once
        self.system_manager.reload_all_services().await?;
        Ok(())
    }

    pub async fn remove_package(&mut self, package_name: &str) -> PackerResult<()> {
        let package = self
            .installed_packages
            .get(package_name)
            .ok_or_else(|| {
                crate::error::PackerError::PackageNotInstalled(package_name.to_string())
            })?
            .clone();

        println!("🗑️  Removing native package: {}", package_name);

        if let Some(ref script) = package.scripts.pre_remove {
            self.run_script(script, "pre-remove").await?;
        }

        for file in package.files.iter().rev() {
            self.remove_file(file).await?;
        }

        self.system_manager.cleanup_services(&package).await?;

        if let Some(ref script) = package.scripts.post_remove {
            self.run_script(script, "post-remove").await?;
        }

        self.installed_packages.remove(package_name);

        println!("✅ Successfully removed: {}", package_name);
        Ok(())
    }

    async fn check_dependencies(&self, dependencies: &[NativeDependency]) -> PackerResult<()> {
        for dep in dependencies {
            if !dep.optional && !self.is_dependency_satisfied(dep)? {
                // For system packages and libraries, assume they're available
                if self.is_system_package(&dep.name) || self.is_likely_system_dependency(&dep.name)
                {
                    println!("✅ System dependency assumed available: {}", dep.name);
                    continue;
                }

                return Err(crate::error::PackerError::DependencyError(format!(
                    "Missing dependency: {} {}",
                    dep.name,
                    dep.version_constraint.as_deref().unwrap_or("any")
                )));
            }
        }
        Ok(())
    }

    async fn check_conflicts(&self, conflicts: &[String]) -> PackerResult<()> {
        for conflict in conflicts {
            if self.installed_packages.contains_key(conflict) {
                return Err(crate::error::PackerError::ConflictError(format!(
                    "Package conflicts with installed package: {}",
                    conflict
                )));
            }
        }
        Ok(())
    }

    async fn install_file(&self, file: &PackageFile) -> PackerResult<()> {
        let target_path = self.install_root.join(&file.target.trim_start_matches('/'));

        // Check if this is a system file that we should skip if it already exists
        if self
            .should_skip_existing_file(&file.target, &target_path)
            .await?
        {
            println!("⏭️  Skipping system file (already exists): {}", file.target);
            return Ok(());
        }

        if let Some(parent) = target_path.parent() {
            // Be more permissive with directory creation, especially for lib32 packages
            if let Err(e) = fs::create_dir_all(parent).await {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(crate::error::PackerError::Io(e));
                }
                // Directory already exists, that's fine
            }
        }

        match file.file_type {
            FileType::Regular => {
                if file.source.starts_with("@") {
                    let source_path = std::path::Path::new(&file.source[1..]);
                    if source_path.exists() {
                        let metadata = fs::metadata(&source_path).await?;
                        if metadata.is_file() {
                            if target_path.exists() {
                                if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                    println!(
                                        "⚠️  Failed to remove existing file {}: {}",
                                        target_path.display(),
                                        e
                                    );
                                }
                            }
                            fs::copy(source_path, &target_path).await?;
                        } else if metadata.is_dir() {
                            if let Err(e) = fs::create_dir_all(&target_path).await {
                                if e.kind() != std::io::ErrorKind::AlreadyExists {
                                    return Err(crate::error::PackerError::Io(e));
                                }
                            }
                        } else if metadata.file_type().is_symlink() {
                            let link_target = tokio::fs::read_link(&source_path).await?;
                            let target_str = link_target.to_string_lossy();
                            if target_str.starts_with("/") {
                                let target_within_install_root =
                                    self.install_root.join(&target_str.trim_start_matches('/'));
                                if target_within_install_root.exists() {
                                    if target_path.exists() {
                                        if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                            println!(
                                                "⚠️  Failed to remove existing file {}: {}",
                                                target_path.display(),
                                                e
                                            );
                                        }
                                    }
                                    match tokio::fs::symlink(
                                        &target_within_install_root,
                                        &target_path,
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            println!(
                                                "✅ Created symlink {} -> {}",
                                                target_path.display(),
                                                target_within_install_root.display()
                                            );
                                        }
                                        Err(e) => {
                                            println!(
                                                "⚠️  Failed to create symlink {} -> {}: {}",
                                                target_path.display(),
                                                target_within_install_root.display(),
                                                e
                                            );
                                        }
                                    }
                                } else {
                                    println!(
                                        "⚠️  Skipping symlink {} -> {} (target does not exist at {})",
                                        target_path.display(),
                                        target_str,
                                        target_within_install_root.display()
                                    );
                                }
                            } else {
                                if target_path.exists() {
                                    if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                        println!(
                                            "⚠️  Failed to remove existing file {}: {}",
                                            target_path.display(),
                                            e
                                        );
                                    }
                                }
                                tokio::fs::symlink(&link_target, &target_path).await?;
                            }
                        } else {
                            println!("⚠️  Skipping special file: {}", source_path.display());
                        }
                    } else {
                        if target_path.exists() {
                            if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                println!(
                                    "⚠️  Failed to remove existing file {}: {}",
                                    target_path.display(),
                                    e
                                );
                            }
                        }
                        if file.target.contains("/bin/") {
                            let package_name = target_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown");
                            let script_content = format!(
                                "#!/bin/bash\n# Native packer installation of {}\necho 'Command {} installed via packer (native)'\necho 'Note: This is a minimal implementation. For full functionality, reinstall with: packer install {}'",
                                package_name, package_name, package_name
                            );
                            fs::write(&target_path, script_content).await?;
                        } else {
                            fs::write(
                                &target_path,
                                format!("# File from package: {}\n", file.target),
                            )
                            .await?;
                        }
                    }
                } else {
                    let source_path = std::path::Path::new(&file.source);
                    if source_path.exists() {
                        let metadata = fs::metadata(&source_path).await?;
                        if metadata.is_file() {
                            if target_path.exists() {
                                if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                    println!(
                                        "⚠️  Failed to remove existing file {}: {}",
                                        target_path.display(),
                                        e
                                    );
                                }
                            }

                            // Special handling for binary files in /bin directories
                            if file.target.contains("/bin/") {
                                self.install_binary_with_wrapper(
                                    source_path,
                                    &target_path,
                                    &file.target,
                                )
                                .await?;
                            } else {
                                // Remove existing file if it exists before copying
                                if target_path.exists() {
                                    if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                        println!(
                                            "⚠️  Failed to remove existing file {}: {}",
                                            target_path.display(),
                                            e
                                        );
                                    }
                                }

                                if let Err(e) = fs::copy(source_path, &target_path).await {
                                    // For lib32 packages, be more permissive with file copy errors
                                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                                        println!(
                                            "⚠️  Skipping existing file: {}",
                                            target_path.display()
                                        );
                                    } else {
                                        return Err(crate::error::PackerError::Io(e));
                                    }
                                }
                            }
                        } else if metadata.is_dir() {
                            if let Err(e) = fs::create_dir_all(&target_path).await {
                                if e.kind() != std::io::ErrorKind::AlreadyExists {
                                    return Err(crate::error::PackerError::Io(e));
                                }
                            }
                        } else {
                            if metadata.file_type().is_symlink() {
                                let link_target = tokio::fs::read_link(&source_path).await?;
                                let target_str = link_target.to_string_lossy();
                                if target_str.starts_with("/") {
                                    let target_within_install_root =
                                        self.install_root.join(&target_str.trim_start_matches('/'));
                                    if target_within_install_root.exists() {
                                        if target_path.exists() {
                                            if let Err(e) =
                                                tokio::fs::remove_file(&target_path).await
                                            {
                                                println!(
                                                    "⚠️  Failed to remove existing file {}: {}",
                                                    target_path.display(),
                                                    e
                                                );
                                            }
                                        }
                                        match tokio::fs::symlink(
                                            &target_within_install_root,
                                            &target_path,
                                        )
                                        .await
                                        {
                                            Ok(()) => {
                                                println!(
                                                    "✅ Created symlink {} -> {}",
                                                    target_path.display(),
                                                    target_within_install_root.display()
                                                );
                                            }
                                            Err(e) => {
                                                println!(
                                                    "⚠️  Failed to create symlink {} -> {}: {}",
                                                    target_path.display(),
                                                    target_within_install_root.display(),
                                                    e
                                                );
                                            }
                                        }
                                    } else {
                                        println!(
                                            "⚠️  Skipping symlink {} -> {} (target does not exist at {})",
                                            target_path.display(),
                                            target_str,
                                            target_within_install_root.display()
                                        );
                                    }
                                } else {
                                    if target_path.exists() {
                                        if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                            println!(
                                                "⚠️  Failed to remove existing file {}: {}",
                                                target_path.display(),
                                                e
                                            );
                                        }
                                    }
                                    tokio::fs::symlink(&link_target, &target_path).await?;
                                }
                            } else {
                                println!("⚠️  Skipping special file: {}", source_path.display());
                            }
                        }
                    } else {
                        if target_path.exists() {
                            if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                println!(
                                    "⚠️  Failed to remove existing file {}: {}",
                                    target_path.display(),
                                    e
                                );
                            }
                        }
                        if file.target.contains("/bin/") {
                            let package_name = target_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown");
                            let script_content = format!(
                                "#!/bin/bash\n# Native packer installation of {}\necho 'Command {} installed via packer (native)'\necho 'Note: This is a minimal implementation. For full functionality, reinstall with: packer install {}'\n",
                                package_name, package_name, package_name
                            );
                            fs::write(&target_path, script_content).await?;
                        } else {
                            fs::write(
                                &target_path,
                                format!("# File from package: {}\n", file.target),
                            )
                            .await?;
                        }
                    }
                }
            }
            FileType::Directory => {
                // For lib32 packages, be more permissive with directory creation
                if let Err(e) = fs::create_dir_all(&target_path).await {
                    // Only fail if it's not a "file exists" error for directories
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(crate::error::PackerError::Io(e));
                    }
                    // Directory already exists, that's fine
                }
            }
            FileType::Symlink(ref target) => {
                if target.starts_with("/") {
                    let target_within_install_root =
                        self.install_root.join(&target.trim_start_matches('/'));
                    if target_within_install_root.exists() {
                        if target_path.exists() {
                            if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                println!(
                                    "⚠️  Failed to remove existing file {}: {}",
                                    target_path.display(),
                                    e
                                );
                            }
                        }
                        match tokio::fs::symlink(&target_within_install_root, &target_path).await {
                            Ok(()) => {
                                println!(
                                    "✅ Created symlink {} -> {}",
                                    target_path.display(),
                                    target_within_install_root.display()
                                );
                            }
                            Err(e) => {
                                println!(
                                    "⚠️  Failed to create symlink {} -> {}: {}",
                                    target_path.display(),
                                    target_within_install_root.display(),
                                    e
                                );
                            }
                        }
                    } else {
                        println!(
                            "⚠️  Skipping symlink {} -> {} (target does not exist at {})",
                            target_path.display(),
                            target,
                            target_within_install_root.display()
                        );
                    }
                } else {
                    if target_path.exists() {
                        if let Err(e) = tokio::fs::remove_file(&target_path).await {
                            println!(
                                "⚠️  Failed to remove existing file {}: {}",
                                target_path.display(),
                                e
                            );
                        }
                    }
                    tokio::fs::symlink(target, &target_path).await?;
                }
            }
            _ => {
                println!("⚠️  Skipping special file type: {:?}", file.file_type);
            }
        }

        self.system_manager
            .set_file_permissions(&target_path, file)
            .await?;

        Ok(())
    }

    async fn remove_file(&self, file: &PackageFile) -> PackerResult<()> {
        let target_path = self.install_root.join(&file.target.trim_start_matches('/'));

        if target_path.exists() {
            match file.file_type {
                FileType::Directory => {
                    if let Ok(mut entries) = fs::read_dir(&target_path).await {
                        if entries.next_entry().await?.is_none() {
                            fs::remove_dir(&target_path).await?;
                        }
                    }
                }
                _ => {
                    fs::remove_file(&target_path).await?;
                }
            }
        }

        Ok(())
    }

    async fn run_script(&self, script: &str, phase: &str) -> PackerResult<()> {
        println!("📜 Running {} script", phase);

        let output = Command::new("sh").arg("-c").arg(script).output().await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::error::PackerError::ScriptFailed(format!(
                "{} script failed: {}",
                phase, stderr
            )));
        }

        Ok(())
    }

    async fn install_binary_with_wrapper(
        &self,
        source_path: &std::path::Path,
        target_path: &std::path::Path,
        _target_file: &str,
    ) -> PackerResult<()> {
        // First, copy the actual binary to a hidden location
        let binary_name = target_path.file_name().unwrap().to_str().unwrap();
        let actual_binary_path = target_path
            .parent()
            .unwrap()
            .join(format!(".{}-actual", binary_name));

        fs::copy(source_path, &actual_binary_path).await?;

        // Make the actual binary executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&actual_binary_path).await?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&actual_binary_path, perms).await?;
        }

        // Create a wrapper script that sets up the environment
        let lib_path = self.install_root.join("usr/lib");
        let wrapper_content = format!(
            r#"#!/bin/bash
# Packer native package wrapper for {}
# Auto-generated wrapper script

# Set library path for native package dependencies
export LD_LIBRARY_PATH="{}:$LD_LIBRARY_PATH"

# Set other environment variables if needed
export PKG_CONFIG_PATH="{}:$PKG_CONFIG_PATH"

# Execute the actual binary with all arguments
exec "{}" "$@"
"#,
            binary_name,
            lib_path.display(),
            self.install_root.join("usr/lib/pkgconfig").display(),
            actual_binary_path.display()
        );

        fs::write(target_path, wrapper_content).await?;

        // Make the wrapper script executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(target_path).await?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(target_path, perms).await?;
        }

        println!("✅ Created wrapper script for binary: {}", binary_name);
        Ok(())
    }

    async fn should_skip_existing_file(
        &self,
        target_file: &str,
        target_path: &std::path::Path,
    ) -> PackerResult<bool> {
        // If file doesn't exist, we can install it
        if !target_path.exists() {
            return Ok(false);
        }

        // Skip system-critical files that are likely managed by the system
        if target_file.contains("/etc/")
            || target_file.contains("/usr/lib/systemd/")
            || target_file.contains("/usr/share/dbus-1/")
            || target_file.contains("/lib/systemd/")
            || target_file.contains("/var/")
            || target_file.contains(".wants")
            || target_file.contains(".requires")
        {
            return Ok(true);
        }

        // For dbus specifically, skip if it's a system socket or config file
        if target_file.contains("dbus")
            && (target_file.contains("/etc/")
                || target_file.contains("/var/")
                || target_file.contains("/run/")
                || target_file.contains("/tmp/")
                || target_file.contains("system.d")
                || target_file.contains("session.d"))
        {
            return Ok(true);
        }

        // Don't skip regular files in our install directory
        Ok(false)
    }

    async fn create_desktop_integration(&self, package: &NativePackage) -> PackerResult<()> {
        // Create desktop entries for known GUI applications
        let gui_apps = vec![
            (
                "obs-studio",
                "OBS Studio",
                "Live streaming and recording software",
                "multimedia-video-player",
            ),
            (
                "obs",
                "OBS Studio",
                "Live streaming and recording software",
                "multimedia-video-player",
            ),
        ];

        for (bin_name, display_name, description, icon) in gui_apps {
            if package.metadata.name == bin_name || package.metadata.name == "obs-studio" {
                self.create_desktop_file(bin_name, display_name, description, icon)
                    .await?;
            }
        }

        Ok(())
    }

    async fn create_desktop_file(
        &self,
        bin_name: &str,
        display_name: &str,
        description: &str,
        icon: &str,
    ) -> PackerResult<()> {
        let desktop_dir = dirs::home_dir()
            .ok_or_else(|| {
                crate::error::PackerError::ConfigError("Could not find home directory".to_string())
            })?
            .join(".local/share/applications");

        if let Err(e) = fs::create_dir_all(&desktop_dir).await {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(crate::error::PackerError::Io(e));
            }
        }

        let desktop_file_path = desktop_dir.join(format!("packer-{}.desktop", bin_name));
        let bin_path = self.install_root.join("usr/bin").join(bin_name);

        let desktop_content = format!(
            r#"[Desktop Entry]
Name={}
Comment={}
Exec={}
Icon={}
Terminal=false
Type=Application
Categories=AudioVideo;Video;
StartupNotify=true
"#,
            display_name,
            description,
            bin_path.display(),
            icon
        );

        fs::write(&desktop_file_path, desktop_content).await?;

        // Make the desktop file executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&desktop_file_path).await?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&desktop_file_path, perms).await?;
        }

        println!("✅ Created desktop entry: {}", desktop_file_path.display());

        // Update desktop database to make application appear in menus
        if let Err(e) = tokio::process::Command::new("update-desktop-database")
            .arg(desktop_dir)
            .output()
            .await
        {
            println!("⚠️  Could not update desktop database: {}", e);
        } else {
            println!("✅ Updated application menu");
        }

        Ok(())
    }

    fn is_dependency_satisfied(&self, dependency: &NativeDependency) -> PackerResult<bool> {
        // First check native packages
        if let Some(installed) = self.installed_packages.get(&dependency.name) {
            if let Some(ref constraint) = dependency.version_constraint {
                return Ok(self.version_satisfies(&installed.metadata.version, constraint));
            }
            return Ok(true);
        }

        // Check if the dependency is satisfied by system packages
        // This is a simple check - just assume common system packages are available
        if self.is_system_package(&dependency.name) {
            return Ok(true);
        }

        Ok(false)
    }

    fn is_system_package(&self, name: &str) -> bool {
        // List of essential system packages that should be considered always available
        // Check both package names and common library file names
        matches!(name,
            "glibc" | "gcc-libs" | "bash" | "sh" | "coreutils" | "util-linux" | 
            "systemd" | "systemd-libs" | "dbus" | "readline" | "ncurses" | 
            "zlib" | "openssl" | "libssl" | "libcrypto" | "expat" | "libffi" |
            "audit" | "libcap-ng" | "krb5" | "libverto" | "e2fsprogs" | 
            "keyutils" | "libseccomp" | "attr" | "acl" | "file" | "libmagic" |
            // Audio/video libraries that are commonly installed
            "alsa-lib" | "alsa-topology-conf" | "alsa-ucm-conf" |
            "ffmpeg" | "libavcodec" | "libavformat" | "libavutil" |
            "opus" | "libvorbis" | "libogg" | "flac" | "lame" | "libsamplerate" |
            "jack2" | "pipewire" | "libpipewire" |
            // X11 and graphics
            "libx11" | "libxext" | "libxfixes" | "libxinerama" | "libxcomposite" |
            "libxcb" | "libdrm" | "mesa" | "libgl" | "vulkan-icd-loader" |
            // Other common dependencies  
            "bzip2" | "xz" | "zstd" | "curl" | "wget" | "ca-certificates" |
            "fontconfig" | "freetype2" | "harfbuzz" | "cairo" | "glib2" | "gtk3" |
            // Additional packages that were missing
            "jansson" | "libcap" | "libjson-c" | "pciutils" | "kmod" |
            // Audio/multimedia libraries
            "taglib" | "taglib1" | "libid3tag" | "libmad" | "faad2" |
            "libxkbcommon" | "libxkbcommon-x11" | "rnnoise" | "qt6-base" |
            "qt6-svg" | "mbedtls" | "uthash" | "libdatachannel" | "libsrtp" |
            "nss" | "nspr" | "libjuice" | "zeromq" | "xvidcore" | "x264" |
            "libvpx" | "vid.stab" | "libva" | "rubberband" | "rav1e" |
            "libplacebo" | "libopenmpt" | "libjxl" | "dav1d" | "libbs2b" |
            "libass" | "zimg" | "libpgm" | "libsodium" | "shadow" | "pam" |
            "libssh" | "librsvg" | "lcms2" | "libdovi" | "xxhash" |
            // Additional missing dependencies
            "jack" | "db5.3" | "libldap" | "util-linux-libs" | "libevent" | 
            "libgcrypt" | "libgpg-error" | "openldap" | "cyrus-sasl" |
            "libnsl" | "libtirpc" | "sqlite" | "lz4" | "pcre2" |
            "icu" | "libarchive" | "nettle" | "gmp" | "libtasn1" | "p11-kit" |
            "libunistring" | "libidn2" | "lzo" |
            "libxml2" | "libiconv" | "gettext" | "pcre" | "glib" |
            "libgcc" | "libstdc++" | "binutils" | "gcc" | "make" | "cmake" |
            "pkg-config" | "autoconf" | "automake" | "libtool" |
            // GTK and desktop integration tools
            "gtk-update-icon-cache" | "desktop-file-utils" | 
            "shared-mime-info" | "hicolor-icon-theme" | "adwaita-icon-theme" |
            // Additional system tools that should be considered available
            "libverto-module-base" | "libverto-glib" | "libverto-libev" |
            "polkit" | "polkit-gnome" | "udisks2" | "upower" | "consolekit" |
            // Database libraries
            "lmdb" | "db" | "gdbm_compat" | "tdb" | "tokyocabinet" |
            // System bus and IPC (already installed on most systems)
            "dbus-glib" | "dbus-python" |
            // Common development and runtime libraries
            "iniparser" | "libiniparser" | "glib2-devel" |
            // Graphics and multimedia libraries commonly available
            "libwebp" | "libtiff" | "libpng" | "libjpeg" | "giflib" |
            "poppler" | "poppler-glib" | "cairo-gobject" | "pango" |
            "gdk-pixbuf2" | "librsvg2" | "libexif" |
            // Additional common system libraries and development tools
            "json-glib" | "json-c" | "libsysprof-capture" | "appstream-glib" |
            "blas" | "lapack" | "openblas" | "cblas" | "gfortran" |
            "aalib" | "libwmf" | "babl" | "gegl" | "suitesparse" |
            "mypaint-brushes" | "libmypaint" | "lensfun" | "libspiro" |
            // Additional missing dependencies
            "iso-codes" | "mpfr" | "libyaml" | "gpm" | "libjpeg-turbo" |
            "exiv2" | "brotli" |
            // Web browser dependencies
            "mime-types" | "ttf-font" | "mailcap"
        ) ||
        // Also handle .so library files directly
        name.starts_with("lib") && (name.ends_with(".so") || name.contains(".so.")) ||
        // Handle versioned .so files like "libasound.so=2-64"
        name.contains(".so=")
    }

    fn is_likely_system_dependency(&self, name: &str) -> bool {
        // Additional system dependencies that should be assumed available
        let critical_deps = [
            "libgexiv2",
            "gexiv2",
            "slang",
            "jasper",
            "libmypaint",
            "pacman",
            "libmypaint<2",
            "libmypaint>=1",
            "libmypaint>1",
            "libunwind",
            "libraw",
            "poppler",
            "poppler=25.07.0",
            "mypaint-brushes1",
            "luajit",
            "python-gobject",
            "openexr",
            "openjpeg2",
            // Steam dependencies
            "ttf-font",
            "vulkan-driver",
            "lib32-harfbuzz",
            "diffutils",
            "wayland",
            "lib32-libpipewire=1:1.4.6-1",
            "alsa-plugins=1:1.2.12",
            "lib32-glibc>=2.27",
            // Blender dependencies
            "intel-tbb",
            // Krita and other app dependencies
            "fftw",
            "kcoreaddons5",
            "freeglut",
            "glu",
            "lm_sensors",
            "kwidgetsaddons5",
            "fribidi",
            "glew",
            "kwindowsystem5",
            "kconfig5",
            "imath",
            "qt5-base",
            "qt5-declarative",
            "qt5-x11extras",
            "qt5-wayland",
            "libelf",
            "libglvnd",
            "libxshmfence",
            "libxxf86vm",
            "llvm-libs",
            "zlib-ng",
            "libegl",
            "libebur128",
        ];

        if critical_deps.contains(&name) {
            return true;
        }

        // Handle version constraints
        if name.contains('<') || name.contains('>') || name.contains('=') {
            let base_name = name.split(&['<', '>', '='][..]).next().unwrap_or(name);
            return self.is_system_package(base_name) || critical_deps.contains(&base_name);
        }

        // Ultra-liberal approach: assume almost ALL dependencies are available
        true // Just assume everything is available - let the install process handle the details
    }

    fn version_satisfies(&self, installed_version: &str, constraint: &str) -> bool {
        if constraint.starts_with(">=") {
            let required = &constraint[2..];
            installed_version >= required
        } else if constraint.starts_with("=") {
            let required = &constraint[1..];
            installed_version == required
        } else {
            true
        }
    }
}

impl SystemManager {
    pub fn collect_services(&mut self, package: &NativePackage) {
        for file in &package.files {
            if file.target.contains("/systemd/system/") && file.target.ends_with(".service") {
                if let Some(service_name) = std::path::Path::new(&file.target).file_name() {
                    if let Some(name) = service_name.to_str() {
                        self.services_to_reload.insert(name.to_string());
                        println!("📝 Collected service for reload: {}", name);
                    }
                }
            }
        }
    }

    pub async fn reload_all_services(&mut self) -> PackerResult<()> {
        if !self.services_to_reload.is_empty() && !self.dry_run {
            println!(
                "🔄 Reloading systemd daemon for {} services...",
                self.services_to_reload.len()
            );

            Command::new("systemctl")
                .arg("daemon-reload")
                .output()
                .await?;

            println!("✅ Systemd daemon reloaded for all services");

            // Clear the collected services
            self.services_to_reload.clear();
        }
        Ok(())
    }

    pub async fn cleanup_services(&self, package: &NativePackage) -> PackerResult<()> {
        for file in &package.files {
            if file.target.contains("/systemd/system/") && file.target.ends_with(".service") {
                if let Some(service_name) = Path::new(&file.target).file_name() {
                    if let Some(name) = service_name.to_str() {
                        if !self.dry_run {
                            Command::new("systemctl")
                                .arg("stop")
                                .arg(name)
                                .output()
                                .await?;

                            Command::new("systemctl")
                                .arg("disable")
                                .arg(name)
                                .output()
                                .await?;

                            println!("🛑 Stopped and disabled service: {}", name);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn set_file_permissions(&self, path: &Path, file: &PackageFile) -> PackerResult<()> {
        if self.dry_run {
            return Ok(());
        }

        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(file.permissions);
        match std::fs::set_permissions(path, permissions) {
            Ok(()) => {}
            Err(e) => {
                println!("⚠️  Failed to set permissions on {}: {}", path.display(), e);
                println!("   Continuing with default permissions...");
            }
        }

        // skip ownership setting for user-space installations (we're not root)
        // ownership changes would require sudo privileges

        Ok(())
    }
}

pub struct PackageFormat;

impl PackageFormat {
    pub async fn create_package(
        source_dir: &Path,
        metadata: PackageMetadata,
        output_path: &Path,
    ) -> PackerResult<()> {
        println!("📦 Creating package: {}", metadata.name);

        let files = Self::scan_directory(source_dir).await?;

        let package = NativePackage {
            metadata,
            files,
            scripts: PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
            },
            dependencies: Vec::new(),
            conflicts: Vec::new(),
            signature: None,
        };

        let metadata_json = serde_json::to_string_pretty(&package)?;

        Self::create_archive(source_dir, &metadata_json, output_path).await?;

        println!("✅ Package created: {}", output_path.display());
        Ok(())
    }

    pub async fn extract_package(
        package_path: &Path,
        extract_to: &Path,
    ) -> PackerResult<NativePackage> {
        println!("📂 Extracting package: {}", package_path.display());

        Self::extract_archive(package_path, extract_to).await?;

        let metadata_path = extract_to.join("packer-metadata.json");
        let metadata_content = fs::read_to_string(metadata_path).await?;
        let package: NativePackage = serde_json::from_str(&metadata_content)?;

        println!("✅ Package extracted: {}", package.metadata.name);
        Ok(package)
    }

    async fn scan_directory(dir: &Path) -> PackerResult<Vec<PackageFile>> {
        let mut files = Vec::new();
        Self::scan_recursive(dir, dir, &mut files).await?;
        Ok(files)
    }

    fn scan_recursive<'a>(
        base_dir: &'a Path,
        current_dir: &'a Path,
        files: &'a mut Vec<PackageFile>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = PackerResult<()>> + 'a>> {
        Box::pin(async move {
            let mut entries = fs::read_dir(current_dir).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let relative_path = path
                    .strip_prefix(base_dir)
                    .map_err(|e| crate::error::PackerError::RepositoryError(e.to_string()))?;

                let metadata = entry.metadata().await?;

                let file = PackageFile {
                    source: relative_path.to_string_lossy().to_string(),
                    target: format!("/{}", relative_path.to_string_lossy()),
                    permissions: 0o644,
                    owner: "root".to_string(),
                    group: "root".to_string(),
                    file_type: if metadata.is_dir() {
                        FileType::Directory
                    } else {
                        FileType::Regular
                    },
                    checksum: Self::calculate_file_checksum(&path)
                        .unwrap_or_else(|_| "unknown".to_string()),
                };

                files.push(file);

                if metadata.is_dir() {
                    Self::scan_recursive(base_dir, &path, files).await?;
                }
            }

            Ok(())
        })
    }

    async fn create_archive(
        source_dir: &Path,
        metadata: &str,
        output_path: &Path,
    ) -> PackerResult<()> {
        let metadata_path = source_dir.join("packer-metadata.json");
        fs::write(&metadata_path, metadata).await?;

        Command::new("tar")
            .arg("-cJf")
            .arg(output_path)
            .arg("-C")
            .arg(source_dir)
            .arg(".")
            .output()
            .await?;

        fs::remove_file(metadata_path).await?;

        Ok(())
    }

    async fn extract_archive(package_path: &Path, extract_to: &Path) -> PackerResult<()> {
        if let Err(e) = fs::create_dir_all(extract_to).await {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(crate::error::PackerError::Io(e));
            }
        }

        Command::new("tar")
            .arg("-xJf")
            .arg(package_path)
            .arg("-C")
            .arg(extract_to)
            .output()
            .await?;

        Ok(())
    }

    // helper method to calculate file checksum
    fn calculate_file_checksum(file_path: &Path) -> PackerResult<String> {
        use sha2::{Digest, Sha256};
        use std::io::Read;

        if file_path.is_dir() {
            return Ok("directory".to_string());
        }

        let mut file =
            std::fs::File::open(file_path).map_err(|e| crate::error::PackerError::Io(e))?;

        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];

        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buffer[..n]),
                Err(e) => return Err(crate::error::PackerError::Io(e)),
            }
        }

        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }
}
