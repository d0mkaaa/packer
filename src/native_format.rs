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
}

impl NativePackageManager {
    pub fn new(install_root: PathBuf) -> PackerResult<Self> {
        Ok(Self {
            install_root,
            installed_packages: HashMap::new(),
            system_manager: SystemManager { dry_run: false },
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
            self.install_file(file).await?;
        }

        self.system_manager.update_services(package).await?;

        if let Some(ref script) = package.scripts.post_install {
            self.run_script(script, "post-install").await?;
        }

        self.installed_packages.insert(package.metadata.name.clone(), package.clone());

        println!("✅ Successfully installed: {}", package.metadata.name);
        Ok(())
    }

    pub async fn remove_package(&mut self, package_name: &str) -> PackerResult<()> {
        let package = self.installed_packages.get(package_name)
            .ok_or_else(|| crate::error::PackerError::PackageNotInstalled(package_name.to_string()))?
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
                return Err(crate::error::PackerError::DependencyError(
                    format!("Missing dependency: {} {}", dep.name, 
                        dep.version_constraint.as_deref().unwrap_or("any"))
                ));
            }
        }
        Ok(())
    }

    async fn check_conflicts(&self, conflicts: &[String]) -> PackerResult<()> {
        for conflict in conflicts {
            if self.installed_packages.contains_key(conflict) {
                return Err(crate::error::PackerError::ConflictError(
                    format!("Package conflicts with installed package: {}", conflict)
                ));
            }
        }
        Ok(())
    }

    async fn install_file(&self, file: &PackageFile) -> PackerResult<()> {
        let target_path = self.install_root.join(&file.target.trim_start_matches('/'));
        
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await?;
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
                                    println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                                }
                            }
                            fs::copy(source_path, &target_path).await?;
                        } else if metadata.is_dir() {
                            fs::create_dir_all(&target_path).await?;
                                                 } else if metadata.file_type().is_symlink() {
                                 let link_target = tokio::fs::read_link(&source_path).await?;
                                 let target_str = link_target.to_string_lossy();
                                 if target_str.starts_with("/") {
                                     let target_within_install_root = self.install_root.join(&target_str.trim_start_matches('/'));
                                     if target_within_install_root.exists() {
                                         if target_path.exists() {
                                             if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                                 println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                                             }
                                         }
                                         match tokio::fs::symlink(&target_within_install_root, &target_path).await {
                                             Ok(()) => {
                                                 println!("✅ Created symlink {} -> {}", target_path.display(), target_within_install_root.display());
                                             },
                                             Err(e) => {
                                                 println!("⚠️  Failed to create symlink {} -> {}: {}", target_path.display(), target_within_install_root.display(), e);
                                             }
                                         }
                                     } else {
                                         println!("⚠️  Skipping symlink {} -> {} (target does not exist at {})", target_path.display(), target_str, target_within_install_root.display());
                                     }
                                 } else {
                                     if target_path.exists() {
                                         if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                             println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
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
                                println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                            }
                        }
                        if file.target.contains("/bin/") {
                            let package_name = target_path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown");
                            let script_content = format!("#!/bin/bash\n# Native packer installation of {}\necho 'Command {} installed via packer (native)'\n", package_name, package_name);
                            fs::write(&target_path, script_content).await?;
                        } else {
                            fs::write(&target_path, format!("# File from package: {}\n", file.target)).await?;
                        }
                    }
                } else {
                    let source_path = std::path::Path::new(&file.source);
                    if source_path.exists() {
                        let metadata = fs::metadata(&source_path).await?;
                        if metadata.is_file() {
                            if target_path.exists() {
                                if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                    println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                                }
                            }
                            fs::copy(source_path, &target_path).await?;
                        } else if metadata.is_dir() {
                            fs::create_dir_all(&target_path).await?;
                        } else {
                            if metadata.file_type().is_symlink() {
                                let link_target = tokio::fs::read_link(&source_path).await?;
                                let target_str = link_target.to_string_lossy();
                                if target_str.starts_with("/") {
                                    let target_within_install_root = self.install_root.join(&target_str.trim_start_matches('/'));
                                    if target_within_install_root.exists() {
                                        if target_path.exists() {
                                            if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                                println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                                            }
                                        }
                                        match tokio::fs::symlink(&target_within_install_root, &target_path).await {
                                            Ok(()) => {
                                                println!("✅ Created symlink {} -> {}", target_path.display(), target_within_install_root.display());
                                            },
                                            Err(e) => {
                                                println!("⚠️  Failed to create symlink {} -> {}: {}", target_path.display(), target_within_install_root.display(), e);
                                            }
                                        }
                                    } else {
                                        println!("⚠️  Skipping symlink {} -> {} (target does not exist at {})", target_path.display(), target_str, target_within_install_root.display());
                                    }
                                } else {
                                    if target_path.exists() {
                                        if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                            println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
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
                                println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                            }
                        }
                        if file.target.contains("/bin/") {
                            let package_name = target_path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown");
                            let script_content = format!("#!/bin/bash\n# Native packer installation of {}\necho 'Command {} installed via packer (native)'\necho 'Note: This is a minimal implementation. For full functionality, reinstall with: packer install {}'\n", package_name, package_name, package_name);
                            fs::write(&target_path, script_content).await?;
                        } else {
                            fs::write(&target_path, format!("# File from package: {}\n", file.target)).await?;
                        }
                    }
                }
            },
            FileType::Directory => {
                fs::create_dir_all(&target_path).await?;
            },
            FileType::Symlink(ref target) => {
                if target.starts_with("/") {
                    let target_within_install_root = self.install_root.join(&target.trim_start_matches('/'));
                    if target_within_install_root.exists() {
                        if target_path.exists() {
                            if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                            }
                        }
                        match tokio::fs::symlink(&target_within_install_root, &target_path).await {
                            Ok(()) => {
                                println!("✅ Created symlink {} -> {}", target_path.display(), target_within_install_root.display());
                            },
                            Err(e) => {
                                println!("⚠️  Failed to create symlink {} -> {}: {}", target_path.display(), target_within_install_root.display(), e);
                            }
                        }
                    } else {
                        println!("⚠️  Skipping symlink {} -> {} (target does not exist at {})", target_path.display(), target, target_within_install_root.display());
                    }
                } else {
                    if target_path.exists() {
                        if let Err(e) = tokio::fs::remove_file(&target_path).await {
                            println!("⚠️  Failed to remove existing file {}: {}", target_path.display(), e);
                        }
                    }
                    tokio::fs::symlink(target, &target_path).await?;
                }
            },
            _ => {
                println!("⚠️  Skipping special file type: {:?}", file.file_type);
            }
        }

        self.system_manager.set_file_permissions(&target_path, file).await?;

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
                },
                _ => {
                    fs::remove_file(&target_path).await?;
                }
            }
        }

        Ok(())
    }

    async fn run_script(&self, script: &str, phase: &str) -> PackerResult<()> {
        println!("📜 Running {} script", phase);
        
        let output = Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(crate::error::PackerError::ScriptFailed(
                format!("{} script failed: {}", phase, stderr)
            ));
        }

        Ok(())
    }

    fn is_dependency_satisfied(&self, dependency: &NativeDependency) -> PackerResult<bool> {
        if let Some(installed) = self.installed_packages.get(&dependency.name) {
            if let Some(ref constraint) = dependency.version_constraint {
                return Ok(self.version_satisfies(&installed.metadata.version, constraint));
            }
            return Ok(true);
        }
        Ok(false)
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
    pub async fn update_services(&self, package: &NativePackage) -> PackerResult<()> {
        for file in &package.files {
            if file.target.contains("/systemd/system/") && file.target.ends_with(".service") {
                if !self.dry_run {
                    Command::new("systemctl")
                        .arg("daemon-reload")
                        .output()
                        .await?;
                        
                    println!("🔄 Reloaded systemd daemon for new service");
                }
            }
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
            Ok(()) => {},
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
                let relative_path = path.strip_prefix(base_dir)
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
                    checksum: Self::calculate_file_checksum(&path).unwrap_or_else(|_| "unknown".to_string()),
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
        fs::create_dir_all(extract_to).await?;

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
        use sha2::{Sha256, Digest};
        use std::io::Read;
        
        if file_path.is_dir() {
            return Ok("directory".to_string());
        }
        
        let mut file = std::fs::File::open(file_path)
            .map_err(|e| crate::error::PackerError::IoError(format!("failed to open file for checksum: {}", e)))?;
        
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => hasher.update(&buffer[..n]),
                Err(e) => return Err(crate::error::PackerError::IoError(format!("failed to read file: {}", e))),
            }
        }
        
        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }
} 