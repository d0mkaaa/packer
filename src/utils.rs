use crate::error::{PackerError, PackerResult};
use std::path::{Path, PathBuf};
use log::{debug, info, warn};
use std::collections::HashMap;
#[derive(Debug, Clone)]
pub struct PackageExtractor {
    supported_formats: HashMap<String, ExtractionMethod>,
    temp_dir: PathBuf,
    security_settings: SecuritySettings,
}
#[derive(Debug, Clone)]
pub struct SecuritySettings {
    pub max_file_size: u64,
    pub max_files: usize,
    pub allowed_paths: Vec<String>,
    pub blocked_paths: Vec<String>,
    pub check_symlinks: bool,
    pub verify_checksums: bool,
}
#[derive(Debug, Clone)]
pub enum ExtractionMethod {
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZstd,
    Zip,
    SevenZip,
    Deb,
    Rpm,
    AppImage,
    Flatpak,
}
impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            max_file_size: 1024 * 1024 * 1024,
            max_files: 100_000,
            allowed_paths: vec![
                "usr/".to_string(),
                "opt/".to_string(),
                "bin/".to_string(),
                "lib/".to_string(),
                "share/".to_string(),
            ],
            blocked_paths: vec![
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "/root/".to_string(),
                "../".to_string(),
                "..\\".to_string(),
            ],
            check_symlinks: true,
            verify_checksums: true,
        }
    }
}
impl PackageExtractor {
    pub fn new() -> PackerResult<Self> {
        let temp_dir = tempfile::tempdir()?.keep();
        let mut supported_formats = HashMap::new();
        supported_formats.insert("tar".to_string(), ExtractionMethod::Tar);
        supported_formats.insert("tar.gz".to_string(), ExtractionMethod::TarGz);
        supported_formats.insert("tgz".to_string(), ExtractionMethod::TarGz);
        supported_formats.insert("tar.bz2".to_string(), ExtractionMethod::TarBz2);
        supported_formats.insert("tbz2".to_string(), ExtractionMethod::TarBz2);
        supported_formats.insert("tar.xz".to_string(), ExtractionMethod::TarXz);
        supported_formats.insert("txz".to_string(), ExtractionMethod::TarXz);
        supported_formats.insert("tar.zst".to_string(), ExtractionMethod::TarZstd);
        supported_formats.insert("zip".to_string(), ExtractionMethod::Zip);
        supported_formats.insert("7z".to_string(), ExtractionMethod::SevenZip);
        supported_formats.insert("deb".to_string(), ExtractionMethod::Deb);
        supported_formats.insert("rpm".to_string(), ExtractionMethod::Rpm);
        supported_formats.insert("appimage".to_string(), ExtractionMethod::AppImage);
        supported_formats.insert("flatpak".to_string(), ExtractionMethod::Flatpak);
        Ok(Self {
            supported_formats,
            temp_dir,
            security_settings: SecuritySettings::default(),
        })
    }
    pub fn with_security_settings(mut self, settings: SecuritySettings) -> Self {
        self.security_settings = settings;
        self
    }
    pub async fn extract_package(&self, archive_path: &Path, extract_to: &Path) -> PackerResult<ExtractionResult> {
        info!("Extracting package from {:?} to {:?}", archive_path, extract_to);
        if !archive_path.exists() {
            return Err(PackerError::InstallationFailed("Archive file does not exist".into()));
        }
        let format = self.detect_format(archive_path)?;
        debug!("Detected format: {:?}", format);
        self.validate_security_constraints(archive_path).await?;
        let extraction_result = match format {
            ExtractionMethod::Tar => self.extract_tar(archive_path, extract_to, None).await,
            ExtractionMethod::TarGz => self.extract_tar(archive_path, extract_to, Some(CompressionType::Gzip)).await,
            ExtractionMethod::TarBz2 => self.extract_tar(archive_path, extract_to, Some(CompressionType::Bzip2)).await,
            ExtractionMethod::TarXz => self.extract_tar(archive_path, extract_to, Some(CompressionType::Xz)).await,
            ExtractionMethod::TarZstd => self.extract_tar(archive_path, extract_to, Some(CompressionType::Zstd)).await,
            ExtractionMethod::Zip => self.extract_zip(archive_path, extract_to).await,
            ExtractionMethod::Deb => self.extract_deb(archive_path, extract_to).await,
            ExtractionMethod::Rpm => self.extract_rpm(archive_path, extract_to).await,
            ExtractionMethod::AppImage => self.extract_appimage(archive_path, extract_to).await,
            _ => Err(PackerError::InstallationFailed(format!("Format {:?} not yet implemented", format))),
        }?;
        self.verify_extraction(&extraction_result).await?;
        info!("Successfully extracted {} files ({} bytes)", 
              extraction_result.files_extracted, extraction_result.bytes_extracted);
        Ok(extraction_result)
    }
    fn detect_format(&self, path: &Path) -> PackerResult<ExtractionMethod> {
        let file_name = path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| PackerError::InstallationFailed("Invalid file name".into()))?
            .to_lowercase();
        for (ext, method) in &self.supported_formats {
            if file_name.ends_with(ext) {
                return Ok(method.clone());
            }
        }
        let magic_bytes = std::fs::read(path)
            .map_err(|_| PackerError::InstallationFailed("Cannot read file for format detection".into()))?
            .get(..32)
            .unwrap_or(&[])
            .to_vec();
        if magic_bytes.starts_with(b"\x1f\x8b") {
            return Ok(ExtractionMethod::TarGz);
        } else if magic_bytes.starts_with(b"BZ") {
            return Ok(ExtractionMethod::TarBz2);
        } else if magic_bytes.starts_with(b"\xfd7zXZ") {
            return Ok(ExtractionMethod::TarXz);
        } else if magic_bytes.starts_with(b"\x28\xb5\x2f\xfd") {
            return Ok(ExtractionMethod::TarZstd);
        } else if magic_bytes.starts_with(b"PK") {
            return Ok(ExtractionMethod::Zip);
        } else if magic_bytes.starts_with(b"!<arch>") {
            return Ok(ExtractionMethod::Deb);
        } else if magic_bytes.starts_with(b"\xed\xab\xee\xdb") {
            return Ok(ExtractionMethod::Rpm);
        }
        Err(PackerError::InstallationFailed("Cannot detect archive format".into()))
    }
    async fn validate_security_constraints(&self, archive_path: &Path) -> PackerResult<()> {
        let metadata = tokio::fs::metadata(archive_path).await?;
        if metadata.len() > self.security_settings.max_file_size {
            return Err(PackerError::InstallationFailed(format!(
                "Archive size {} exceeds maximum allowed size {}",
                metadata.len(), self.security_settings.max_file_size
            )));
        }
        Ok(())
    }
    async fn extract_tar(&self, archive_path: &Path, extract_to: &Path, compression: Option<CompressionType>) -> PackerResult<ExtractionResult> {
        self.extract_tar_sync(archive_path, extract_to, compression)
    }
    fn extract_tar_sync(&self, archive_path: &Path, extract_to: &Path, compression: Option<CompressionType>) -> PackerResult<ExtractionResult> {
        use std::fs::File;
        use flate2::read::GzDecoder;
        use bzip2::read::BzDecoder;
        use tar::Archive;
        let file = File::open(archive_path)?;
        let mut files_extracted = 0;
        let mut bytes_extracted = 0;
        let mut extracted_files = Vec::new();
        let archive: Box<dyn std::io::Read> = match compression {
            Some(CompressionType::Gzip) => Box::new(GzDecoder::new(file)),
            Some(CompressionType::Bzip2) => Box::new(BzDecoder::new(file)),
            Some(CompressionType::Xz) => {
                return Err(PackerError::InstallationFailed("XZ compression requires async extraction".into()));
            }
            Some(CompressionType::Zstd) => {
                Box::new(zstd::Decoder::new(file)?)
            }
            None => Box::new(file),
        };
        let mut tar = Archive::new(archive);
        for entry in tar.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;
            let path_buf = path.to_path_buf();
            if !self.is_safe_path(&path_buf)? {
                warn!("Skipping unsafe path: {:?}", path_buf);
                continue;
            }
            let output_path = extract_to.join(&path_buf);
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            entry.unpack(&output_path)?;
            files_extracted += 1;
            bytes_extracted += entry.size();
            extracted_files.push(ExtractedFile {
                path: path_buf.clone(),
                size: entry.size(),
                permissions: entry.header().mode()?,
                file_type: self.classify_file_type(&path_buf),
            });
            if files_extracted > self.security_settings.max_files {
                return Err(PackerError::InstallationFailed("Too many files in archive".into()));
            }
        }
        Ok(ExtractionResult {
            files_extracted,
            bytes_extracted,
            extracted_files,
            extraction_time: std::time::Duration::from_secs(0),
        })
    }
    async fn extract_zip(&self, archive_path: &Path, extract_to: &Path) -> PackerResult<ExtractionResult> {
        use std::fs::File;
        use zip::ZipArchive;
        let file = File::open(archive_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut files_extracted = 0;
        let mut bytes_extracted = 0;
        let mut extracted_files = Vec::new();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_path = match file.enclosed_name() {
                Some(path) => path.to_owned(),
                None => {
                    warn!("Skipping file with unsafe name");
                    continue;
                }
            };
            if !self.is_safe_path(&file_path)? {
                warn!("Skipping unsafe path: {:?}", file_path);
                continue;
            }
            let outpath = extract_to.join(&file_path);
            if file.is_dir() {
                std::fs::create_dir_all(&outpath)?;
            } else {
                if let Some(parent) = outpath.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let mut outfile = File::create(&outpath)?;
                std::io::copy(&mut file, &mut outfile)?;
                files_extracted += 1;
                bytes_extracted += file.size();
                extracted_files.push(ExtractedFile {
                    path: file_path,
                    size: file.size(),
                    permissions: 0o755,
                    file_type: self.classify_file_type(&PathBuf::from(file.name())),
                });
            }
            if files_extracted > self.security_settings.max_files {
                return Err(PackerError::InstallationFailed("Too many files in archive".into()));
            }
        }
        Ok(ExtractionResult {
            files_extracted,
            bytes_extracted,
            extracted_files,
            extraction_time: std::time::Duration::from_secs(0),
        })
    }
    async fn extract_deb(&self, archive_path: &Path, extract_to: &Path) -> PackerResult<ExtractionResult> {
        let temp_dir = tempfile::tempdir()?;
        self.extract_ar(archive_path, temp_dir.path()).await?;
        let data_archive = self.find_data_archive(temp_dir.path())?;
        let result = Box::pin(self.extract_package(&data_archive, extract_to)).await?;
        Ok(result)
    }
    async fn extract_rpm(&self, _archive_path: &Path, _extract_to: &Path) -> PackerResult<ExtractionResult> {
        warn!("RPM extraction not fully implemented");
        Err(PackerError::InstallationFailed("RPM extraction requires rpm2cpio".into()))
    }
    async fn extract_appimage(&self, archive_path: &Path, extract_to: &Path) -> PackerResult<ExtractionResult> {
        let output = tokio::process::Command::new(archive_path)
            .arg("--appimage-extract")
            .current_dir(extract_to)
            .output()
            .await?;
        if !output.status.success() {
            return Err(PackerError::InstallationFailed("Failed to extract AppImage".into()));
        }
        let extracted_dir = extract_to.join("squashfs-root");
        let file_count = self.count_files_recursive(&extracted_dir)?;
        Ok(ExtractionResult {
            files_extracted: file_count,
            bytes_extracted: 0,
            extracted_files: Vec::new(),
            extraction_time: std::time::Duration::from_secs(0),
        })
    }
    async fn extract_ar(&self, archive_path: &Path, extract_to: &Path) -> PackerResult<()> {
        warn!("AR extraction not implemented - using system ar command");
        let output = tokio::process::Command::new("ar")
            .arg("x")
            .arg(archive_path)
            .current_dir(extract_to)
            .output()
            .await?;
        if !output.status.success() {
            return Err(PackerError::InstallationFailed("Failed to extract AR archive".into()));
        }
        Ok(())
    }
    fn find_data_archive(&self, dir: &Path) -> PackerResult<PathBuf> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("data.tar") {
                return Ok(entry.path());
            }
        }
        Err(PackerError::InstallationFailed("No data archive found in deb package".into()))
    }
    fn is_safe_path(&self, path: &Path) -> PackerResult<bool> {
        let path_str = path.to_string_lossy();
        if path_str.contains("../") || path_str.contains("..\\") {
            return Ok(false);
        }
        for blocked in &self.security_settings.blocked_paths {
            if path_str.contains(blocked) {
                return Ok(false);
            }
        }
        if path.is_absolute() {
            return Ok(false);
        }
        if !self.security_settings.allowed_paths.is_empty() {
            let allowed = self.security_settings.allowed_paths.iter()
                .any(|allowed_path| path_str.starts_with(allowed_path));
            let is_aur_package = path_str.contains("PKGBUILD") || 
                               path_str.contains(".SRCINFO") || 
                               path_str.ends_with(".install") ||
                               path_str.ends_with(".sh") ||
                               path_str.ends_with(".patch") ||
                               path_str.ends_with(".diff") ||
                               path_str.ends_with(".conf") ||
                               path_str.ends_with(".service") ||
                               path_str.ends_with(".desktop") ||
                               path_str.ends_with(".xml") ||
                               path_str.ends_with("/") ||
                               !path_str.contains("/");
            if !allowed && !is_aur_package {
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn classify_file_type(&self, path: &Path) -> FileType {
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            match extension.to_lowercase().as_str() {
                "exe" | "bin" | "" if self.is_executable(path) => FileType::Executable,
                "so" | "dll" | "dylib" => FileType::Library,
                "conf" | "config" | "cfg" | "ini" | "toml" | "yaml" | "yml" | "json" => FileType::Configuration,
                "txt" | "md" | "rst" | "doc" => FileType::Documentation,
                "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" => FileType::Asset,
                _ => FileType::Data,
            }
        } else {
            FileType::Data
        }
    }
    fn is_executable(&self, path: &Path) -> bool {
        path.parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .map(|name| name == "bin" || name == "sbin")
            .unwrap_or(false)
    }
    async fn verify_extraction(&self, result: &ExtractionResult) -> PackerResult<()> {
        if result.files_extracted == 0 {
            return Err(PackerError::InstallationFailed("No files were extracted".into()));
        }
        Ok(())
    }
    fn count_files_recursive(&self, dir: &Path) -> PackerResult<usize> {
        let mut count = 0;
        let entries = std::fs::read_dir(dir)?;
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_file() {
                count += 1;
            } else if file_type.is_dir() {
                count += self.count_files_recursive(&entry.path())?;
            }
        }
        Ok(count)
    }
}
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    pub files_extracted: usize,
    pub bytes_extracted: u64,
    pub extracted_files: Vec<ExtractedFile>,
    pub extraction_time: std::time::Duration,
}
#[derive(Debug, Clone)]
pub struct ExtractedFile {
    pub path: PathBuf,
    pub size: u64,
    pub permissions: u32,
    pub file_type: FileType,
}
#[derive(Debug, Clone)]
pub enum FileType {
    Executable,
    Library,
    Configuration,
    Documentation,
    Asset,
    Data,
}
#[derive(Debug, Clone)]
pub enum CompressionType {
    Gzip,
    Bzip2,
    Xz,
    Zstd,
}
pub fn validate_package_name(name: &str) -> PackerResult<()> {
    if name.is_empty() {
        return Err(PackerError::InvalidPackageName("Package name cannot be empty".into()));
    }
    for c in name.chars() {
        if !c.is_alphanumeric() && c != '-' && c != '_' && c != '.' {
            return Err(PackerError::InvalidPackageName(
                format!("Package name contains invalid character: {}", c)
            ));
        }
    }
    if name.len() > 100 {
        return Err(PackerError::InvalidPackageName(
            "Package name too long (max 100 characters)".into()
        ));
    }
    Ok(())
}
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    format!("{:.1} {}", size, UNITS[unit_index])
}
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    }
}
pub fn ensure_directory(path: &Path) -> PackerResult<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}
pub fn calculate_checksum(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}
pub fn calculate_file_checksum(path: &Path) -> PackerResult<String> {
    use std::fs::File;
    use std::io::Read;
    use sha2::{Digest, Sha256};
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
pub fn is_root_user() -> bool {
    unsafe { libc::geteuid() == 0 }
}
pub fn require_root() -> PackerResult<()> {
    if !is_root_user() {
        return Err(PackerError::PermissionDenied(
            "This operation requires root privileges".into()
        ));
    }
    Ok(())
}
pub fn get_system_arch() -> String {
    std::env::consts::ARCH.to_string()
}
pub fn get_system_os() -> String {
    std::env::consts::OS.to_string()
}
pub fn parse_version(version: &str) -> PackerResult<semver::Version> {
    semver::Version::parse(version)
        .map_err(|e| PackerError::InvalidVersion(format!("Invalid version {}: {}", version, e)))
}
pub fn parse_version_req(version_req: &str) -> PackerResult<semver::VersionReq> {
    semver::VersionReq::parse(version_req)
        .map_err(|e| PackerError::InvalidVersion(format!("Invalid version requirement {}: {}", version_req, e)))
}
pub fn compare_versions(version1: &str, version2: &str) -> PackerResult<std::cmp::Ordering> {
    let v1 = parse_version(version1)?;
    let v2 = parse_version(version2)?;
    Ok(v1.cmp(&v2))
}
pub fn is_newer_version(current: &str, newer: &str) -> PackerResult<bool> {
    Ok(compare_versions(current, newer)? == std::cmp::Ordering::Less)
}
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}
pub fn get_file_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase())
}
pub fn is_archive_file(path: &Path) -> bool {
    if let Some(ext) = get_file_extension(path) {
        matches!(ext.as_str(), "tar" | "gz" | "bz2" | "zip" | "deb" | "rpm" | "xz" | "zst")
    } else {
        false
    }
}
pub async fn extract_archive(archive_path: &Path, extract_to: &Path) -> PackerResult<ExtractionResult> {
    let extractor = PackageExtractor::new()?;
    extractor.extract_package(archive_path, extract_to).await
}
pub fn run_command(cmd: &str, args: &[&str]) -> PackerResult<()> {
    use std::process::Command;
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| PackerError::CriticalSystemError(format!("Failed to run command {}: {}", cmd, e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PackerError::CriticalSystemError(
            format!("Command {} failed: {}", cmd, stderr)
        ));
    }
    Ok(())
}
pub fn run_command_with_output(cmd: &str, args: &[&str]) -> PackerResult<String> {
    use std::process::Command;
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| PackerError::CriticalSystemError(format!("Failed to run command {}: {}", cmd, e)))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(PackerError::CriticalSystemError(
            format!("Command {} failed: {}", cmd, stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| PackerError::CriticalSystemError(format!("Invalid UTF-8 in command output: {}", e)))?;
    Ok(stdout)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_validate_package_name() {
        assert!(validate_package_name("valid-package").is_ok());
        assert!(validate_package_name("valid_package").is_ok());
        assert!(validate_package_name("valid.package").is_ok());
        assert!(validate_package_name("").is_err());
        assert!(validate_package_name("invalid package").is_err());
    }
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1024 * 1024), "1.0 MB");
        assert_eq!(format_size(1024 * 1024 * 1024), "1.0 GB");
    }
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
    }
    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test file.txt"), "test_file.txt");
        assert_eq!(sanitize_filename("valid-name.tar.gz"), "valid-name.tar.gz");
    }
    #[test]
    fn test_compare_versions() {
        assert!(compare_versions("1.0.0", "2.0.0").unwrap() == std::cmp::Ordering::Less);
        assert!(compare_versions("2.0.0", "1.0.0").unwrap() == std::cmp::Ordering::Greater);
        assert!(compare_versions("1.0.0", "1.0.0").unwrap() == std::cmp::Ordering::Equal);
    }
} 