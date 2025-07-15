use crate::{error::PackerResult, PACKER_CONFIG};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_repositories")]
    pub repositories: Vec<RepositoryConfig>,

    #[serde(default = "default_install_root")]
    pub install_root: PathBuf,

    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,

    #[serde(default = "default_database_dir")]
    pub database_dir: PathBuf,

    #[serde(default = "default_max_parallel_downloads")]
    pub max_parallel_downloads: usize,

    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,

    #[serde(default = "default_verify_signatures")]
    pub verify_signatures: bool,

    #[serde(default = "default_verify_checksums")]
    pub verify_checksums: bool,

    #[serde(default = "default_keep_downloads")]
    pub keep_downloads: bool,

    #[serde(default = "default_auto_clean")]
    pub auto_clean: bool,

    #[serde(default = "default_clean_interval_days")]
    pub clean_interval_days: u32,

    #[serde(default = "default_compression_level")]
    pub compression_level: u32,

    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,

    #[serde(default = "default_retry_delay_seconds")]
    pub retry_delay_seconds: u64,

    #[serde(default = "default_http_proxy")]
    pub http_proxy: Option<String>,

    #[serde(default = "default_https_proxy")]
    pub https_proxy: Option<String>,

    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    #[serde(default = "default_arch")]
    pub arch: String,

    #[serde(default = "default_os")]
    pub os: String,

    #[serde(default = "default_package_format")]
    pub package_format: PackageFormat,

    #[serde(default = "default_compression_format")]
    pub compression_format: CompressionFormat,

    #[serde(default)]
    pub mirrors: HashMap<String, Vec<String>>,

    #[serde(default)]
    pub hooks: HashMap<String, String>,

    #[serde(default = "default_auto_discover")]
    pub auto_discover: bool,

    #[serde(default)]
    pub github_token: Option<String>,

    #[serde(default = "default_security_level")]
    pub security_level: SecurityLevel,

    #[serde(default)]
    pub profiles: HashMap<String, Profile>,

    #[serde(default = "default_parallel_installs")]
    pub parallel_installs: usize,

    #[serde(default)]
    pub security_policy: SecurityPolicy,

    #[serde(default)]
    pub trusted_maintainers: Vec<String>,

    #[serde(default)]
    pub blocked_packages: Vec<String>,

    #[serde(default)]
    pub gpg_config: GPGConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryConfig {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub priority: i32,
    pub repo_type: RepositoryType,
    pub trust_level: TrustLevel,
    pub mirror_urls: Vec<String>,
    pub arch: Option<String>,
    pub siglevel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepositoryType {
    #[serde(rename = "Packer")]
    Packer,
    #[serde(rename = "AUR")]
    AUR,
    #[serde(rename = "Arch")]
    Arch,
    #[serde(rename = "GitHub")]
    GitHub,
    #[serde(rename = "NPM")]
    NPM,
    #[serde(rename = "PyPI")]
    PyPI,
    #[serde(rename = "Debian")]
    Debian,
    #[serde(rename = "Ubuntu")]
    Ubuntu,
    #[serde(rename = "Fedora")]
    Fedora,
    #[serde(rename = "Custom")]
    Custom,
    #[serde(rename = "Flatpak")]
    Flatpak,
    #[serde(rename = "AppImage")]
    AppImage,
    #[serde(rename = "Nix")]
    Nix,
    #[serde(rename = "Homebrew")]
    Homebrew,
    #[serde(rename = "Cargo")]
    Cargo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustLevel {
    #[serde(rename = "trusted")]
    Trusted,
    #[serde(rename = "verified")]
    Verified,
    #[serde(rename = "community")]
    Community,
    #[serde(rename = "untrusted")]
    Untrusted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    #[serde(rename = "strict")]
    Strict,
    #[serde(rename = "moderate")]
    Moderate,
    #[serde(rename = "permissive")]
    Permissive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub repositories: Vec<String>,
    pub install_root: Option<String>,
    pub auto_update: bool,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageFormat {
    #[serde(rename = "tar")]
    Tar,
    #[serde(rename = "zip")]
    Zip,
    #[serde(rename = "deb")]
    Deb,
    #[serde(rename = "rpm")]
    Rpm,
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompressionFormat {
    #[serde(rename = "gzip")]
    Gzip,
    #[serde(rename = "bzip2")]
    Bzip2,
    #[serde(rename = "xz")]
    Xz,
    #[serde(rename = "zstd")]
    Zstd,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "auto")]
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    #[serde(default = "default_require_signatures")]
    pub require_signatures: bool,
    
    #[serde(default = "default_allow_untrusted_repos")]
    pub allow_untrusted_repos: bool,
    
    #[serde(default = "default_scan_for_vulnerabilities")]
    pub scan_for_vulnerabilities: bool,
    
    #[serde(default = "default_block_high_risk")]
    pub block_high_risk_packages: bool,
    
    #[serde(default = "default_quarantine_duration")]
    pub quarantine_duration_hours: u64,
    
    #[serde(default = "default_max_package_size")]
    pub max_package_size_mb: u64,
    
    #[serde(default = "default_allowed_protocols")]
    pub allowed_protocols: Vec<String>,
    
    #[serde(default)]
    pub sandbox_builds: bool,
    
    #[serde(default)]
    pub verify_build_reproducibility: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPGConfig {
    #[serde(default)]
    pub keyring_path: Option<String>,
    
    #[serde(default)]
    pub trusted_keyservers: Vec<String>,
    
    #[serde(default)]
    pub auto_import_keys: bool,
    
    #[serde(default = "default_key_trust_threshold")]
    pub minimum_trust_level: String,
    
    #[serde(default = "default_signature_algorithms")]
    pub allowed_signature_algorithms: Vec<String>,
}

impl Default for RepositoryType {
    fn default() -> Self {
        RepositoryType::Packer
    }
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Community
    }
}

impl Config {
    pub fn load(config_path: Option<&str>) -> PackerResult<Self> {
        let config_path = if let Some(path) = config_path {
            std::path::PathBuf::from(path)
        } else {
            PACKER_CONFIG.join("packer.toml")
        };

        if config_path.exists() && config_path.is_file() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            let config = Config::default();
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            config.save(&config_path)?;
            Ok(config)
        }
    }

    pub fn save(&self, path: &Path) -> PackerResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn get_repository(&self, name: &str) -> Option<&RepositoryConfig> {
        self.repositories.iter().find(|r| r.name == name)
    }

    pub fn get_enabled_repositories(&self) -> Vec<&RepositoryConfig> {
        self.repositories
            .iter()
            .filter(|r| r.enabled)
            .collect()
    }

    pub fn get_repositories_by_priority(&self) -> Vec<&RepositoryConfig> {
        let mut repos = self.get_enabled_repositories();
        repos.sort_by_key(|r| r.priority);
        repos
    }

    pub fn get_trusted_repositories(&self) -> Vec<&RepositoryConfig> {
        self.repositories
            .iter()
            .filter(|r| r.enabled && matches!(r.trust_level, TrustLevel::Trusted | TrustLevel::Verified))
            .collect()
    }

    pub fn get_mirrors(&self, repository: &str) -> Vec<&String> {
        self.mirrors
            .get(repository)
            .map(|mirrors| mirrors.iter().collect())
            .unwrap_or_default()
    }

    pub fn get_active_profile(&self) -> Option<&Profile> {
        std::env::var("PACKER_PROFILE")
            .ok()
            .and_then(|profile_name| self.profiles.get(&profile_name))
    }

    pub fn should_verify_signature(&self, repo: &RepositoryConfig) -> bool {
        match self.security_level {
            SecurityLevel::Strict => true,
            SecurityLevel::Moderate => matches!(repo.trust_level, TrustLevel::Trusted),
            SecurityLevel::Permissive => matches!(repo.trust_level, TrustLevel::Trusted),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repositories: default_repositories(),
            install_root: default_install_root(),
            cache_dir: default_cache_dir(),
            database_dir: default_database_dir(),
            max_parallel_downloads: default_max_parallel_downloads(),
            timeout_seconds: default_timeout_seconds(),
            verify_signatures: default_verify_signatures(),
            verify_checksums: default_verify_checksums(),
            keep_downloads: default_keep_downloads(),
            auto_clean: default_auto_clean(),
            clean_interval_days: default_clean_interval_days(),
            compression_level: default_compression_level(),
            retry_attempts: default_retry_attempts(),
            retry_delay_seconds: default_retry_delay_seconds(),
            http_proxy: default_http_proxy(),
            https_proxy: default_https_proxy(),
            user_agent: default_user_agent(),
            arch: default_arch(),
            os: default_os(),
            package_format: default_package_format(),
            compression_format: default_compression_format(),
            mirrors: HashMap::new(),
            hooks: HashMap::new(),
            auto_discover: default_auto_discover(),
            github_token: None,
            security_level: default_security_level(),
            profiles: HashMap::new(),
            parallel_installs: default_parallel_installs(),
            security_policy: SecurityPolicy::default(),
            trusted_maintainers: Vec::new(),
            blocked_packages: Vec::new(),
            gpg_config: GPGConfig::default(),
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            require_signatures: default_require_signatures(),
            allow_untrusted_repos: default_allow_untrusted_repos(),
            scan_for_vulnerabilities: default_scan_for_vulnerabilities(),
            block_high_risk_packages: default_block_high_risk(),
            quarantine_duration_hours: default_quarantine_duration(),
            max_package_size_mb: default_max_package_size(),
            allowed_protocols: default_allowed_protocols(),
            sandbox_builds: false,
            verify_build_reproducibility: false,
        }
    }
}

impl Default for GPGConfig {
    fn default() -> Self {
        Self {
            keyring_path: None,
            trusted_keyservers: vec![
                "keys.gnupg.net".to_string(),
                "keyserver.ubuntu.com".to_string(),
                "pgp.mit.edu".to_string(),
            ],
            auto_import_keys: false,
            minimum_trust_level: default_key_trust_threshold(),
            allowed_signature_algorithms: default_signature_algorithms(),
        }
    }
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self {
            name: "aur".to_string(),
            url: "https://aur.archlinux.org/".to_string(),
            enabled: true,
            priority: 1,
            repo_type: RepositoryType::AUR,
            trust_level: TrustLevel::Community,
            mirror_urls: vec!["https://aur.archlinux.org/".to_string()],
            arch: Some("any".to_string()),
            siglevel: Some("Never".to_string()),
        }
    }
}

fn default_repositories() -> Vec<RepositoryConfig> {
    vec![
        RepositoryConfig {
            name: "aur".to_string(),
            url: "https://aur.archlinux.org/".to_string(),
            enabled: true,
            priority: 1,
            repo_type: RepositoryType::AUR,
            trust_level: TrustLevel::Community,
            mirror_urls: vec!["https://aur.archlinux.org/".to_string()],
            arch: Some("any".to_string()),
            siglevel: Some("Never".to_string()),
        },
    ]
}

fn default_install_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from("C:\\Program Files\\packer")
    } else if unsafe { libc::geteuid() } == 0 {
        PathBuf::from("/usr/local")
    } else {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string())).join(".local")
    }
}

fn default_cache_dir() -> PathBuf {
    crate::PACKER_CACHE.clone()
}

fn default_database_dir() -> PathBuf {
    crate::PACKER_HOME.join("db.json")
}

fn default_max_parallel_downloads() -> usize {
    num_cpus::get().min(8)
}

fn default_parallel_installs() -> usize {
    num_cpus::get().min(4)
}

fn default_require_signatures() -> bool {
    false
}

fn default_allow_untrusted_repos() -> bool {
    true
}

fn default_scan_for_vulnerabilities() -> bool {
    true
}

fn default_block_high_risk() -> bool {
    true
}

fn default_quarantine_duration() -> u64 {
    24
}

fn default_max_package_size() -> u64 {
    1024
}

fn default_allowed_protocols() -> Vec<String> {
    vec![
        "https".to_string(),
        "ssh".to_string(),
    ]
}

fn default_key_trust_threshold() -> String {
    "marginal".to_string()
}

fn default_signature_algorithms() -> Vec<String> {
    vec![
        "RSA".to_string(),
        "ECDSA".to_string(),
        "EdDSA".to_string(),
    ]
}

fn default_timeout_seconds() -> u64 {
    300
}

fn default_verify_signatures() -> bool {
    true
}

fn default_verify_checksums() -> bool {
    true
}

fn default_keep_downloads() -> bool {
    false
}

fn default_auto_clean() -> bool {
    true
}

fn default_clean_interval_days() -> u32 {
    7
}

fn default_compression_level() -> u32 {
    6
}

fn default_retry_attempts() -> u32 {
    3
}

fn default_retry_delay_seconds() -> u64 {
    2
}

fn default_http_proxy() -> Option<String> {
    std::env::var("HTTP_PROXY").ok()
}

fn default_https_proxy() -> Option<String> {
    std::env::var("HTTPS_PROXY").ok()
}

fn default_user_agent() -> String {
    format!("packer/{} ({}; {})", crate::PACKER_VERSION, std::env::consts::OS, std::env::consts::ARCH)
}

fn default_arch() -> String {
    std::env::consts::ARCH.to_string()
}

fn default_os() -> String {
    std::env::consts::OS.to_string()
}

fn default_package_format() -> PackageFormat {
    PackageFormat::Auto
}

fn default_compression_format() -> CompressionFormat {
    CompressionFormat::Auto
}

fn default_auto_discover() -> bool {
    false
}

fn default_security_level() -> SecurityLevel {
    SecurityLevel::Permissive
} 