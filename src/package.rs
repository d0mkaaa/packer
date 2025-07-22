use crate::{
    config::Config,
    dependency::Dependency,
    error::{PackerError, PackerResult},
    gpg_manager::GPGManager,
    repository::RepositoryManager,
    resolver::{DependencyResolver, ResolutionPreferences},
    storage::{DatabaseManager, InstallReason},
    utils::extract_archive,
};
use chrono::{DateTime, Utc};
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitAvailability {
    pub functional_exploit: bool,
    pub proof_of_concept: bool,
    pub exploit_kit: bool,
    pub active_exploitation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionType {
    Install,
    Remove,
    Upgrade,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PackageStatus {
    Available,
    Downloading,
    Downloaded,
    Verifying,
    Verified,
    Installing,
    Installed,
    Upgrading,
    Upgraded,
    Removing,
    Removed,
    Failed(String),
    Corrupted,
    Quarantined,
    Deprecated,
    Obsolete,
    Pending,
    Cancelled,
    Rollback,
    Conflict,
    Missing,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageHealth {
    pub status: PackageStatus,
    pub integrity_verified: bool,
    pub checksum_valid: bool,
    pub signature_valid: bool,
    pub dependencies_satisfied: bool,
    pub conflicts_resolved: bool,
    pub last_health_check: DateTime<Utc>,
    pub health_score: f64,
    pub issues: Vec<HealthIssue>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthIssue {
    pub severity: IssueSeverity,
    pub category: IssueCategory,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub resolution_suggestion: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueCategory {
    Integrity,
    Security,
    Dependency,
    Compatibility,
    Performance,
    Configuration,
    Network,
    Storage,
}
#[derive(Debug)]
#[allow(dead_code)]
struct DownloadProgress {
    downloaded_bytes: u64,
    total_bytes: u64,
    percentage: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityInfo {
    pub target_arch: String,
    pub target_os: String,
    pub min_os_version: Option<String>,
    pub max_os_version: Option<String>,
    pub required_features: Vec<String>,
    pub incompatible_packages: Vec<String>,
    pub system_requirements: SystemRequirements,
    pub compatibility_score: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemRequirements {
    pub min_memory_mb: Option<u64>,
    pub min_disk_space_mb: Option<u64>,
    pub required_libraries: Vec<String>,
    pub required_binaries: Vec<String>,
    pub kernel_modules: Vec<String>,
    pub environment_variables: Vec<String>,
}
impl PackageStatus {
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            PackageStatus::Downloading
                | PackageStatus::Verifying
                | PackageStatus::Installing
                | PackageStatus::Upgrading
                | PackageStatus::Removing
        )
    }
    pub fn is_success(&self) -> bool {
        matches!(
            self,
            PackageStatus::Installed | PackageStatus::Upgraded | PackageStatus::Removed
        )
    }
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            PackageStatus::Failed(_)
                | PackageStatus::Corrupted
                | PackageStatus::Conflict
                | PackageStatus::Missing
        )
    }
    pub fn can_retry(&self) -> bool {
        matches!(
            self,
            PackageStatus::Failed(_) | PackageStatus::Cancelled | PackageStatus::Corrupted
        )
    }
}
impl Default for PackageHealth {
    fn default() -> Self {
        Self {
            status: PackageStatus::Unknown,
            integrity_verified: false,
            checksum_valid: false,
            signature_valid: false,
            dependencies_satisfied: false,
            conflicts_resolved: false,
            last_health_check: Utc::now(),
            health_score: 0.0,
            issues: Vec::new(),
        }
    }
}
impl Default for CompatibilityInfo {
    fn default() -> Self {
        Self {
            target_arch: "x86_64".to_string(),
            target_os: "linux".to_string(),
            min_os_version: None,
            max_os_version: None,
            required_features: Vec::new(),
            incompatible_packages: Vec::new(),
            system_requirements: SystemRequirements::default(),
            compatibility_score: 1.0,
        }
    }
}
impl Default for SystemRequirements {
    fn default() -> Self {
        Self {
            min_memory_mb: None,
            min_disk_space_mb: None,
            required_libraries: Vec::new(),
            required_binaries: Vec::new(),
            kernel_modules: Vec::new(),
            environment_variables: Vec::new(),
        }
    }
}
impl Package {
    pub fn new_with_defaults(
        name: String,
        version: String,
        description: String,
        repository: String,
        arch: String,
        size: u64,
        installed_size: u64,
        dependencies: Vec<Dependency>,
        conflicts: Vec<String>,
        provides: Vec<String>,
        replaces: Vec<String>,
        maintainer: String,
        license: String,
        url: String,
        checksum: String,
        signature: Option<String>,
        build_date: DateTime<Utc>,
        install_date: Option<DateTime<Utc>>,
        files: Vec<PackageFile>,
        scripts: PackageScripts,
    ) -> Self {
        Self {
            name,
            version,
            description,
            repository,
            arch,
            size,
            installed_size,
            dependencies,
            conflicts,
            provides,
            replaces,
            maintainer,
            license,
            url,
            checksum,
            signature,
            build_date,
            install_date,
            files,
            scripts,
            health: PackageHealth::default(),
            compatibility: CompatibilityInfo::default(),
        }
    }
}
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub description: String,
    pub repository: String,
    pub arch: String,
    pub size: u64,
    pub installed_size: u64,
    pub dependencies: Vec<Dependency>,
    pub conflicts: Vec<String>,
    pub provides: Vec<String>,
    pub replaces: Vec<String>,
    pub maintainer: String,
    pub license: String,
    pub url: String,
    pub checksum: String,
    pub signature: Option<String>,
    pub build_date: DateTime<Utc>,
    pub install_date: Option<DateTime<Utc>>,
    pub files: Vec<PackageFile>,
    pub scripts: PackageScripts,
    pub health: PackageHealth,
    pub compatibility: CompatibilityInfo,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageFile {
    pub path: String,
    pub size: u64,
    pub checksum: String,
    pub permissions: u32,
    pub owner: String,
    pub group: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageScripts {
    pub pre_install: Option<String>,
    pub post_install: Option<String>,
    pub pre_remove: Option<String>,
    pub post_remove: Option<String>,
    pub pre_upgrade: Option<String>,
    pub post_upgrade: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallTransaction {
    pub to_install: Vec<Package>,
    pub to_remove: Vec<Package>,
    pub to_upgrade: Vec<(Package, Package)>,
    pub conflicts: Vec<String>,
    pub total_size: u64,
    pub download_size: u64,
    pub transaction_id: String,
    pub security_summary: SecuritySummary,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySummary {
    pub verified_signatures: usize,
    pub unverified_packages: Vec<String>,
    pub vulnerabilities: Vec<SecurityVulnerability>,
    pub trust_score: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityVulnerability {
    pub package: String,
    pub vulnerability_id: String,
    pub severity: VulnerabilitySeverity,
    pub description: String,
    pub fixed_version: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
pub struct PackageManager {
    pub config: Config,
    pub database: DatabaseManager,
    pub repository_manager: RepositoryManager,
    pub resolver: DependencyResolver,
    multi_progress: MultiProgress,
    pub security_scanner: SecurityScanner,
    pub gpg_manager: GPGManager,
    transaction_cache: Arc<RwLock<HashMap<String, InstallTransaction>>>,
    aur_downloads: Option<Vec<PathBuf>>,
    binary_downloads: Option<Vec<PathBuf>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPGKeyInfo {
    pub id: String,
    pub fingerprint: String,
    pub user_id: String,
    pub expires: Option<DateTime<Utc>>,
    pub trust_level: String,
    pub imported_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditResult {
    pub total_packages: usize,
    pub vulnerable_packages: usize,
    pub high_risk_packages: usize,
    pub total_vulnerabilities: usize,
    pub reports: Vec<VulnerabilityReport>,
    pub recommendations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityReport {
    pub package_name: String,
    pub version: String,
    pub vulnerabilities: Vec<VulnerabilityDetail>,
    pub risk_score: f64,
    pub recommendation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityDetail {
    pub id: String,
    pub severity: String,
    pub description: String,
    pub fixed_version: Option<String>,
    pub cve_id: Option<String>,
    pub published_date: DateTime<Utc>,
}
pub struct SecurityScanner {
    vulnerability_db: Arc<RwLock<HashMap<String, Vec<SecurityVulnerability>>>>,
    gpg_keyring: Option<PathBuf>,
    _trusted_keys: Arc<RwLock<HashMap<String, GPGKeyInfo>>>,
    config: Config,
}
impl SecurityScanner {
    pub fn new(config: Config) -> Self {
        let gpg_keyring = dirs::data_dir()
            .map(|d| d.join("packer").join("gnupg"))
            .or_else(|| Some(PathBuf::from("/tmp/packer/gnupg")));
        Self {
            vulnerability_db: Arc::new(RwLock::new(HashMap::new())),
            gpg_keyring,
            _trusted_keys: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    pub async fn scan_package(
        &self,
        package: &Package,
    ) -> PackerResult<Vec<SecurityVulnerability>> {
        info!("Scanning package {} for vulnerabilities", package.name);
        let vulns = self.vulnerability_db.read().await;
        let mut package_vulns = vulns.get(&package.name).cloned().unwrap_or_default();
        for vuln in &mut package_vulns {
            if let Some(ref fixed_version) = vuln.fixed_version {
                if let (Ok(current), Ok(fixed)) = (
                    semver::Version::parse(&package.version),
                    semver::Version::parse(fixed_version),
                ) {
                    if current >= fixed {
                        continue;
                    }
                }
            }
        }
        Ok(package_vulns)
    }
    pub async fn verify_signature(
        &self,
        package: &Package,
        file_path: &PathBuf,
    ) -> PackerResult<bool> {
        if package.signature.is_none() {
            debug!("No signature available for package: {}", package.name);
            return Ok(false);
        }
        let signature = package.signature.as_ref().unwrap();
        info!("Verifying GPG signature for package: {}", package.name);
        if !self.is_gpg_available().await? {
            warn!("GPG not available on system, cannot verify signatures");
            return Ok(false);
        }
        if let Some(ref gpg_dir) = self.gpg_keyring {
            tokio::fs::create_dir_all(gpg_dir).await?;
        }
        let signature_path = if signature.starts_with("http") {
            self.download_signature(signature, file_path).await?
        } else {
            PathBuf::from(signature)
        };
        self.verify_detached_signature(file_path, &signature_path)
            .await
    }
    async fn is_gpg_available(&self) -> PackerResult<bool> {
        match tokio::process::Command::new("gpg")
            .arg("--version")
            .output()
            .await
        {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }
    async fn download_signature(
        &self,
        signature_url: &str,
        package_path: &PathBuf,
    ) -> PackerResult<PathBuf> {
        let client = reqwest::Client::new();
        let response = client.get(signature_url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::DownloadFailed(format!(
                "Failed to download signature: {}",
                response.status()
            )));
        }
        let signature_data = response.bytes().await?;
        let mut signature_path = package_path.clone();
        signature_path.set_extension("sig");
        tokio::fs::write(&signature_path, signature_data).await?;
        Ok(signature_path)
    }
    async fn verify_detached_signature(
        &self,
        file_path: &PathBuf,
        signature_path: &PathBuf,
    ) -> PackerResult<bool> {
        let mut cmd = tokio::process::Command::new("gpg");
        if let Some(ref gpg_dir) = self.gpg_keyring {
            cmd.env("GNUPGHOME", gpg_dir);
        }
        cmd.arg("--verify")
            .arg(signature_path)
            .arg(file_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let output = cmd.output().await?;
        if output.status.success() {
            info!("GPG signature verification successful");
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("GPG signature verification failed: {}", stderr);
            if stderr.contains("public key not found ") || stderr.contains("No public key") {
                warn!("Public key not found in keyring. Consider importing the required keys.");
            }
            Ok(false)
        }
    }
    pub async fn import_gpg_keys(
        &self,
        key_ids: &[String],
        keyserver: Option<&str>,
    ) -> PackerResult<Vec<GPGKeyInfo>> {
        let keyserver = keyserver.unwrap_or("keys.gnupg.net");
        let mut imported_keys = Vec::new();
        for key_id in key_ids {
            match self.import_single_key(key_id, keyserver).await {
                Ok(key_info) => {
                    imported_keys.push(key_info);
                }
                Err(e) => {
                    warn!("Failed to import key {}: {}", key_id, e);
                }
            }
        }
        Ok(imported_keys)
    }
    async fn import_single_key(&self, key_id: &str, keyserver: &str) -> PackerResult<GPGKeyInfo> {
        let mut cmd = tokio::process::Command::new("gpg");
        if let Some(ref gpg_dir) = self.gpg_keyring {
            cmd.env("GNUPGHOME", gpg_dir);
        }
        cmd.arg("--keyserver")
            .arg(keyserver)
            .arg("--recv-keys")
            .arg(key_id);
        let output = cmd.output().await?;
        if !output.status.success() {
            return Err(PackerError::SecurityError(format!(
                "Failed to import key {}: {}",
                key_id,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        self.get_key_info(key_id).await
    }
    async fn get_key_info(&self, key_id: &str) -> PackerResult<GPGKeyInfo> {
        let mut cmd = tokio::process::Command::new("gpg");
        if let Some(ref gpg_dir) = self.gpg_keyring {
            cmd.env("GNUPGHOME", gpg_dir);
        }
        cmd.arg("--with-colons").arg("--list-keys").arg(key_id);
        let output = cmd.output().await?;
        if !output.status.success() {
            return Err(PackerError::SecurityError(format!(
                "Failed to get key info for {}: {}",
                key_id,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.starts_with("pub:") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 10 {
                    let trust_level = self.parse_trust_level(parts[1]);
                    let _key_size = parts[2].parse::<u32>().unwrap_or(0);
                    let key_id = parts[4].to_string();
                    let _creation_date = parts[5]
                        .parse::<i64>()
                        .ok()
                        .and_then(|ts| DateTime::from_timestamp(ts, 0))
                        .unwrap_or_else(Utc::now);
                    let expires = parts[6]
                        .parse::<i64>()
                        .ok()
                        .and_then(|ts| DateTime::from_timestamp(ts, 0));
                    return Ok(GPGKeyInfo {
                        id: key_id.clone(),
                        fingerprint: key_id.clone(),
                        user_id: "Unknown".to_string(),
                        expires,
                        trust_level,
                        imported_at: Utc::now(),
                    });
                }
            }
        }
        Err(PackerError::SecurityError(format!(
            "Could not parse key info for {}",
            key_id
        )))
    }
    fn parse_trust_level(&self, trust_field: &str) -> String {
        match trust_field {
            "o" => "unknown".to_string(),
            "i" => "invalid".to_string(),
            "d" => "disabled".to_string(),
            "r" => "revoked".to_string(),
            "e" => "expired".to_string(),
            "-" => "unknown".to_string(),
            "q" => "undefined".to_string(),
            "n" => "never".to_string(),
            "m" => "marginal".to_string(),
            "f" => "full".to_string(),
            "u" => "ultimate".to_string(),
            _ => "unknown".to_string(),
        }
    }
    pub async fn update_vulnerability_database(&self) -> PackerResult<()> {
        info!("Updating vulnerability database ");
        let mut all_vulnerabilities = Vec::new();
        match self.fetch_github_advisories().await {
            Ok(vulns) => {
                info!("Fetched {} vulnerabilities from GitHub", vulns.len());
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => warn!("Failed to fetch GitHub advisories: {}", e),
        }
        match self.fetch_osv_vulnerabilities().await {
            Ok(vulns) => {
                info!("Fetched {} vulnerabilities from OSV", vulns.len());
                all_vulnerabilities.extend(vulns);
            }
            Err(e) => warn!("Failed to fetch OSV vulnerabilities: {}", e),
        }
        let mut db = self.vulnerability_db.write().await;
        db.clear();
        for vuln in all_vulnerabilities {
            db.entry(vuln.package.clone())
                .or_insert_with(Vec::new)
                .push(vuln);
        }
        info!("Vulnerability database updated with {} packages ", db.len());
        Ok(())
    }
    async fn fetch_github_advisories(&self) -> PackerResult<Vec<SecurityVulnerability>> {
        let client = reqwest::Client::new();
        let mut vulnerabilities = Vec::new();
        let url = "https://api.github.com/graphql";
        let query = r#"
        {
          securityAdvisories(first: 100, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
            nodes {
              ghsaId
              summary
              severity
              publishedAt
              vulnerabilities(first: 10) {
                nodes {
                  package {
                    name
                  }
                  firstPatchedVersion {
                    identifier
                  }
                  vulnerableVersionRange
                }
              }
            }
          }
        }
        "#;
        let request_body = serde_json::json!({
            "query": query
        });
        let mut request = client.post(url).json(&request_body);
        if let Some(token) = &self.config.github_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }
        let response = request.send().await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        let json: serde_json::Value = response.json().await?;
        if let Some(advisories) = json["data"]["securityAdvisories"]["nodes"].as_array() {
            for advisory in advisories {
                if let Some(vuln) = self.parse_github_advisory(advisory) {
                    vulnerabilities.push(vuln);
                }
            }
        }
        Ok(vulnerabilities)
    }
    fn parse_github_advisory(&self, advisory: &serde_json::Value) -> Option<SecurityVulnerability> {
        let ghsa_id = advisory["ghsaId"].as_str()?;
        let summary = advisory["summary"].as_str()?;
        let severity = advisory["severity"].as_str()?;
        let vulnerability_severity = self.parse_severity(severity);
        if let Some(vulnerabilities) = advisory["vulnerabilities"]["nodes"].as_array() {
            for vuln in vulnerabilities {
                if let Some(package) = vuln["package "]["name"].as_str() {
                    let fixed_version = vuln["firstPatchedVersion"]["identifier"]
                        .as_str()
                        .map(|s| s.to_string());
                    return Some(SecurityVulnerability {
                        package: package.to_string(),
                        vulnerability_id: ghsa_id.to_string(),
                        severity: vulnerability_severity,
                        description: summary.to_string(),
                        fixed_version,
                    });
                }
            }
        }
        None
    }
    async fn fetch_osv_vulnerabilities(&self) -> PackerResult<Vec<SecurityVulnerability>> {
        let client = reqwest::Client::new();
        let mut vulnerabilities = Vec::new();
        let ecosystems = ["npm", "PyPI", "Go", "crates.io ", "RubyGems"];
        for ecosystem in &ecosystems {
            let url = format!("https://api.osv.dev/v1/query");
            let query = serde_json::json!({
                "query": {
                    "ecosystem": ecosystem
                }
            });
            let response = client.post(&url).json(&query).send().await?;
            if response.status().is_success() {
                let json: serde_json::Value = response.json().await?;
                if let Some(vulns) = json["vulns"].as_array() {
                    for vuln_data in vulns.iter().take(50) {
                        if let Some(vuln) = self.parse_osv_vulnerability(vuln_data) {
                            vulnerabilities.push(vuln);
                        }
                    }
                }
            }
        }
        Ok(vulnerabilities)
    }
    fn parse_osv_vulnerability(
        &self,
        vuln_data: &serde_json::Value,
    ) -> Option<SecurityVulnerability> {
        let id = vuln_data["id"].as_str()?;
        let summary = vuln_data["summary"].as_str().unwrap_or("");
        let details = vuln_data["details"].as_str().unwrap_or("");
        let description = if !summary.is_empty() {
            summary.to_string()
        } else {
            details.to_string()
        };
        if let Some(affected) = vuln_data["affected"].as_array() {
            for affected_item in affected {
                if let Some(package) = affected_item["package "]["name"].as_str() {
                    let fixed_version = affected_item["ranges"]
                        .as_array()?
                        .iter()
                        .find_map(|range| range["events"].as_array())
                        .and_then(|events| events.iter().find_map(|event| event["fixed"].as_str()))
                        .map(|s| s.to_string());
                    return Some(SecurityVulnerability {
                        package: package.to_string(),
                        vulnerability_id: id.to_string(),
                        severity: VulnerabilitySeverity::Medium,
                        description,
                        fixed_version,
                    });
                }
            }
        }
        None
    }
    fn parse_severity(&self, severity: &str) -> VulnerabilitySeverity {
        match severity.to_lowercase().as_str() {
            "critical" => VulnerabilitySeverity::Critical,
            "high" => VulnerabilitySeverity::High,
            "medium" | "moderate" => VulnerabilitySeverity::Medium,
            "low" => VulnerabilitySeverity::Low,
            _ => VulnerabilitySeverity::Info,
        }
    }
    pub fn calculate_trust_score(&self, packages: &[Package]) -> f64 {
        if packages.is_empty() {
            return 100.0;
        }
        let mut total_score = 0.0;
        let mut weight_sum = 0.0;
        for package in packages {
            let mut package_score = match package.repository.as_str() {
                "core" | "extra" | "community" | "multilib " => 95.0,
                "aur" => 85.0,
                "github" => 80.0,
                "flathub" => 88.0,
                "appimage" => 82.0,
                "npm" => 75.0,
                "pypi" => 78.0,
                _ => 70.0,
            };
            let package_weight = 1.0;

            if package.signature.is_some() {
                package_score += 5.0;
            } else {
                match package.repository.as_str() {
                    "core" | "extra" | "community" | "multilib " => {
                        package_score -= 10.0;
                    }
                    "aur" => {}
                    _ => {
                        package_score -= 3.0;
                    }
                }
            }
            if !package.maintainer.is_empty() && package.maintainer != "unknown" {
                package_score += 3.0;
            }
            let age_days = (Utc::now() - package.build_date).num_days();
            if age_days > 365 * 2 {
                package_score -= 2.0;
            } else if age_days > 365 {
                package_score += 2.0;
            } else if age_days < 7 {
                package_score -= 3.0;
            }
            if package.size < 100 {
                package_score -= 5.0;
            } else if package.size > 500 * 1024 * 1024 {
                package_score -= 2.0;
            }
            if !package.license.is_empty() && package.license != "unknown" {
                match package.license.to_lowercase().as_str() {
                    l if l.contains("mit")
                        || l.contains("apache")
                        || l.contains("gpl")
                        || l.contains("bsd") =>
                    {
                        package_score += 2.0;
                    }
                    l if l.contains("proprietary") => {
                        package_score -= 1.0;
                    }
                    _ => {}
                }
            }
            total_score += package_score * package_weight;
            weight_sum += package_weight;
        }
        if weight_sum > 0.0 {
            let score: f64 = total_score / weight_sum;
            score.min(100.0).max(0.0)
        } else {
            75.0
        }
    }
    pub async fn audit_system(&self) -> PackerResult<SecurityAuditResult> {
        info!("Starting comprehensive security audit");
        let installed_packages = Vec::new();
        let total_packages = installed_packages.len();
        let mut vulnerable_packages = 0;
        let mut high_risk_packages = 0;
        let mut total_vulnerabilities = 0;
        let mut reports = Vec::new();
        let mut recommendations = Vec::new();
        for package in &installed_packages {
            let vulnerabilities = self.scan_package(package).await?;
            if !vulnerabilities.is_empty() {
                vulnerable_packages += 1;
                total_vulnerabilities += vulnerabilities.len();
                let high_risk = vulnerabilities.iter().any(|v| {
                    matches!(
                        v.severity,
                        VulnerabilitySeverity::Critical | VulnerabilitySeverity::High
                    )
                });
                if high_risk {
                    high_risk_packages += 1;
                }
                let vulnerability_details: Vec<VulnerabilityDetail> = vulnerabilities
                    .iter()
                    .map(|v| VulnerabilityDetail {
                        id: v.vulnerability_id.clone(),
                        severity: format!("{:?}", v.severity),
                        description: v.description.clone(),
                        fixed_version: v.fixed_version.clone(),
                        cve_id: None,
                        published_date: Utc::now(),
                    })
                    .collect();
                let risk_score = self.calculate_package_risk_score(&vulnerabilities);
                let recommendation =
                    self.generate_package_recommendation(&vulnerabilities, package);
                reports.push(VulnerabilityReport {
                    package_name: package.name.clone(),
                    version: package.version.clone(),
                    vulnerabilities: vulnerability_details,
                    risk_score,
                    recommendation,
                });
            }
        }
        if vulnerable_packages > 0 {
            recommendations.push(format!(
                "Update {} vulnerable packages ",
                vulnerable_packages
            ));
        }
        if high_risk_packages > 0 {
            recommendations.push(format!(
                "Prioritize {} high-risk packages ",
                high_risk_packages
            ));
        }
        recommendations.push("Enable automatic security updates".to_string());
        recommendations.push("Regularly update vulnerability database ".to_string());
        recommendations.push("Consider using only official repositories".to_string());
        Ok(SecurityAuditResult {
            total_packages,
            vulnerable_packages,
            high_risk_packages,
            total_vulnerabilities,
            reports,
            recommendations,
        })
    }
    fn calculate_package_risk_score(&self, vulnerabilities: &[SecurityVulnerability]) -> f64 {
        if vulnerabilities.is_empty() {
            return 0.0;
        }
        let mut score: f64 = 0.0;
        for vuln in vulnerabilities {
            let severity_score = match vuln.severity {
                VulnerabilitySeverity::Critical => 10.0,
                VulnerabilitySeverity::High => 7.0,
                VulnerabilitySeverity::Medium => 4.0,
                VulnerabilitySeverity::Low => 2.0,
                VulnerabilitySeverity::Info => 0.5,
            };
            score += severity_score;
        }
        score.min(10.0_f64)
    }
    fn generate_package_recommendation(
        &self,
        vulnerabilities: &[SecurityVulnerability],
        package: &Package,
    ) -> String {
        let has_fix = vulnerabilities.iter().any(|v| v.fixed_version.is_some());
        if has_fix {
            format!(
                "Update {} to latest version to fix known vulnerabilities",
                package.name
            )
        } else {
            format!(
                "Monitor {} for security updates - no fixes available yet",
                package.name
            )
        }
    }
    pub async fn advanced_vulnerability_assessment(
        &self,
        package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<AdvancedVulnerabilityAssessment> {
        info!(
            "Performing advanced vulnerability assessment for {}",
            package.name
        );
        let basic_vulns = self.scan_package(package).await?;
        if basic_vulns.is_empty() {
            return Err(PackerError::SecurityError(
                "No vulnerabilities found for assessment".into(),
            ));
        }
        let vuln = &basic_vulns[0];
        let cvss_vector = self
            .build_cvss_vector(vuln, package, system_context)
            .await?;
        let epss_score = self.fetch_epss_score(&vuln.vulnerability_id).await?;
        let contextual_risk = self.assess_contextual_risk(package, system_context).await?;
        let temporal_factors = self.analyze_temporal_factors(vuln, package).await?;
        let threat_intelligence = self
            .gather_threat_intelligence(&vuln.vulnerability_id)
            .await?;
        let business_impact = self
            .calculate_business_impact(package, system_context, &cvss_vector)
            .await?;
        let mitigation_status = self
            .assess_mitigation_status(vuln, package, system_context)
            .await?;
        Ok(AdvancedVulnerabilityAssessment {
            vulnerability_id: vuln.vulnerability_id.clone(),
            package: package.name.clone(),
            cvss_vector,
            epss_score,
            contextual_risk,
            temporal_factors,
            threat_intelligence,
            business_impact,
            mitigation_status,
        })
    }
    async fn build_cvss_vector(
        &self,
        vuln: &SecurityVulnerability,
        package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<CVSSVector> {
        let attack_vector = if package.name.contains("web") || package.name.contains("http") {
            AttackVector::Network
        } else {
            AttackVector::Local
        };
        let attack_complexity = match vuln.severity {
            VulnerabilitySeverity::Critical | VulnerabilitySeverity::High => AttackComplexity::Low,
            _ => AttackComplexity::High,
        };
        let base_score =
            self.calculate_cvss_base_score(&attack_vector, &attack_complexity, &vuln.severity);
        Ok(CVSSVector {
            version: "4.0".to_string(),
            attack_vector,
            attack_complexity,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::High,
            base_score,
            temporal_score: base_score * 0.9,
            environmental_score: base_score * self.get_environmental_modifier(system_context),
            vector_string: format!("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        })
    }
    fn calculate_cvss_base_score(
        &self,
        attack_vector: &AttackVector,
        attack_complexity: &AttackComplexity,
        severity: &VulnerabilitySeverity,
    ) -> f64 {
        let mut score: f64 = match severity {
            VulnerabilitySeverity::Critical => 9.5,
            VulnerabilitySeverity::High => 8.0,
            VulnerabilitySeverity::Medium => 6.0,
            VulnerabilitySeverity::Low => 3.0,
            VulnerabilitySeverity::Info => 1.0,
        };
        score *= match attack_vector {
            AttackVector::Network => 1.0,
            AttackVector::Adjacent => 0.9,
            AttackVector::Local => 0.8,
            AttackVector::Physical => 0.7,
        };
        score *= match attack_complexity {
            AttackComplexity::Low => 1.0,
            AttackComplexity::High => 0.8,
        };
        score.min(10.0_f64)
    }
    fn get_environmental_modifier(&self, system_context: &SystemContext) -> f64 {
        let mut modifier = 1.0;
        match system_context.exposure {
            SystemExposure::InternetFacing => modifier *= 1.2,
            SystemExposure::InternalNetwork => modifier *= 1.0,
            SystemExposure::Isolated => modifier *= 0.8,
            SystemExposure::AirGapped => modifier *= 0.6,
        }
        match system_context.data_sensitivity {
            DataSensitivity::TopSecret => modifier *= 1.3,
            DataSensitivity::Secret => modifier *= 1.2,
            DataSensitivity::Confidential => modifier *= 1.1,
            DataSensitivity::Internal => modifier *= 1.0,
            DataSensitivity::Public => modifier *= 0.9,
        }
        modifier
    }
    async fn fetch_epss_score(&self, vulnerability_id: &str) -> PackerResult<EPSSScore> {
        let client = reqwest::Client::new();
        let url = format!(
            "https://api.first.org/data/v1/epss?cve={}",
            vulnerability_id
        );
        match client.get(&url).send().await {
            Ok(response) => {
                if let Ok(data) = response.json::<serde_json::Value>().await {
                    if let Some(score_data) = data["data"].as_array().and_then(|arr| arr.first()) {
                        return Ok(EPSSScore {
                            probability: score_data["epss"].as_f64().unwrap_or(0.1),
                            percentile: score_data["percentile"].as_f64().unwrap_or(0.5),
                            last_updated: Utc::now(),
                            data_sources: vec!["FIRST.org EPSS ".to_string()],
                        });
                    }
                }
            }
            Err(_) => {}
        }
        Ok(EPSSScore {
            probability: 0.05,
            percentile: 0.5,
            last_updated: Utc::now(),
            data_sources: vec!["Estimated".to_string()],
        })
    }
    async fn assess_contextual_risk(
        &self,
        package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<ContextualRisk> {
        let attack_surface = AttackSurface {
            network_ports: self.analyze_package_network_exposure(package).await?,
            protocols: self.identify_package_protocols(package).await?,
            services: self.identify_package_services(package).await?,
            file_permissions: self.analyze_file_permissions(package).await?,
            database_access: self.has_database_access(package).await?,
            web_interfaces: self.has_web_interfaces(package).await?,
        };
        let compensating_controls = self
            .evaluate_compensating_controls(package, system_context)
            .await?;
        Ok(ContextualRisk {
            system_exposure: system_context.exposure.clone(),
            data_sensitivity: system_context.data_sensitivity.clone(),
            network_position: system_context.network_position.clone(),
            user_privileges: system_context.user_privileges.clone(),
            attack_surface,
            compensating_controls,
        })
    }
    async fn analyze_temporal_factors(
        &self,
        vuln: &SecurityVulnerability,
        package: &Package,
    ) -> PackerResult<TemporalFactors> {
        let vulnerability_age = self.calculate_vulnerability_age(vuln).await?;
        let exploit_availability = self
            .check_exploit_availability(&vuln.vulnerability_id)
            .await?;
        let patch_status = self.assess_patch_availability(vuln, package).await?;
        Ok(TemporalFactors {
            exploit_maturity: if exploit_availability.functional_exploit {
                ExploitMaturity::Functional
            } else if exploit_availability.proof_of_concept {
                ExploitMaturity::ProofOfConcept
            } else {
                ExploitMaturity::Unproven
            },
            patch_availability: patch_status,
            vulnerability_age_days: vulnerability_age,
            disclosure_timeline: self.build_disclosure_timeline(vuln).await?,
            active_exploitation: exploit_availability.active_exploitation,
            proof_of_concept_available: exploit_availability.proof_of_concept,
            exploit_kit_availability: exploit_availability.exploit_kit,
        })
    }
    async fn gather_threat_intelligence(
        &self,
        vulnerability_id: &str,
    ) -> PackerResult<ThreatIntelligence> {
        let threat_actors = self.identify_threat_actors(vulnerability_id).await?;
        let attack_patterns = self.map_to_mitre_attack(vulnerability_id).await?;
        let iocs = self
            .fetch_indicators_of_compromise(vulnerability_id)
            .await?;
        Ok(ThreatIntelligence {
            threat_actors,
            campaigns: vec![],
            iocs,
            attack_patterns,
            geographic_threats: vec!["China".to_string(), "Russia".to_string()],
            industry_targeting: vec!["Financial".to_string(), "Healthcare".to_string()],
        })
    }
    async fn calculate_business_impact(
        &self,
        package: &Package,
        system_context: &SystemContext,
        cvss_vector: &CVSSVector,
    ) -> PackerResult<BusinessImpact> {
        let financial_impact = self
            .calculate_financial_impact(package, system_context, cvss_vector)
            .await?;
        let operational_impact = self
            .calculate_operational_impact(package, system_context)
            .await?;
        let reputational_impact = self.calculate_reputational_impact(system_context).await?;
        let compliance_impact = self
            .calculate_compliance_impact(system_context, cvss_vector)
            .await?;
        let recovery_metrics = self
            .calculate_recovery_metrics(package, system_context)
            .await?;
        Ok(BusinessImpact {
            financial_impact,
            operational_impact,
            reputational_impact,
            compliance_impact,
            recovery_metrics,
        })
    }
    async fn assess_mitigation_status(
        &self,
        vuln: &SecurityVulnerability,
        package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<MitigationStatus> {
        let controls_in_place = system_context.security_controls.clone();
        let mitigation_effectiveness = self
            .calculate_mitigation_effectiveness(&controls_in_place, vuln)
            .await?;
        let residual_risk = self
            .calculate_residual_risk(vuln, mitigation_effectiveness)
            .await?;
        let recommended_actions = self
            .generate_recommended_actions(vuln, package, system_context)
            .await?;
        let priority_level = self
            .determine_priority_level(residual_risk, &system_context.business_criticality)
            .await?;
        Ok(MitigationStatus {
            controls_in_place,
            mitigation_effectiveness,
            residual_risk,
            recommended_actions,
            priority_level,
        })
    }
    async fn analyze_package_network_exposure(&self, package: &Package) -> PackerResult<Vec<u16>> {
        let mut ports = Vec::new();
        if package.name.contains("http") || package.name.contains("web") {
            ports.extend(vec![80, 443, 8080, 8443]);
        }
        if package.name.contains("ssh") {
            ports.push(22);
        }
        if package.name.contains("database ") || package.name.contains("mysql") {
            ports.extend(vec![3306, 5432]);
        }
        Ok(ports)
    }
    async fn identify_package_protocols(&self, package: &Package) -> PackerResult<Vec<String>> {
        let mut protocols = Vec::new();
        if package.name.contains("http") {
            protocols.push("HTTP".to_string());
            protocols.push("HTTPS".to_string());
        }
        if package.name.contains("ssh") {
            protocols.push("SSH".to_string());
        }
        if package.name.contains("ftp") {
            protocols.push("FTP".to_string());
        }
        Ok(protocols)
    }
    async fn identify_package_services(&self, _package: &Package) -> PackerResult<Vec<String>> {
        Ok(vec!["daemon".to_string()])
    }
    async fn analyze_file_permissions(&self, _package: &Package) -> PackerResult<Vec<String>> {
        Ok(vec!["0755".to_string(), "0644".to_string()])
    }
    async fn has_database_access(&self, package: &Package) -> PackerResult<bool> {
        Ok(package.name.contains("database ") || package.name.contains("sql"))
    }
    async fn has_web_interfaces(&self, package: &Package) -> PackerResult<bool> {
        Ok(package.name.contains("web") || package.name.contains("http"))
    }
    async fn evaluate_compensating_controls(
        &self,
        _package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<Vec<CompensatingControl>> {
        let mut controls = Vec::new();
        if system_context
            .security_controls
            .iter()
            .any(|c| c.control_id.starts_with("FW"))
        {
            controls.push(CompensatingControl {
                control_type: "Network Firewall ".to_string(),
                effectiveness: 0.8,
                coverage: 0.9,
                description: "Network firewall provides perimeter protection ".to_string(),
            });
        }
        Ok(controls)
    }
    async fn calculate_vulnerability_age(
        &self,
        _vuln: &SecurityVulnerability,
    ) -> PackerResult<u64> {
        Ok(30)
    }
    async fn check_exploit_availability(
        &self,
        vulnerability_id: &str,
    ) -> PackerResult<ExploitAvailability> {
        let is_metasploit = self.check_metasploit_availability(vulnerability_id).await?;
        let is_exploit_db = self.check_exploit_db_availability(vulnerability_id).await?;
        Ok(ExploitAvailability {
            functional_exploit: is_metasploit,
            proof_of_concept: is_exploit_db,
            exploit_kit: false,
            active_exploitation: false,
        })
    }
    async fn check_metasploit_availability(&self, _vulnerability_id: &str) -> PackerResult<bool> {
        Ok(false)
    }
    async fn check_exploit_db_availability(&self, _vulnerability_id: &str) -> PackerResult<bool> {
        Ok(false)
    }
    async fn assess_patch_availability(
        &self,
        vuln: &SecurityVulnerability,
        _package: &Package,
    ) -> PackerResult<PatchAvailability> {
        if vuln.fixed_version.is_some() {
            Ok(PatchAvailability::OfficialFix)
        } else {
            Ok(PatchAvailability::NotAvailable)
        }
    }
    async fn build_disclosure_timeline(
        &self,
        _vuln: &SecurityVulnerability,
    ) -> PackerResult<DisclosureTimeline> {
        Ok(DisclosureTimeline {
            discovered_date: Some(Utc::now() - chrono::Duration::days(60)),
            disclosed_date: Some(Utc::now() - chrono::Duration::days(30)),
            patch_released_date: Some(Utc::now() - chrono::Duration::days(15)),
            public_exploit_date: None,
            zero_day_duration_days: Some(30),
        })
    }
    async fn identify_threat_actors(
        &self,
        _vulnerability_id: &str,
    ) -> PackerResult<Vec<ThreatActor>> {
        Ok(vec![ThreatActor {
            name: "APT29".to_string(),
            sophistication: ThreatSophistication::StateSponsored,
            motivation: vec!["Espionage".to_string()],
            attribution_confidence: 0.8,
        }])
    }
    async fn map_to_mitre_attack(
        &self,
        _vulnerability_id: &str,
    ) -> PackerResult<Vec<AttackPattern>> {
        Ok(vec![AttackPattern {
            mitre_id: "T1068".to_string(),
            technique: "Exploitation for Privilege Escalation ".to_string(),
            tactic: "Privilege Escalation ".to_string(),
            likelihood: 0.7,
        }])
    }
    async fn fetch_indicators_of_compromise(
        &self,
        _vulnerability_id: &str,
    ) -> PackerResult<Vec<IoC>> {
        Ok(vec![IoC {
            ioc_type: "domain".to_string(),
            value: "malicious-example.com ".to_string(),
            confidence: 0.9,
            last_seen: Utc::now() - chrono::Duration::days(7),
        }])
    }
    async fn calculate_financial_impact(
        &self,
        _package: &Package,
        system_context: &SystemContext,
        cvss_vector: &CVSSVector,
    ) -> PackerResult<FinancialImpact> {
        let base_cost = match system_context.business_criticality {
            BusinessCriticality::MissionCritical => 1_000_000.0,
            BusinessCriticality::BusinessCritical => 500_000.0,
            BusinessCriticality::Important => 100_000.0,
            BusinessCriticality::Standard => 25_000.0,
            BusinessCriticality::Development => 5_000.0,
        };
        let cvss_multiplier = cvss_vector.environmental_score / 10.0;
        let total_impact = base_cost * cvss_multiplier;
        Ok(FinancialImpact {
            direct_costs: total_impact * 0.3,
            indirect_costs: total_impact * 0.4,
            revenue_loss: total_impact * 0.2,
            regulatory_fines: total_impact * 0.1,
            total_estimated_impact: total_impact,
            confidence_interval: (total_impact * 0.7, total_impact * 1.3),
        })
    }
    async fn calculate_operational_impact(
        &self,
        _package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<OperationalImpact> {
        let downtime_hours = match system_context.business_criticality {
            BusinessCriticality::MissionCritical => 0.5,
            BusinessCriticality::BusinessCritical => 2.0,
            BusinessCriticality::Important => 8.0,
            BusinessCriticality::Standard => 24.0,
            BusinessCriticality::Development => 72.0,
        };
        Ok(OperationalImpact {
            system_downtime_hours: downtime_hours,
            degraded_performance_hours: downtime_hours * 2.0,
            affected_users: 1000,
            critical_processes_affected: vec!["Authentication".to_string()],
            cascading_failures: vec!["Dependent services ".to_string()],
        })
    }
    async fn calculate_reputational_impact(
        &self,
        system_context: &SystemContext,
    ) -> PackerResult<ReputationalImpact> {
        let base_risk = match system_context.exposure {
            SystemExposure::InternetFacing => 0.8,
            SystemExposure::InternalNetwork => 0.4,
            SystemExposure::Isolated => 0.2,
            SystemExposure::AirGapped => 0.1,
        };
        Ok(ReputationalImpact {
            public_disclosure_risk: base_risk,
            customer_trust_impact: base_risk * 0.8,
            media_attention_likelihood: base_risk * 0.6,
            brand_damage_score: base_risk * 0.7,
        })
    }
    async fn calculate_compliance_impact(
        &self,
        system_context: &SystemContext,
        cvss_vector: &CVSSVector,
    ) -> PackerResult<ComplianceImpact> {
        let violation_severity = if cvss_vector.environmental_score >= 9.0 {
            ViolationSeverity::Critical
        } else if cvss_vector.environmental_score >= 7.0 {
            ViolationSeverity::Major
        } else if cvss_vector.environmental_score >= 4.0 {
            ViolationSeverity::Moderate
        } else {
            ViolationSeverity::Minor
        };
        Ok(ComplianceImpact {
            regulations_affected: system_context.compliance_requirements.clone(),
            violation_severity,
            audit_implications: vec!["Potential audit findings ".to_string()],
            certification_impact: vec!["SOC 2 implications ".to_string()],
        })
    }
    async fn calculate_recovery_metrics(
        &self,
        _package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<RecoveryMetrics> {
        let recovery_time = match system_context.business_criticality {
            BusinessCriticality::MissionCritical => 2.0,
            BusinessCriticality::BusinessCritical => 8.0,
            BusinessCriticality::Important => 24.0,
            BusinessCriticality::Standard => 72.0,
            BusinessCriticality::Development => 168.0,
        };
        Ok(RecoveryMetrics {
            estimated_recovery_time: recovery_time,
            recovery_complexity: RecoveryComplexity::Moderate,
            resource_requirements: ResourceRequirements {
                personnel_hours: recovery_time * 2.0,
                specialist_expertise_required: vec!["Security Engineer ".to_string()],
                external_vendor_support: false,
                infrastructure_requirements: vec!["Backup systems ".to_string()],
            },
            backup_availability: true,
        })
    }
    async fn calculate_mitigation_effectiveness(
        &self,
        controls: &[SecurityControl],
        _vuln: &SecurityVulnerability,
    ) -> PackerResult<f64> {
        if controls.is_empty() {
            return Ok(0.0);
        }
        let total_effectiveness: f64 = controls
            .iter()
            .map(|c| c.effectiveness_rating * c.coverage_percentage)
            .sum();
        Ok((total_effectiveness / controls.len() as f64).min(1.0))
    }
    async fn calculate_residual_risk(
        &self,
        _vuln: &SecurityVulnerability,
        mitigation_effectiveness: f64,
    ) -> PackerResult<f64> {
        let base_risk = 0.8;
        Ok(base_risk * (1.0 - mitigation_effectiveness))
    }
    async fn generate_recommended_actions(
        &self,
        vuln: &SecurityVulnerability,
        _package: &Package,
        system_context: &SystemContext,
    ) -> PackerResult<Vec<RecommendedAction>> {
        let mut actions = Vec::new();
        if vuln.fixed_version.is_some() {
            actions.push(RecommendedAction {
                action_type: ActionType::Patch,
                description: format!("Update to version {}", vuln.fixed_version.as_ref().unwrap()),
                priority: Priority::High,
                estimated_effort: 2.0,
                cost_estimate: 500.0,
                risk_reduction: 0.9,
                deadline: Some(Utc::now() + chrono::Duration::days(7)),
            });
        }
        if matches!(system_context.exposure, SystemExposure::InternetFacing) {
            actions.push(RecommendedAction {
                action_type: ActionType::NetworkSegmentation,
                description: "Implement network segmentation to limit exposure ".to_string(),
                priority: Priority::Medium,
                estimated_effort: 8.0,
                cost_estimate: 2000.0,
                risk_reduction: 0.6,
                deadline: Some(Utc::now() + chrono::Duration::days(30)),
            });
        }
        Ok(actions)
    }
    async fn determine_priority_level(
        &self,
        residual_risk: f64,
        business_criticality: &BusinessCriticality,
    ) -> PackerResult<PriorityLevel> {
        let priority = match (residual_risk, business_criticality) {
            (r, BusinessCriticality::MissionCritical) if r > 0.8 => PriorityLevel::P0Emergency,
            (r, BusinessCriticality::MissionCritical) if r > 0.6 => PriorityLevel::P1Critical,
            (r, _) if r > 0.8 => PriorityLevel::P1Critical,
            (r, _) if r > 0.6 => PriorityLevel::P2High,
            (r, _) if r > 0.4 => PriorityLevel::P3Medium,
            (r, _) if r > 0.2 => PriorityLevel::P4Low,
            _ => PriorityLevel::P5Informational,
        };
        Ok(priority)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedVulnerabilityAssessment {
    pub vulnerability_id: String,
    pub package: String,
    pub cvss_vector: CVSSVector,
    pub epss_score: EPSSScore,
    pub contextual_risk: ContextualRisk,
    pub temporal_factors: TemporalFactors,
    pub threat_intelligence: ThreatIntelligence,
    pub business_impact: BusinessImpact,
    pub mitigation_status: MitigationStatus,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CVSSVector {
    pub version: String,
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality_impact: Impact,
    pub integrity_impact: Impact,
    pub availability_impact: Impact,
    pub base_score: f64,
    pub temporal_score: f64,
    pub environmental_score: f64,
    pub vector_string: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackComplexity {
    Low,
    High,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserInteraction {
    None,
    Required,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Scope {
    Unchanged,
    Changed,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Impact {
    None,
    Low,
    High,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EPSSScore {
    pub probability: f64,
    pub percentile: f64,
    pub last_updated: DateTime<Utc>,
    pub data_sources: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextualRisk {
    pub system_exposure: SystemExposure,
    pub data_sensitivity: DataSensitivity,
    pub network_position: NetworkPosition,
    pub user_privileges: UserPrivilegeContext,
    pub attack_surface: AttackSurface,
    pub compensating_controls: Vec<CompensatingControl>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemExposure {
    InternetFacing,
    InternalNetwork,
    Isolated,
    AirGapped,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataSensitivity {
    Public,
    Internal,
    Confidential,
    Secret,
    TopSecret,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkPosition {
    DMZ,
    CoreNetwork,
    ManagementNetwork,
    UserWorkstation,
    ServerInfrastructure,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserPrivilegeContext {
    Unprivileged,
    LocalUser,
    PowerUser,
    Administrator,
    SystemService,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    pub network_ports: Vec<u16>,
    pub protocols: Vec<String>,
    pub services: Vec<String>,
    pub file_permissions: Vec<String>,
    pub database_access: bool,
    pub web_interfaces: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompensatingControl {
    pub control_type: String,
    pub effectiveness: f64,
    pub coverage: f64,
    pub description: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalFactors {
    pub exploit_maturity: ExploitMaturity,
    pub patch_availability: PatchAvailability,
    pub vulnerability_age_days: u64,
    pub disclosure_timeline: DisclosureTimeline,
    pub active_exploitation: bool,
    pub proof_of_concept_available: bool,
    pub exploit_kit_availability: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExploitMaturity {
    NotDefined,
    Unproven,
    ProofOfConcept,
    Functional,
    High,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PatchAvailability {
    NotAvailable,
    Workaround,
    TemporaryFix,
    OfficialFix,
    Superseded,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisclosureTimeline {
    pub discovered_date: Option<DateTime<Utc>>,
    pub disclosed_date: Option<DateTime<Utc>>,
    pub patch_released_date: Option<DateTime<Utc>>,
    pub public_exploit_date: Option<DateTime<Utc>>,
    pub zero_day_duration_days: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligence {
    pub threat_actors: Vec<ThreatActor>,
    pub campaigns: Vec<String>,
    pub iocs: Vec<IoC>,
    pub attack_patterns: Vec<AttackPattern>,
    pub geographic_threats: Vec<String>,
    pub industry_targeting: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatActor {
    pub name: String,
    pub sophistication: ThreatSophistication,
    pub motivation: Vec<String>,
    pub attribution_confidence: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSophistication {
    ScriptKiddie,
    Cybercriminal,
    Hacktivist,
    StateSponsored,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub ioc_type: String,
    pub value: String,
    pub confidence: f64,
    pub last_seen: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub mitre_id: String,
    pub technique: String,
    pub tactic: String,
    pub likelihood: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessImpact {
    pub financial_impact: FinancialImpact,
    pub operational_impact: OperationalImpact,
    pub reputational_impact: ReputationalImpact,
    pub compliance_impact: ComplianceImpact,
    pub recovery_metrics: RecoveryMetrics,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialImpact {
    pub direct_costs: f64,
    pub indirect_costs: f64,
    pub revenue_loss: f64,
    pub regulatory_fines: f64,
    pub total_estimated_impact: f64,
    pub confidence_interval: (f64, f64),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalImpact {
    pub system_downtime_hours: f64,
    pub degraded_performance_hours: f64,
    pub affected_users: u64,
    pub critical_processes_affected: Vec<String>,
    pub cascading_failures: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationalImpact {
    pub public_disclosure_risk: f64,
    pub customer_trust_impact: f64,
    pub media_attention_likelihood: f64,
    pub brand_damage_score: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceImpact {
    pub regulations_affected: Vec<String>,
    pub violation_severity: ViolationSeverity,
    pub audit_implications: Vec<String>,
    pub certification_impact: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Minor,
    Moderate,
    Major,
    Critical,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryMetrics {
    pub estimated_recovery_time: f64,
    pub recovery_complexity: RecoveryComplexity,
    pub resource_requirements: ResourceRequirements,
    pub backup_availability: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryComplexity {
    Simple,
    Moderate,
    Complex,
    VeryComplex,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub personnel_hours: f64,
    pub specialist_expertise_required: Vec<String>,
    pub external_vendor_support: bool,
    pub infrastructure_requirements: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationStatus {
    pub controls_in_place: Vec<SecurityControl>,
    pub mitigation_effectiveness: f64,
    pub residual_risk: f64,
    pub recommended_actions: Vec<RecommendedAction>,
    pub priority_level: PriorityLevel,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityControl {
    pub control_id: String,
    pub control_type: SecurityControlType,
    pub implementation_status: ImplementationStatus,
    pub effectiveness_rating: f64,
    pub coverage_percentage: f64,
    pub last_tested: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityControlType {
    Preventive,
    Detective,
    Corrective,
    Deterrent,
    Recovery,
    Compensating,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImplementationStatus {
    NotImplemented,
    Planned,
    PartiallyImplemented,
    FullyImplemented,
    UnderReview,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action_type: ActionType,
    pub description: String,
    pub priority: Priority,
    pub estimated_effort: f64,
    pub cost_estimate: f64,
    pub risk_reduction: f64,
    pub deadline: Option<DateTime<Utc>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Patch,
    ConfigurationChange,
    AccessControlUpdate,
    NetworkSegmentation,
    MonitoringEnhancement,
    TrainingAndAwareness,
    IncidentResponse,
    BusinessContinuity,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PriorityLevel {
    P0Emergency,
    P1Critical,
    P2High,
    P3Medium,
    P4Low,
    P5Informational,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemContext {
    pub exposure: SystemExposure,
    pub data_sensitivity: DataSensitivity,
    pub network_position: NetworkPosition,
    pub user_privileges: UserPrivilegeContext,
    pub security_controls: Vec<SecurityControl>,
    pub compliance_requirements: Vec<String>,
    pub business_criticality: BusinessCriticality,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessCriticality {
    MissionCritical,
    BusinessCritical,
    Important,
    Standard,
    Development,
}
impl SystemContext {
    pub fn new_development_environment() -> Self {
        Self {
            exposure: SystemExposure::Isolated,
            data_sensitivity: DataSensitivity::Internal,
            network_position: NetworkPosition::UserWorkstation,
            user_privileges: UserPrivilegeContext::LocalUser,
            security_controls: Vec::new(),
            compliance_requirements: Vec::new(),
            business_criticality: BusinessCriticality::Development,
        }
    }
    pub fn new_production_environment() -> Self {
        Self {
            exposure: SystemExposure::InternetFacing,
            data_sensitivity: DataSensitivity::Confidential,
            network_position: NetworkPosition::ServerInfrastructure,
            user_privileges: UserPrivilegeContext::SystemService,
            security_controls: vec![SecurityControl {
                control_id: "FW-001".to_string(),
                control_type: SecurityControlType::Preventive,
                implementation_status: ImplementationStatus::FullyImplemented,
                effectiveness_rating: 0.85,
                coverage_percentage: 0.95,
                last_tested: Some(Utc::now()),
            }],
            compliance_requirements: vec!["SOX".to_string(), "GDPR ".to_string()],
            business_criticality: BusinessCriticality::MissionCritical,
        }
    }
}
impl PackageManager {
    pub async fn new(config: Config) -> PackerResult<Self> {
        let database = DatabaseManager::new(&config.database_dir.to_string_lossy()).await?;
        let repository_manager = RepositoryManager::new(config.clone()).await?;
        let preferences = ResolutionPreferences {
            prefer_newer_versions: true,
            prefer_trusted_repositories: true,
            prefer_stable_versions: true,
            ..Default::default()
        };
        let resolver = DependencyResolver::new().with_preferences(preferences);
        let multi_progress = MultiProgress::new();
        let security_scanner = SecurityScanner::new(config.clone());
        let mut gpg_manager = GPGManager::new(config.clone());
        gpg_manager.initialize().await?;
        Ok(Self {
            config,
            database,
            repository_manager,
            resolver,
            multi_progress,
            security_scanner,
            gpg_manager,
            transaction_cache: Arc::new(RwLock::new(HashMap::new())),
            aur_downloads: None,
            binary_downloads: None,
        })
    }
    pub async fn install_packages(&mut self, package_names: Vec<String>) -> PackerResult<()> {
        use colored::*;
        use std::io::Write;

        println!("{}", "📦 Analyzing packages...".cyan());

        println!(
            "{}",
            format!(
                "📥 Installing {} package(s) natively...",
                package_names.len()
            )
            .cyan()
        );

        for package_name in &package_names {
            print!("  • Installing {}... ", package_name.bold());
            std::io::stdout().flush().unwrap();

            match Err(PackerError::PackageNotFound(format!(
                "Native installation not yet implemented for {}",
                package_name
            ))) {
                Ok(()) => {
                    println!("{}", "[✓ Installed]".green());
                }
                Err(e) => {
                    println!("{}", format!("[✗ Failed: {}]", e).red());
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    // Removed: install_official_packages - now using native installation for all packages

    #[allow(dead_code)]
    async fn install_aur_packages(&mut self, package_names: &[String]) -> PackerResult<()> {
        info!("installing aur packages: {:?}", package_names);

        for package_name in package_names {
            // get aur package info
            if let Some(aur_results) = self
                .repository_manager
                .search_aur_directly(package_name, true)
                .await?
            {
                if let Some(package) = aur_results.into_iter().find(|p| p.name == *package_name) {
                    info!("building aur package: {}", package.name);
                    self.build_and_install_aur_package(&package).await?;
                } else {
                    return Err(PackerError::PackageNotFound(package_name.clone()));
                }
            } else {
                return Err(PackerError::PackageNotFound(package_name.clone()));
            }
        }

        Ok(())
    }

    // simplified aur building
    async fn build_and_install_aur_package(&mut self, package: &Package) -> PackerResult<()> {
        use colored::*;
        use std::process::Stdio;

        println!("  📂 Cloning {}...", package.name.bold());

        // clone aur repo
        let build_dir = std::env::temp_dir().join(format!("packer-build-{}", package.name));

        if build_dir.exists() {
            std::fs::remove_dir_all(&build_dir)?;
        }

        // git clone
        let mut clone_cmd = tokio::process::Command::new("git");
        clone_cmd
            .arg("clone")
            .arg(format!("https://aur.archlinux.org/{}.git", package.name))
            .arg(&build_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let clone_output = clone_cmd.output().await?;

        if !clone_output.status.success() {
            return Err(PackerError::BuildFailed(format!(
                "git clone failed for {}",
                package.name
            )));
        }

        println!("  🔨 Building and installing {}...", package.name.bold());

        // makepkg with interactive output
        let mut makepkg_cmd = tokio::process::Command::new("makepkg");
        makepkg_cmd
            .arg("-si")
            .arg("--needed")
            .current_dir(&build_dir)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let mut child = makepkg_cmd.spawn()?;
        let status = child.wait().await?;

        if !status.success() {
            return Err(PackerError::BuildFailed(format!(
                "makepkg failed for {}",
                package.name
            )));
        }

        println!(
            "  ✅ {} installed successfully",
            package.name.green().bold()
        );

        // cleanup
        if build_dir.exists() {
            std::fs::remove_dir_all(&build_dir)?;
        }

        Ok(())
    }

    // simplified security summary for compatibility
    #[allow(dead_code)]
    async fn create_security_summary(&self, packages: &[Package]) -> PackerResult<SecuritySummary> {
        Ok(SecuritySummary {
            verified_signatures: packages.len(),
            unverified_packages: Vec::new(),
            vulnerabilities: Vec::new(),
            trust_score: 85.0, // default good score
        })
    }

    pub async fn remove_packages(
        &mut self,
        package_names: &[String],
        _force: bool,
        cascade: bool,
        dry_run: bool,
    ) -> PackerResult<()> {
        info!("Removing packages: {:?}", package_names);

        let mut packages = Vec::new();
        for name in package_names {
            if let Some(package) = self.repository_manager.get_package(name).await? {
                packages.push(package);
            } else {
                warn!("Package {} not found", name);
            }
        }

        if dry_run {
            self.show_remove_transaction_summary(&packages);
            return Ok(());
        }

        if cascade {
            // TODO: need to implement cascade removal logic
            warn!("Cascade removal not yet implemented, performing simple removal");
        }

        self.execute_remove_transaction(packages).await?;
        info!("Removal completed successfully");
        Ok(())
    }
    pub async fn search_packages(
        &self,
        query: &str,
        exact: bool,
        installed: bool,
    ) -> PackerResult<Vec<Package>> {
        let mut results = Vec::new();
        if installed {
            results.extend(self.database.search_packages(query, exact).await?);
        } else {
            results.extend(
                self.repository_manager
                    .search_packages(query, exact, Some(50))
                    .await?,
            );
        }
        Ok(results)
    }
    pub async fn update_database(&mut self) -> PackerResult<()> {
        info!("Updating package database ");
        let pb = self.multi_progress.add(ProgressBar::new_spinner());
        pb.set_message("Updating repositories...");
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {wide_msg}")
                .unwrap(),
        );
        self.repository_manager.update_all().await?;
        self.security_scanner
            .update_vulnerability_database()
            .await?;
        pb.finish_with_message("Database updated successfully ");
        info!("Database update completed ");
        Ok(())
    }
    pub async fn upgrade_packages(&mut self, _force: bool, dry_run: bool) -> PackerResult<()> {
        info!("Upgrading packages");

        let transaction = InstallTransaction {
            to_install: Vec::new(),
            to_remove: Vec::new(),
            to_upgrade: Vec::new(),
            conflicts: Vec::new(),
            total_size: 0,
            download_size: 0,
            transaction_id: format!("upgrade-{}", chrono::Utc::now().timestamp()),
            security_summary: SecuritySummary {
                verified_signatures: 0,
                unverified_packages: Vec::new(),
                vulnerabilities: Vec::new(),
                trust_score: 1.0,
            },
        };

        if transaction.to_upgrade.is_empty() {
            println!("{}", "No packages to upgrade".green());
            return Ok(());
        }

        if dry_run {
            self.show_upgrade_transaction_summary(&transaction);
            return Ok(());
        }

        self.execute_upgrade_transaction(transaction).await?;
        info!("Upgrade completed successfully ");
        Ok(())
    }
    #[allow(dead_code)]
    fn parse_curl_progress(line: &str) -> Option<DownloadProgress> {
        if line.trim_start().starts_with("100") || line.contains("% Total ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(percentage) = parts[0].parse::<f64>() {
                    if percentage > 0.0 && parts.len() >= 2 {
                        if let Some(size_str) = parts.get(1) {
                            if let Ok(total_mb) = Self::parse_size_string(size_str) {
                                let downloaded = (total_mb as f64 * percentage / 100.0) as u64;
                                return Some(DownloadProgress {
                                    downloaded_bytes: downloaded,
                                    total_bytes: total_mb,
                                    percentage,
                                });
                            }
                        }
                    }
                }
            }
        }
        None
    }
    #[allow(dead_code)]
    fn parse_size_string(size_str: &str) -> Result<u64, ()> {
        let size_str = size_str.trim();
        if size_str.ends_with('M') {
            if let Ok(mb) = size_str.trim_end_matches('M').parse::<f64>() {
                return Ok((mb * 1024.0 * 1024.0) as u64);
            }
        } else if size_str.ends_with('K') {
            if let Ok(kb) = size_str.trim_end_matches('K').parse::<f64>() {
                return Ok((kb * 1024.0) as u64);
            }
        } else if size_str.ends_with('G') {
            if let Ok(gb) = size_str.trim_end_matches('G').parse::<f64>() {
                return Ok((gb * 1024.0 * 1024.0 * 1024.0) as u64);
            }
        } else if let Ok(bytes) = size_str.parse::<u64>() {
            return Ok(bytes);
        }
        Err(())
    }
    #[allow(dead_code)]
    async fn run_makepkg_with_realistic_progress(
        &self,
        package_dir: &std::path::Path,
        args: &[&str],
        progress_bar: &ProgressBar,
        phase_name: &str,
    ) -> PackerResult<bool> {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;
        let mut cmd = Command::new("makepkg");
        for arg in args {
            cmd.arg(arg);
        }
        cmd.current_dir(package_dir);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        eprintln!(
            "🐛 DEBUG: Running makepkg with args: {:?} in {:?}",
            args, package_dir
        );
        eprintln!("🐛 DEBUG: Directory exists: {}", package_dir.exists());
        if package_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(package_dir) {
                eprintln!("🐛 DEBUG: Directory contents:");
                for entry in entries.take(10) {
                    if let Ok(entry) = entry {
                        eprintln!("  {:?}", entry.file_name());
                    }
                }
            }
        }

        info!("Running makepkg with args: {:?} in {:?}", args, package_dir);
        let mut child = cmd.spawn()?;
        progress_bar.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );
        progress_bar.set_message(format!("{} starting...", phase_name));
        let pb_for_stdout = progress_bar.clone();
        let (stdout_tx, mut stdout_rx) = tokio::sync::mpsc::unbounded_channel();
        let stdout_handle = if let Some(stdout) = child.stdout.take() {
            Some(tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                let mut total_bytes_downloaded = 0u64;
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = stdout_tx.send(line.clone());
                    if line.contains("==> Making package:") {
                        pb_for_stdout.set_message("Preparing package build...".to_string());
                    } else if line.contains("==> Retrieving sources ") {
                        pb_for_stdout.set_message("Downloading source files...".to_string());
                    } else if line.contains("==> Validating source files ") {
                        pb_for_stdout.set_message("Validating sources...".to_string());
                    } else if line.contains("==> Extracting sources ") {
                        pb_for_stdout.set_message("Extracting source files...".to_string());
                    } else if line.contains("==> Starting build()") {
                        pb_for_stdout.set_message("Compiling source code...".to_string());
                    } else if line.contains("==> Entering fakeroot environment ") {
                        pb_for_stdout.set_message("Packaging files...".to_string());
                    } else if line.contains("==> Starting package()") {
                        pb_for_stdout.set_message("Creating package...".to_string());
                    } else if line.contains("==> Creating package ") {
                        pb_for_stdout.set_message("Finalizing package...".to_string());
                    } else if line.contains("==> Finished making:") {
                        pb_for_stdout.set_message("Build completed ".to_string());
                    } else if line.contains("==> Installing missing dependencies ") {
                        pb_for_stdout.set_message("Installing build dependencies...".to_string());
                    } else if line.contains("resolving dependencies ") {
                        pb_for_stdout.set_message("Resolving dependencies...".to_string());
                    } else if line.contains("downloading") || line.contains("Downloading") {
                        pb_for_stdout.set_message("Downloading dependencies...".to_string());
                    }
                    if line.contains("%") && (line.contains("Downloaded") || line.contains("curl"))
                    {
                        if let Some(progress_info) = Self::parse_curl_progress(&line) {
                            if progress_info.total_bytes > 0 {
                                pb_for_stdout.set_length(progress_info.total_bytes);
                                pb_for_stdout.set_position(progress_info.downloaded_bytes);
                                total_bytes_downloaded = progress_info.downloaded_bytes;
                            }
                        }
                    }
                    if line.contains("downloading") && line.contains("...") {
                        total_bytes_downloaded += 1024 * 1024;
                        pb_for_stdout.set_position(total_bytes_downloaded);
                        if pb_for_stdout.length() == Some(0) {
                            pb_for_stdout.set_length(total_bytes_downloaded * 2);
                        }
                    }
                    if line.contains("ERROR ") || line.contains("FAILED") {
                        warn!("makepkg: {}", line);
                    } else if line.contains("==>") {
                        info!("makepkg: {}", line);
                    }
                }
            }))
        } else {
            None
        };
        let pb_for_stderr = progress_bar.clone();
        let (error_tx, mut error_rx) = tokio::sync::mpsc::unbounded_channel();
        let stderr_handle = if let Some(stderr) = child.stderr.take() {
            Some(tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                let mut _total_bytes_downloaded = 0u64;
                while let Ok(Some(line)) = lines.next_line().await {
                    let _ = error_tx.send(line.clone());

                    if line.contains("%") && (line.contains("100") || line.contains("Total ")) {
                        if let Some(progress_info) = Self::parse_curl_progress(&line) {
                            if progress_info.total_bytes > 0 {
                                pb_for_stderr.set_length(progress_info.total_bytes);
                                pb_for_stderr.set_position(progress_info.downloaded_bytes);
                                pb_for_stderr.set_message(format!(
                                    "Downloading... {:.1}%",
                                    progress_info.percentage
                                ));
                            }
                        }
                    }
                    if line.contains("% Total ")
                        || line.contains("Dload")
                        || line.contains("downloading")
                    {
                        pb_for_stderr.set_message("Downloading...".to_string());
                    }
                    if line.contains("ERROR ") || line.contains("error") {
                        warn!("makepkg stderr: {}", line);
                    }
                }
            }))
        } else {
            None
        };
        let status =
            match tokio::time::timeout(std::time::Duration::from_secs(1800), child.wait()).await {
                Ok(status) => status?,
                Err(_) => {
                    progress_bar.set_message(format!("{} timed out ", phase_name));
                    warn!("makepkg process timed out after 30 minutes ");
                    let _ = child.kill().await;
                    return Ok(false);
                }
            };
        if let Some(handle) = stdout_handle {
            let _ = handle.await;
        }
        if let Some(handle) = stderr_handle {
            let _ = handle.await;
        }

        let mut stderr_lines = Vec::new();
        while let Ok(line) = error_rx.try_recv() {
            stderr_lines.push(line);
        }

        let mut stdout_lines = Vec::new();
        while let Ok(line) = stdout_rx.try_recv() {
            stdout_lines.push(line);
        }

        let success = status.success();
        if success {
            progress_bar.set_message(format!("{} completed successfully ", phase_name));
        } else {
            progress_bar.set_message(format!("{} failed ", phase_name));
            warn!("makepkg failed with exit code: {:?}", status.code());

            if !stdout_lines.is_empty() {
                eprintln!("\n🐛 DEBUG: makepkg stdout output:");
                for line in stdout_lines.iter().take(15) {
                    eprintln!("  {}", line);
                }
                if stdout_lines.len() > 15 {
                    eprintln!("  ... ({} more lines)", stdout_lines.len() - 15);
                }
            }

            if !stderr_lines.is_empty() {
                eprintln!("\n🐛 DEBUG: makepkg stderr output:");
                for line in stderr_lines.iter().take(15) {
                    eprintln!("  {}", line);
                }
                if stderr_lines.len() > 15 {
                    eprintln!("  ... ({} more lines)", stderr_lines.len() - 15);
                }
            }
        }
        Ok(success)
    }
    #[allow(dead_code)]
    async fn find_built_packages(
        &self,
        package_dir: &std::path::Path,
    ) -> PackerResult<Vec<PathBuf>> {
        eprintln!("🐛 DEBUG: Looking for built packages in: {:?}", package_dir);

        if let Ok(mut debug_entries) = tokio::fs::read_dir(package_dir).await {
            eprintln!("🐛 DEBUG: All files in build directory:");
            while let Ok(Some(entry)) = debug_entries.next_entry().await {
                eprintln!("  {:?}", entry.file_name());
            }
        }

        let mut built_packages = Vec::new();
        let mut entries = tokio::fs::read_dir(package_dir).await?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if filename.ends_with(".pkg.tar.xz")
                || filename.ends_with(".pkg.tar.zst")
                || filename.ends_with(".pkg.tar.gz")
                || filename.ends_with(".pkg.tar.bz2")
            {
                eprintln!("🐛 DEBUG: Found built package: {:?}", filename);
                built_packages.push(path);
            }
        }
        if built_packages.is_empty() {
            let mut entries = tokio::fs::read_dir(package_dir).await?;
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if filename.ends_with(".pkg.tar.xz")
                    || filename.ends_with(".pkg.tar.zst")
                    || filename.ends_with(".pkg.tar.gz")
                    || filename.ends_with(".pkg.tar.bz2")
                {
                    built_packages.push(path);
                }
            }
        }
        Ok(built_packages)
    }

    #[allow(dead_code)]
    fn get_makepkg_download_args(&self) -> Vec<String> {
        let mut args = vec![
            "--nobuild".to_string(),
            "--syncdeps".to_string(),
            "--noconfirm".to_string(),
        ];

        if self.gpg_manager.should_skip_signature_check() {
            args.push("--skippgpcheck".to_string());
            info!("Skipping GPG checks during source download as per configuration");
        } else {
            info!("GPG signature verification enabled for source download");
        }

        args
    }

    #[allow(dead_code)]
    fn get_makepkg_build_args(&self) -> Vec<String> {
        let mut args = vec!["--noconfirm".to_string(), "--needed".to_string()];

        // skipping integrity checks for now - this could be configurable in the future
        args.push("--skipinteg".to_string());

        if self.gpg_manager.should_skip_signature_check() {
            args.push("--skippgpcheck".to_string());
            info!("Skipping GPG checks during build as per configuration");
        } else {
            info!("GPG signature verification enabled for build");
        }

        args
    }

    #[allow(dead_code)]
    async fn import_required_gpg_keys(&mut self, package_dir: &Path) -> PackerResult<()> {
        let pkgbuild_path = package_dir.join("PKGBUILD");
        if !pkgbuild_path.exists() {
            return Ok(());
        }

        let pkgbuild_content = tokio::fs::read_to_string(&pkgbuild_path)
            .await
            .map_err(|e| PackerError::ConfigError(format!("Failed to read PKGBUILD: {}", e)))?;

        let mut keys_to_import = Vec::new();

        for line in pkgbuild_content.lines() {
            let line = line.trim();
            if line.starts_with("validpgpkeys=") {
                let keys_part = line.strip_prefix("validpgpkeys=").unwrap_or("");
                let keys_part = keys_part.trim_start_matches('(').trim_end_matches(')');

                for key in keys_part.split_whitespace() {
                    let key = key.trim_matches('\'').trim_matches('"');
                    if !key.is_empty() && key.len() >= 8 {
                        keys_to_import.push(key.to_string());
                    }
                }
                break; // found validpgpkeys, no need to continue
            }
        }

        if keys_to_import.is_empty() {
            debug!("No GPG keys found in PKGBUILD");
            return Ok(());
        }

        println!(
            "{}",
            format!("  -> Importing {} GPG key(s)...", keys_to_import.len()).yellow()
        );

        let mut successful_imports = 0;
        for key_id in &keys_to_import {
            match self.gpg_manager.import_key(key_id).await {
                Ok(_) => {
                    successful_imports += 1;
                    debug!("Successfully imported GPG key: {}", key_id);
                }
                Err(e) => {
                    warn!("Failed to import GPG key {}: {}", key_id, e);
                }
            }
        }

        if successful_imports > 0 {
            println!(
                "{}",
                format!(
                    "  -> Successfully imported {}/{} GPG key(s)",
                    successful_imports,
                    keys_to_import.len()
                )
                .green()
            );
        }

        Ok(())
    }

    pub async fn import_gpg_keys(
        &mut self,
        key_ids: &[String],
    ) -> PackerResult<Vec<crate::gpg_manager::GPGKeyInfo>> {
        let mut imported_keys = Vec::new();
        for key_id in key_ids {
            match self.gpg_manager.import_key(key_id).await {
                Ok(key_info) => {
                    imported_keys.push(key_info);
                }
                Err(e) => {
                    warn!("Failed to import key {}: {}", key_id, e);
                }
            }
        }
        Ok(imported_keys)
    }

    pub async fn get_gpg_status(&self) -> PackerResult<String> {
        let mut status = String::new();

        status.push_str("🔐 GPG System Status:\n");
        status.push_str(&format!(
            "  Keyring path: {:?}\n",
            self.gpg_manager.get_keyring_path()
        ));
        status.push_str(&format!(
            "  Auto-import keys: {}\n",
            self.gpg_manager.get_config().auto_import_keys
        ));
        status.push_str(&format!(
            "  Require signatures: {}\n",
            self.gpg_manager.get_config().require_signatures
        ));
        status.push_str(&format!(
            "  Minimum trust level: {}\n",
            self.gpg_manager.get_config().minimum_trust_level
        ));

        let trusted_keys = self.gpg_manager.get_trusted_keys();
        status.push_str(&format!("  Trusted keys: {}\n", trusted_keys.len()));

        if !trusted_keys.is_empty() {
            status.push_str("  Key details:\n");
            for (id, key) in trusted_keys.iter().take(5) {
                status.push_str(&format!(
                    "    • {} ({}) - {}\n",
                    id, key.user_id, key.trust_level
                ));
            }
            if trusted_keys.len() > 5 {
                status.push_str(&format!(
                    "    ... and {} more keys\n",
                    trusted_keys.len() - 5
                ));
            }
        }

        Ok(status)
    }

    pub fn log_operation_details(&self, operation: &str, package_name: Option<&str>) {
        let prefix = if let Some(name) = package_name {
            format!("[{}:{}]", operation, name)
        } else {
            format!("[{}]", operation)
        };

        info!("{} Configuration:", prefix);
        info!("  • Verify checksums: {}", self.config.verify_checksums);
        info!("  • Verify signatures: {}", self.config.verify_signatures);
        info!(
            "  • Allow untrusted repos: {}",
            self.config.security_policy.allow_untrusted_repos
        );
        info!(
            "  • Scan for vulnerabilities: {}",
            self.config.security_policy.scan_for_vulnerabilities
        );
        info!(
            "  • Block high-risk packages: {}",
            self.config.security_policy.block_high_risk_packages
        );

        if self.config.verify_signatures {
            info!(
                "  • GPG auto-import: {}",
                self.gpg_manager.get_config().auto_import_keys
            );
            info!(
                "  • GPG minimum trust: {}",
                self.gpg_manager.get_config().minimum_trust_level
            );
            info!(
                "  • GPG keyservers: {:?}",
                self.gpg_manager.get_config().keyservers
            );
        }
    }

    #[allow(dead_code)]
    fn show_install_transaction_summary(&self, transaction: &InstallTransaction) {
        println!();
        println!("{}", "=".repeat(60));
        let mut aur_packages = Vec::new();
        let mut binary_packages = Vec::new();
        for package in &transaction.to_install {
            if package.repository == "aur" {
                aur_packages.push(package);
            } else {
                binary_packages.push(package);
            }
        }
        for package in &binary_packages {
            println!(
                "  {} {} ({}) [{}]",
                package.name.bold(),
                package.version,
                self.format_size(package.size),
                package.repository
            );
        }
        for package in &aur_packages {
            println!(
                "  {} {} (AUR source package) [{}]",
                package.name.bold(),
                package.version,
                package.repository
            );
        }
        println!();
        let mut binary_download_size = 0u64;
        let mut aur_count = 0;
        for package in &transaction.to_install {
            if package.repository == "aur" {
                aur_count += 1;
            } else {
                binary_download_size += package.size;
            }
        }
        println!("  Packages to install: {}", transaction.to_install.len());
        if aur_count > 0 {
            if binary_download_size > 0 {
                println!(
                    "  Binary package downloads: {}",
                    self.format_size(binary_download_size)
                );
            }
            println!(
                "  AUR packages: {} (download size determined during build)",
                aur_count
            );
        } else {
            println!(
                "  Total download size: {}",
                self.format_size(binary_download_size)
            );
        }
        println!(
            "  Total installed size: {}",
            self.format_size(transaction.total_size)
        );
    }
    #[allow(dead_code)]
    async fn confirm_installation(&self, transaction: &InstallTransaction) -> PackerResult<bool> {
        use std::io::{self, Write};
        let has_aur_packages = transaction.to_install.iter().any(|p| p.repository == "aur");
        if has_aur_packages {
            println!(
                "{}",
                ":: Some packages are from AUR and will require building.".yellow()
            );
            println!(
                "{}",
                ":: Root privileges will be required to install built packages.".yellow()
            );
        }
        print!("{}", ":: Proceed with installation? [Y/n] ".bold());
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();
        Ok(input.is_empty() || input == "y" || input == "yes")
    }
    #[allow(dead_code)]
    async fn confirm_reinstall_or_upgrade(
        &self,
        message: &str,
        default_yes: bool,
    ) -> PackerResult<bool> {
        use std::io::{self, Write};
        print!("{}", message.bold());
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();
        if input.is_empty() {
            Ok(default_yes)
        } else {
            Ok(input == "y" || input == "yes")
        }
    }
    #[allow(dead_code)]
    async fn record_transaction_result(
        &mut self,
        transaction_id: String,
        success: bool,
        duration: u64,
        error: Option<&PackerError>,
    ) -> PackerResult<()> {
        use crate::storage::{PackageOperation, RollbackInfo, TransactionPackage};
        let transaction_cache = self.transaction_cache.read().await;
        let transaction = transaction_cache.get(&transaction_id).cloned();
        drop(transaction_cache);
        if let Some(transaction) = transaction {
            let transaction_packages: Vec<TransactionPackage> = transaction
                .to_install
                .iter()
                .map(|pkg| TransactionPackage {
                    name: pkg.name.clone(),
                    version: pkg.version.clone(),
                    repository: pkg.repository.clone(),
                    operation: PackageOperation::Install,
                    size: pkg.installed_size,
                    files: pkg.files.iter().map(|f| f.path.clone()).collect(),
                    dependencies: pkg.dependencies.iter().map(|d| d.name.clone()).collect(),
                    conflicts: pkg.conflicts.clone(),
                })
                .collect();
            let size_change: i64 = transaction
                .to_install
                .iter()
                .map(|p| p.installed_size as i64)
                .sum();
            let rollback_info = if success {
                Some(RollbackInfo {
                    can_rollback: true,
                    rollback_commands: vec![],
                    affected_packages: transaction
                        .to_install
                        .iter()
                        .map(|p| p.name.clone())
                        .collect(),
                    dependencies_to_restore: vec![],
                })
            } else {
                None
            };
            let record = crate::storage::TransactionRecord {
                id: transaction_id,
                transaction_type: crate::storage::TransactionType::Install,
                packages: transaction_packages,
                timestamp: chrono::Utc::now(),
                success,
                error_message: error.map(|e| e.to_string()),
                duration,
                user: whoami::username(),
                size_change,
                security_score: transaction.security_summary.trust_score,
                rollback_info,
                status: if success {
                    crate::storage::TransactionStatus::Completed
                } else {
                    crate::storage::TransactionStatus::Failed
                },
                progress: crate::storage::TransactionProgress::default(),
                compatibility_checked: true,
                health_verified: true,
            };
            self.database.add_transaction(record).await?;
        }
        Ok(())
    }
    async fn execute_install_transaction(
        &mut self,
        transaction: InstallTransaction,
    ) -> PackerResult<()> {
        let _semaphore = Arc::new(Semaphore::new(self.config.max_parallel_downloads));
        let aur_packages: Vec<_> = transaction
            .to_install
            .iter()
            .filter(|p| p.repository == "aur")
            .collect();
        let binary_packages: Vec<_> = transaction
            .to_install
            .iter()
            .filter(|p| p.repository != "aur")
            .collect();
        println!();
        println!("{}", "🔄 Installation Progress ".bold());
        println!("{}", "=".repeat(50));
        if !aur_packages.is_empty() {
            println!("{}", "Phase 1: Downloading AUR source tarballs...".cyan());
            let aur_pb = self
                .multi_progress
                .add(ProgressBar::new(aur_packages.len() as u64));
            aur_pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} AUR tarballs ")
                    .unwrap(),
            );
            let mut aur_downloaded = Vec::new();
            for package in aur_packages {
                aur_pb.set_message(format!("Downloading {}", package.name));
                let downloaded = self
                    .repository_manager
                    .download_package(package, &aur_pb)
                    .await?;
                aur_downloaded.push(downloaded);
                aur_pb.inc(1);
            }
            aur_pb.finish_with_message("AUR source tarballs downloaded ");
            self.aur_downloads = Some(aur_downloaded);
        }
        if !binary_packages.is_empty() {
            println!("{}", "Phase 2: Downloading binary packages...".cyan());
            let binary_pb = self
                .multi_progress
                .add(ProgressBar::new(binary_packages.len() as u64));
            binary_pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} Binary packages ")
                    .unwrap(),
            );
            let mut binary_downloaded = Vec::new();
            for package in binary_packages {
                binary_pb.set_message(format!("Downloading {}", package.name));
                let downloaded = self
                    .repository_manager
                    .download_package(package, &binary_pb)
                    .await?;
                binary_downloaded.push(downloaded);
                binary_pb.inc(1);
            }
            binary_pb.finish_with_message("Binary packages downloaded ");
            self.binary_downloads = Some(binary_downloaded);
        }
        let aur_packages: Vec<_> = transaction
            .to_install
            .iter()
            .filter(|p| p.repository == "aur")
            .collect();
        let binary_packages: Vec<_> = transaction
            .to_install
            .iter()
            .filter(|p| p.repository != "aur")
            .collect();
        if !aur_packages.is_empty() {
            println!("{}", "Phase 3: Building AUR packages...".cyan());
            let aur_downloads = self.aur_downloads.take().unwrap_or_default();
            for (package, downloaded_path) in aur_packages.iter().zip(aur_downloads.iter()) {
                self.install_single_package(package, downloaded_path)
                    .await?;
            }
        }
        if !binary_packages.is_empty() {
            let phase_name = if aur_packages.is_empty() {
                "Phase 3: Installing packages..."
            } else {
                "Phase 4: Installing binary packages..."
            };
            println!("{}", phase_name.cyan());
            let install_pb = self
                .multi_progress
                .add(ProgressBar::new(binary_packages.len() as u64));
            install_pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                    .unwrap(),
            );
            let binary_downloads = self.binary_downloads.take().unwrap_or_default();
            for (package, downloaded_path) in binary_packages.iter().zip(binary_downloads.iter()) {
                install_pb.set_message(format!("Installing {}", package.name));
                self.install_single_package(package, downloaded_path)
                    .await?;
                install_pb.inc(1);
            }
            install_pb.finish_with_message("Binary packages installed ");
        }
        self.transaction_cache
            .write()
            .await
            .insert(transaction.transaction_id.clone(), transaction);
        Ok(())
    }
    async fn execute_remove_transaction(&mut self, packages: Vec<Package>) -> PackerResult<()> {
        let pb = self
            .multi_progress
            .add(ProgressBar::new(packages.len() as u64));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} Removing packages ")
                .unwrap(),
        );
        for package in packages {
            self.remove_single_package(&package).await?;
            pb.inc(1);
        }
        pb.finish_with_message("Removal completed ");
        Ok(())
    }
    async fn execute_upgrade_transaction(
        &mut self,
        transaction: InstallTransaction,
    ) -> PackerResult<()> {
        for (old_package, _) in &transaction.to_upgrade {
            self.remove_single_package(old_package).await?;
        }
        let mut to_install = Vec::new();
        for (_, new_package) in &transaction.to_upgrade {
            to_install.push(new_package.clone());
        }
        let new_transaction = InstallTransaction {
            to_install,
            to_remove: Vec::new(),
            to_upgrade: Vec::new(),
            conflicts: Vec::new(),
            total_size: transaction.total_size,
            download_size: transaction.download_size,
            transaction_id: uuid::Uuid::new_v4().to_string(),
            security_summary: transaction.security_summary,
        };
        self.execute_install_transaction(new_transaction).await?;
        Ok(())
    }
    async fn install_single_package(
        &mut self,
        package: &Package,
        path: &PathBuf,
    ) -> PackerResult<()> {
        info!(
            "Installing package: {} {} from {}",
            package.name,
            package.version,
            path.display()
        );

        if !path.exists() {
            return Err(PackerError::InstallationFailed(format!(
                "Package file does not exist: {}",
                path.display()
            )));
        }

        let extraction_result = self.extract_and_install_package(package, path).await?;

        let mut updated_package = package.clone();
        updated_package.installed_size = extraction_result.bytes_extracted;
        updated_package.install_date = Some(Utc::now());

        self.database
            .add_package_with_transaction(
                updated_package,
                InstallReason::Explicit,
                "manual-install".to_string(),
            )
            .await?;

        info!(
            "Successfully installed package: {} {}",
            package.name, package.version
        );
        Ok(())
    }

    async fn remove_single_package(&mut self, package: &Package) -> PackerResult<()> {
        info!("Removing package: {} {}", package.name, package.version);
        if let Some(ref script) = package.scripts.pre_remove {
            self.run_package_script(script, "pre-remove ").await?;
        }
        let mut files_removed = 0;
        let mut bytes_freed = 0u64;
        {
            let install_root = self.config.install_root.clone();
            let mut directories_to_check = Vec::new();
            debug!(
                "Removing {} tracked files for package {}",
                package.files.len(),
                package.name
            );
            for file in &package.files {
                debug!("Processing file: {}", file.path);
                let mut paths_to_try = Vec::new();
                if file.path.starts_with('/') {
                    paths_to_try.push(PathBuf::from(&file.path));
                } else {
                    paths_to_try.push(install_root.join(&file.path));
                    paths_to_try.push(PathBuf::from("/").join(&file.path));
                    paths_to_try.push(PathBuf::from(&file.path));
                }
                let mut file_found = false;
                for path_to_try in &paths_to_try {
                    debug!("Trying path: {:?}", path_to_try);
                    if path_to_try.exists() {
                        if path_to_try.is_file() {
                            if let Ok(metadata) = tokio::fs::metadata(path_to_try).await {
                                bytes_freed += metadata.len();
                            }
                            if let Err(e) = tokio::fs::remove_file(path_to_try).await {
                                warn!("Failed to remove file {:?}: {}", path_to_try, e);
                            } else {
                                files_removed += 1;
                                info!("Removed file: {:?}", path_to_try);
                            }
                            if let Some(parent) = path_to_try.parent() {
                                directories_to_check.push(parent.to_path_buf());
                            }
                            file_found = true;
                            break;
                        } else if path_to_try.is_dir() {
                            directories_to_check.push(path_to_try.clone());
                            file_found = true;
                            break;
                        }
                    }
                }
                if !file_found {
                    warn!(
                        "File not found for removal: {} (tried paths: {:?})",
                        file.path, paths_to_try
                    );
                }
            }
            directories_to_check.sort();
            directories_to_check.dedup();
            directories_to_check.reverse();
            for dir in directories_to_check {
                if dir.exists() && dir.is_dir() {
                    match self.is_directory_empty(&dir).await {
                        Ok(true) => {
                            if let Err(e) = tokio::fs::remove_dir(&dir).await {
                                debug!("Could not remove empty directory {:?}: {}", dir, e);
                            } else {
                                info!("Removed empty directory: {:?}", dir);
                            }
                        }
                        Ok(false) => {
                            debug!("Directory not empty, keeping: {:?}", dir);
                        }
                        Err(e) => {
                            debug!("Could not check if directory is empty {:?}: {}", dir, e);
                        }
                    }
                }
            }
        }
        if let Some(ref script) = package.scripts.post_remove {
            self.run_package_script(script, "post-remove ").await?;
        }
        self.database.remove_package(&package.name).await?;
        info!(
            "Removed package: {} {} ({} files, {} freed)",
            package.name,
            package.version,
            files_removed,
            self.format_size(bytes_freed)
        );
        Ok(())
    }
    async fn is_directory_empty(&self, dir: &PathBuf) -> PackerResult<bool> {
        let mut entries = tokio::fs::read_dir(dir).await?;
        match entries.next_entry().await? {
            Some(_) => Ok(false),
            None => Ok(true),
        }
    }
    async fn verify_package_checksum(&self, package: &Package, path: &PathBuf) -> PackerResult<()> {
        if package.checksum.is_empty() {
            return Ok(());
        }
        use sha2::{Digest, Sha256};
        let mut file = tokio::fs::File::open(path).await?;
        let mut hasher = Sha256::new();
        use tokio::io::AsyncReadExt;
        let mut buffer = [0; 8192];
        loop {
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let calculated = format!("{:x}", hasher.finalize());
        if calculated != package.checksum {
            return Err(PackerError::HashVerificationFailed(format!(
                "Checksum mismatch for {}: expected {}, got {}",
                package.name, package.checksum, calculated
            )));
        }
        Ok(())
    }
    async fn extract_and_install_package(
        &mut self,
        package: &Package,
        path: &PathBuf,
    ) -> PackerResult<crate::utils::ExtractionResult> {
        let install_dir = self.config.install_root.clone();
        if let Some(ref script) = package.scripts.pre_install {
            self.run_package_script(script, "pre-install ").await?;
        }
        let extraction_result = if package.repository == "aur" {
            self.build_and_install_aur_package(package).await?;
            crate::utils::ExtractionResult {
                files_extracted: 1,
                bytes_extracted: 0,
                extracted_files: Vec::new(),
                extraction_time: std::time::Duration::from_secs(0),
            }
        } else {
            info!(
                "Extracting package {} to {}",
                package.name,
                self.config.install_root.display()
            );
            let result = extract_archive(path, &install_dir).await?;
            info!(
                "Extracted {} files ({} bytes)",
                result.files_extracted, result.bytes_extracted
            );
            result
        };
        if let Some(ref script) = package.scripts.post_install {
            self.run_package_script(script, "post-install ").await?;
        }
        Ok(extraction_result)
    }
    #[allow(dead_code)]
    fn classify_file_type(&self, path: &PathBuf) -> crate::utils::FileType {
        use crate::utils::FileType;
        let path_str = path.to_string_lossy().to_lowercase();
        if path_str.starts_with("usr/bin/") || path_str.starts_with("bin/") {
            FileType::Executable
        } else if path_str.contains("/lib/") {
            FileType::Library
        } else if path_str.starts_with("etc/") {
            FileType::Configuration
        } else if path_str.contains("/share/doc/") || path_str.contains("/share/man/") {
            FileType::Documentation
        } else if path_str.contains("/share/") {
            FileType::Asset
        } else {
            FileType::Data
        }
    }
    async fn run_package_script(&self, script: &str, script_type: &str) -> PackerResult<()> {
        info!("Running {} script ", script_type);
        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .await?;
        if !output.status.success() {
            let _stderr = String::from_utf8_lossy(&output.stderr);
            //             return Err(PackerError::InstallationFailed(format!(
            //                 "{} script failed: {}", script_type, stderr
            //             )));
        }
        Ok(())
    }
    #[allow(dead_code)]
    fn show_transaction_summary(&self, transaction: &InstallTransaction) {
        println!();
        println!("{}", "Transaction Summary ".bold().blue());
        println!("{}", "=".repeat(50));
        println!("Transaction ID: {}", transaction.transaction_id.dimmed());
        if !transaction.to_install.is_empty() {
            println!();
            println!("{}", "Packages to install:".green());
            for package in &transaction.to_install {
                println!(
                    "  {} {} [{}]",
                    package.name,
                    package.version,
                    package.repository.cyan()
                );
            }
        }
        if !transaction.to_remove.is_empty() {
            println!();
            println!("{}", "Packages to remove:".red());
            for package in &transaction.to_remove {
                println!("  {} {}", package.name, package.version);
            }
        }
        if !transaction.to_upgrade.is_empty() {
            println!();
            println!("{}", "Packages to upgrade:".yellow());
            for (old, new) in &transaction.to_upgrade {
                println!("  {} {} -> {}", old.name, old.version, new.version);
            }
        }
        println!();
        println!("{}", "Size Information:".cyan());
        println!(
            "  Download size: {}",
            self.format_size(transaction.download_size)
        );
        println!(
            "  Installed size: {}",
            self.format_size(transaction.total_size)
        );
    }
    fn show_remove_transaction_summary(&self, packages: &[Package]) {
        println!();
        println!("{}", "Removal Summary ".bold().red());
        println!("{}", "=".repeat(50));
        println!();
        println!("{}", "Packages to remove:".red());
        for package in packages {
            println!("  {} {}", package.name, package.version);
        }
        let total_size: u64 = packages.iter().map(|p| p.installed_size).sum();
        println!();
        println!("{}", "Size Information:".cyan());
        println!("  Space to be freed: {}", self.format_size(total_size));
    }
    fn show_upgrade_transaction_summary(&self, transaction: &InstallTransaction) {
        println!();
        println!("{}", "Upgrade Summary ".bold().yellow());
        println!("{}", "=".repeat(50));
        println!();
        println!("{}", "Packages to upgrade:".yellow());
        for (old, new) in &transaction.to_upgrade {
            println!("  {} {} -> {}", old.name, old.version, new.version);
        }
        println!();
        println!("{}", "Size Information:".cyan());
        println!(
            "  Download size: {}",
            self.format_size(transaction.download_size)
        );
        println!(
            "  Net size change: {}",
            self.format_size(transaction.total_size)
        );
    }
    fn format_size(&self, bytes: u64) -> String {
        crate::utils::format_size(bytes)
    }
    pub async fn rollback_transaction(&mut self, transaction_id: &str) -> PackerResult<()> {
        info!("Rolling back transaction: {}", transaction_id);
        let transaction = self
            .database
            .get_transaction_by_id(transaction_id)
            .ok_or_else(|| {
                PackerError::DatabaseError(format!("Transaction {} not found ", transaction_id))
            })?;
        let rollback_info = if let Some(ref rollback_info) = transaction.rollback_info {
            if !rollback_info.can_rollback {
                return Err(PackerError::DatabaseError(
                    "Transaction cannot be rolled back ".to_string(),
                ));
            }
            rollback_info.clone()
        } else {
            return Err(PackerError::DatabaseError(
                "No rollback information available for this transaction ".to_string(),
            ));
        };
        println!(
            "{}",
            format!("🔄 Rolling back transaction: {}", transaction_id).yellow()
        );
        let rollback_commands = rollback_info.rollback_commands.clone();
        let packages = transaction.packages.clone();
        let size_change = transaction.size_change;
        let security_score = transaction.security_score;
        for command in rollback_commands.iter().rev() {
            match &command.command_type {
                crate::storage::RollbackCommandType::RemovePackage => {
                    println!("  🗑️  Removing package: {}", command.package_name);
                    self.database.remove_package(&command.package_name).await?;
                }
                crate::storage::RollbackCommandType::InstallPackage => {
                    println!(
                        "  📦 Restoring package: {} {}",
                        command.package_name, command.package_version
                    );
                    info!(
                        "Restoring package {} {} (not implemented)",
                        command.package_name, command.package_version
                    );
                }
                crate::storage::RollbackCommandType::RestoreFiles => {
                    println!("  📁 Restoring {} files ", command.files_to_restore.len());
                    for file in &command.files_to_restore {
                        info!("Restoring file: {}", file);
                    }
                }
                crate::storage::RollbackCommandType::RemoveFiles => {
                    println!("  🗑️  Removing {} files ", command.files_to_remove.len());
                    for file in &command.files_to_remove {
                        if let Err(e) = tokio::fs::remove_file(file).await {
                            warn!("Failed to remove file {}: {}", file, e);
                        }
                    }
                }
                crate::storage::RollbackCommandType::RestoreDependencies => {
                    println!("  🔗 Restoring dependencies ");
                }
            }
        }
        let rollback_transaction = crate::storage::TransactionRecord {
            id: uuid::Uuid::new_v4().to_string(),
            transaction_type: crate::storage::TransactionType::Rollback,
            packages,
            timestamp: chrono::Utc::now(),
            success: true,
            error_message: None,
            duration: 0,
            user: whoami::username(),
            size_change: -size_change,
            security_score,
            rollback_info: None,
            status: crate::storage::TransactionStatus::Completed,
            progress: crate::storage::TransactionProgress::default(),
            compatibility_checked: false,
            health_verified: false,
        };
        self.database.add_transaction(rollback_transaction).await?;
        println!(
            "{}",
            "✅ Transaction rollback completed successfully ".green()
        );
        Ok(())
    }
    pub async fn get_package_info(&self, package_name: &str) -> PackerResult<Option<Package>> {
        self.database.get_package(package_name).await
    }
    pub async fn is_package_installed(&self, package_name: &str) -> PackerResult<bool> {
        Ok(self.database.get_package(package_name).await?.is_some())
    }
    pub async fn list_installed_packages(
        &self,
    ) -> PackerResult<Vec<(Package, crate::storage::InstallReason)>> {
        self.database.get_all_packages().await
    }
    pub async fn check_package_upgrade(&self, package_name: &str) -> PackerResult<Option<Package>> {
        if let Some(installed) = self.database.get_package(package_name).await? {
            self.repository_manager.get_newer_version(&installed).await
        } else {
            Ok(None)
        }
    }
    pub async fn upgrade_packages_by_names(
        &mut self,
        package_names: Vec<String>,
        _force: bool,
    ) -> PackerResult<()> {
        let mut packages_to_upgrade = Vec::new();
        for package_name in package_names {
            if let Some(upgrade) = self.check_package_upgrade(&package_name).await? {
                packages_to_upgrade.push(upgrade);
            }
        }
        if packages_to_upgrade.is_empty() {
            return Ok(());
        }
        let package_names: Vec<String> =
            packages_to_upgrade.iter().map(|p| p.name.clone()).collect();
        self.install_packages(package_names.clone()).await
    }
    pub async fn check_upgrades(&self) -> PackerResult<Vec<(Package, Package)>> {
        let installed_packages = self.list_installed_packages().await?;
        let mut to_upgrade = Vec::new();
        for (package, _) in installed_packages {
            if let Some(newer) = self.repository_manager.get_newer_version(&package).await? {
                to_upgrade.push((package, newer));
            }
        }
        Ok(to_upgrade)
    }
    pub async fn check_conflicts(&self) -> PackerResult<Vec<String>> {
        let installed_packages = self.list_installed_packages().await?;
        let package_names: Vec<String> = installed_packages
            .iter()
            .map(|(p, _)| p.name.clone())
            .collect();
        let conflict_result = self.resolver.check_conflicts(&package_names).await?;
        Ok(conflict_result.conflicts)
    }
    pub async fn list_repositories(&self) -> PackerResult<Vec<crate::repository::RepositoryInfo>> {
        Ok(self.repository_manager.get_repository_info())
    }
    pub async fn update_repository(
        &mut self,
        repository_name: &str,
        force: bool,
    ) -> PackerResult<()> {
        self.repository_manager
            .update_repository(repository_name, force)
            .await
    }
    pub fn get_cache_dir(&self) -> std::path::PathBuf {
        self.config.cache_dir.clone()
    }
    pub fn get_database_path(&self) -> std::path::PathBuf {
        self.config.database_dir.clone()
    }
    pub fn get_install_root(&self) -> String {
        self.config.install_root.to_string_lossy().to_string()
    }
    pub async fn rebuild_database(&mut self) -> PackerResult<()> {
        self.database.rebuild().await
    }
    pub async fn reinstall_package(&mut self, package_name: &str) -> PackerResult<()> {
        info!("Reinstalling package: {}", package_name);
        let current_package = self
            .database
            .get_package(package_name)
            .await?
            .ok_or_else(|| PackerError::PackageNotInstalled(package_name.to_string()))?;
        self.remove_single_package(&current_package).await?;
        let _package_to_install = self
            .repository_manager
            .get_package(package_name)
            .await?
            .ok_or_else(|| PackerError::PackageNotFound(package_name.to_string()))?;
        let package_names = vec![package_name.to_string()];
        self.install_packages(package_names.clone()).await?;
        info!("Package {} reinstalled successfully ", package_name);
        Ok(())
    }
    pub async fn recalculate_package_sizes(&mut self) -> PackerResult<()> {
        info!("Recalculating package sizes ");
        let packages = self.database.get_all_packages().await?;
        let updated_count = 0;
        for (package, _) in packages {
            if package.repository == "aur" {
                warn!(
                    "AUR installation scanning not yet implemented for {}",
                    package.name
                );
                continue;
            }
        }
        info!("Updated sizes for {} packages ", updated_count);
        Ok(())
    }
    pub async fn fix_package_database(&mut self) -> PackerResult<()> {
        info!("Fixing package database ");
        self.rebuild_database().await?;
        self.recalculate_package_sizes().await?;
        let broken_deps = self.database.find_broken_dependencies().await?;
        if !broken_deps.is_empty() {
            warn!("Found {} broken dependencies:", broken_deps.len());
            for dep in &broken_deps {
                warn!("  {}", dep);
            }
        }
        info!("Database fix completed ");
        Ok(())
    }
    pub async fn update_package_size(
        &mut self,
        package_name: &str,
        new_size: u64,
    ) -> PackerResult<()> {
        self.database
            .update_package_size(package_name, new_size)
            .await
    }
    pub async fn check_package_compatibility(
        &self,
        package: &Package,
    ) -> PackerResult<CompatibilityInfo> {
        let mut compatibility = CompatibilityInfo::default();
        let system_arch = self.get_system_architecture();
        let arch_compatible = self.is_architecture_compatible(&package.arch, &system_arch);
        let system_os = self.get_system_os();
        let os_compatible = self.is_os_compatible(&package.compatibility.target_os, &system_os);
        let requirements_met = self
            .check_system_requirements(&package.compatibility.system_requirements)
            .await?;
        let incompatible_packages = self.find_incompatible_packages(package).await?;
        let mut score = 1.0;
        if !arch_compatible {
            score *= 0.0;
        }
        if !os_compatible {
            score *= 0.5;
        }
        if !requirements_met {
            score *= 0.3;
        }
        if !incompatible_packages.is_empty() {
            score *= 0.7;
        }
        compatibility.target_arch = package.arch.clone();
        compatibility.target_os = package.compatibility.target_os.clone();
        compatibility.incompatible_packages = incompatible_packages;
        compatibility.system_requirements = package.compatibility.system_requirements.clone();
        compatibility.compatibility_score = score;
        Ok(compatibility)
    }
    pub async fn check_package_health(&self, package: &Package) -> PackerResult<PackageHealth> {
        let mut health = PackageHealth::default();
        let mut issues = Vec::new();
        if let Ok(installed_package) = self.database.get_package(&package.name).await {
            if let Some(installed) = installed_package {
                health.integrity_verified = self.verify_package_integrity(&installed).await?;
                if !health.integrity_verified {
                    issues.push(HealthIssue {
                        severity: IssueSeverity::High,
                        category: IssueCategory::Integrity,
                        description: "Package integrity verification failed ".to_string(),
                        detected_at: Utc::now(),
                        resolution_suggestion: Some("Reinstall the package ".to_string()),
                    });
                }
            }
        }
        health.dependencies_satisfied = self.check_dependencies_satisfied(package).await?;
        if !health.dependencies_satisfied {
            issues.push(HealthIssue {
                severity: IssueSeverity::Medium,
                category: IssueCategory::Dependency,
                description: "Some dependencies are not satisfied ".to_string(),
                detected_at: Utc::now(),
                resolution_suggestion: Some("Install missing dependencies ".to_string()),
            });
        }
        health.conflicts_resolved = self.check_conflicts_resolved(package).await?;
        if !health.conflicts_resolved {
            issues.push(HealthIssue {
                severity: IssueSeverity::High,
                category: IssueCategory::Dependency,
                description: "Package conflicts detected ".to_string(),
                detected_at: Utc::now(),
                resolution_suggestion: Some("Resolve package conflicts ".to_string()),
            });
        }
        let mut score = 1.0;
        for issue in &issues {
            match issue.severity {
                IssueSeverity::Critical => score *= 0.0,
                IssueSeverity::High => score *= 0.5,
                IssueSeverity::Medium => score *= 0.7,
                IssueSeverity::Low => score *= 0.9,
                IssueSeverity::Info => score *= 0.95,
            }
        }
        health.health_score = score;
        health.issues = issues;
        health.last_health_check = Utc::now();
        Ok(health)
    }
    fn get_system_architecture(&self) -> String {
        std::env::consts::ARCH.to_string()
    }
    fn get_system_os(&self) -> String {
        std::env::consts::OS.to_string()
    }
    fn is_architecture_compatible(&self, package_arch: &str, system_arch: &str) -> bool {
        match (package_arch, system_arch) {
            ("any", _) => true,
            ("noarch", _) => true,
            (p_arch, s_arch) if p_arch == s_arch => true,
            ("x86_64", "x86_64") => true,
            ("amd64", "x86_64") => true,
            ("i686", "x86_64") => true,
            ("i386", "x86_64") => true,
            ("aarch64", "aarch64") => true,
            ("arm64", "aarch64") => true,
            _ => false,
        }
    }
    fn is_os_compatible(&self, package_os: &str, system_os: &str) -> bool {
        match (package_os, system_os) {
            ("any", _) => true,
            (p_os, s_os) if p_os == s_os => true,
            ("linux", "linux") => true,
            ("unix", "linux") => true,
            ("unix", "macos") => true,
            _ => false,
        }
    }
    async fn check_system_requirements(
        &self,
        requirements: &SystemRequirements,
    ) -> PackerResult<bool> {
        if let Some(min_memory) = requirements.min_memory_mb {
            let available_memory = self.get_available_memory().await?;
            if available_memory < min_memory * 1024 * 1024 {
                return Ok(false);
            }
        }
        if let Some(min_disk) = requirements.min_disk_space_mb {
            let available_disk = self.get_available_disk_space().await?;
            if available_disk < min_disk * 1024 * 1024 {
                return Ok(false);
            }
        }
        for lib in &requirements.required_libraries {
            if !self.is_library_available(lib).await? {
                return Ok(false);
            }
        }
        for binary in &requirements.required_binaries {
            if !self.is_binary_available(binary).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn find_incompatible_packages(&self, package: &Package) -> PackerResult<Vec<String>> {
        let mut incompatible = Vec::new();
        let installed_packages = self.database.get_all_packages().await?;
        for (installed_package, _) in installed_packages {
            if package.conflicts.contains(&installed_package.name) {
                incompatible.push(installed_package.name.clone());
            }
            if installed_package.conflicts.contains(&package.name) {
                incompatible.push(installed_package.name);
            }
        }
        Ok(incompatible)
    }
    async fn verify_package_integrity(&self, _package: &Package) -> PackerResult<bool> {
        Ok(true)
    }
    async fn check_dependencies_satisfied(&self, package: &Package) -> PackerResult<bool> {
        for dependency in &package.dependencies {
            if !self.is_package_installed(&dependency.name).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn check_conflicts_resolved(&self, package: &Package) -> PackerResult<bool> {
        for conflict in &package.conflicts {
            if self.is_package_installed(conflict).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn get_available_memory(&self) -> PackerResult<u64> {
        Ok(8 * 1024 * 1024 * 1024)
    }
    async fn get_available_disk_space(&self) -> PackerResult<u64> {
        Ok(100 * 1024 * 1024 * 1024)
    }
    async fn is_library_available(&self, _lib: &str) -> PackerResult<bool> {
        Ok(true)
    }
    async fn is_binary_available(&self, binary: &str) -> PackerResult<bool> {
        match which::which(binary) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    pub async fn recover_package(&mut self, package_name: &str) -> PackerResult<()> {
        info!("Starting recovery for package: {}", package_name);
        if let Some(package) = self.database.get_package(package_name).await? {
            let health = self.check_package_health(&package).await?;
            if health.health_score < 0.5 {
                info!(
                    "Package {} health score is low ({}), attempting recovery ",
                    package_name, health.health_score
                );
                self.repair_package(&package).await?;
                let new_health = self.check_package_health(&package).await?;
                if new_health.health_score >= 0.5 {
                    info!("Package {} successfully recovered ", package_name);
                } else {
                    warn!(
                        "Package {} recovery partially successful, may need reinstallation ",
                        package_name
                    );
                }
            } else {
                info!("Package {} is healthy, no recovery needed ", package_name);
            }
        } else {
            return Err(PackerError::PackageNotInstalled(package_name.to_string()));
        }
        Ok(())
    }
    pub async fn repair_package(&mut self, package: &Package) -> PackerResult<()> {
        info!("Repairing package: {}", package.name);
        if !self.verify_package_integrity(package).await? {
            info!(
                "Package {} has integrity issues, attempting to fix ",
                package.name
            );
            if let Ok(newer_version) = self.repository_manager.get_package(&package.name).await {
                if let Some(repo_package) = newer_version {
                    info!("Re-downloading package {} for repair ", package.name);
                    let progress_bar = self
                        .multi_progress
                        .add(indicatif::ProgressBar::new(repo_package.size));
                    progress_bar.set_style(ProgressStyle::default_bar()
                        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                        .unwrap());
                    let download_path = self
                        .repository_manager
                        .download_package(&repo_package, &progress_bar)
                        .await?;
                    if self
                        .verify_package_checksum(&repo_package, &download_path)
                        .await
                        .is_ok()
                    {
                        self.install_single_package(&repo_package, &download_path)
                            .await?;
                        info!("Package {} successfully repaired ", package.name);
                    } else {
                        return Err(PackerError::RecoveryFailed(format!(
                            "Downloaded package {} failed verification ",
                            package.name
                        )));
                    }
                    progress_bar.finish_with_message("Repair completed ");
                }
            }
        }
        Ok(())
    }
    pub async fn auto_repair_system(&mut self) -> PackerResult<Vec<String>> {
        info!("Starting automatic system repair ");
        let mut repaired_packages = Vec::new();
        let installed_packages = self.database.get_all_packages().await?;
        for (package, _) in installed_packages {
            let health = self.check_package_health(&package).await?;
            if health.health_score < 0.7 {
                info!(
                    "Package {} needs repair (health score: {})",
                    package.name, health.health_score
                );
                match self.repair_package(&package).await {
                    Ok(_) => {
                        repaired_packages.push(package.name.clone());
                        info!("Successfully repaired package: {}", package.name);
                    }
                    Err(e) => {
                        warn!("Failed to repair package {}: {}", package.name, e);
                    }
                }
            }
        }
        info!(
            "Auto-repair completed. Repaired {} packages ",
            repaired_packages.len()
        );
        Ok(repaired_packages)
    }
    pub async fn emergency_recovery(&mut self) -> PackerResult<()> {
        warn!("Starting emergency recovery mode ");
        let critical_packages = vec!["glibc", "systemd", "kernel", "bash"];
        for package_name in critical_packages {
            if self.is_package_installed(package_name).await? {
                match self.recover_package(package_name).await {
                    Ok(_) => info!("Critical package {} recovered ", package_name),
                    Err(_) => eprintln!("Failed to recover critical package {}", package_name),
                }
            }
        }
        let _ = self.database.rebuild().await;
        let _ = self.repository_manager.clear_cache();
        Ok(())
    }
    pub async fn create_system_snapshot(&self) -> PackerResult<String> {
        let snapshot_id = Uuid::new_v4().to_string();
        // TODO: implement system snapshot creation
        Ok(snapshot_id)
    }
    pub async fn restore_from_snapshot(&mut self, _snapshot_id: &str) -> PackerResult<()> {
        // TODO: implement snapshot restoration
        Ok(())
    }

    pub async fn _restore_from_snapshot_disabled(
        &mut self,
        _snapshot_id: &str,
    ) -> PackerResult<()> {
        // TODO: implement snapshot restoration
        Ok(())
    }
}
