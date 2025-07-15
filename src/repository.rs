use crate::{
    config::{Config, RepositoryConfig, RepositoryType, TrustLevel},
    dependency::Dependency,
    error::{PackerError, PackerResult},
    package::Package,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures::StreamExt;
use indicatif::ProgressBar;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::Duration,
    collections::HashSet,
};
use tokio::{fs, time::sleep};
use log::{debug, info, warn};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryHealth {
    pub status: RepositoryStatus,
    pub last_health_check: DateTime<Utc>,
    pub response_time_ms: u64,
    pub success_rate: f64,
    pub issues: Vec<RepositoryIssue>,
    pub uptime_score: f64,
    pub security_score: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RepositoryStatus {
    Healthy,
    Degraded,
    Unavailable,
    Maintenance,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryIssue {
    pub severity: IssueSeverity,
    pub category: IssueCategory,
    pub description: String,
    pub detected_at: DateTime<Utc>,
    pub resolution: Option<String>,
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
    Connectivity,
    Performance,
    Security,
    Content,
    Synchronization,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorStatus {
    pub available_mirrors: Vec<MirrorInfo>,
    pub current_mirror: Option<String>,
    pub failover_enabled: bool,
    pub last_failover: Option<DateTime<Utc>>,
    pub auto_select_best: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorInfo {
    pub url: String,
    pub status: MirrorHealthStatus,
    pub response_time_ms: u64,
    pub last_checked: DateTime<Utc>,
    pub reliability_score: f64,
    pub geographic_location: Option<String>,
    pub bandwidth_score: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MirrorHealthStatus {
    Online,
    Slow,
    Offline,
    Timeout,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub priority: i32,
    pub last_update: Option<DateTime<Utc>>,
    pub packages: HashMap<String, Package>,
    pub repo_type: RepositoryType,
    pub trust_level: TrustLevel,
    pub metadata: RepositoryMetadata,
    pub health: RepositoryHealth,
    pub mirror_status: MirrorStatus,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryMetadata {
    pub version: String,
    pub description: Option<String>,
    pub maintainer: Option<String>,
    pub homepage: Option<String>,
    pub package_count: usize,
    pub total_size: u64,
    pub categories: Vec<String>,
    pub languages: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryIndex {
    pub version: String,
    pub timestamp: DateTime<Utc>,
    pub packages: Vec<PackageMetadata>,
    pub metadata: Option<RepositoryMetadata>,
    pub signature: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub repository: String,
    pub arch: String,
    pub size: u64,
    pub installed_size: u64,
    pub dependencies: Vec<String>,
    pub conflicts: Vec<String>,
    pub provides: Vec<String>,
    pub replaces: Vec<String>,
    pub maintainer: String,
    pub license: String,
    pub url: String,
    pub checksum: String,
    pub signature: Option<String>,
    pub build_date: DateTime<Utc>,
    pub download_url: String,
    pub category: Option<String>,
    pub tags: Vec<String>,
    pub popularity: Option<f64>,
    pub security_scan: Option<SecurityScan>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScan {
    pub scanned_at: DateTime<Utc>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub score: f64,
    pub passed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: String,
    pub description: String,
    pub fixed_in: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub name: String,
    pub body: String,
    pub draft: bool,
    pub prerelease: bool,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub assets: Vec<GitHubAsset>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
    pub content_type: String,
}
pub struct RepositoryManager {
    config: Config,
    repositories: Arc<DashMap<String, Repository>>,
    client: Client,
    cache_dir: PathBuf,
    github_client: Option<GitHubClient>,
}
pub struct GitHubClient {
    client: Client,
    _token: Option<String>,
}
impl GitHubClient {
    pub fn new(token: Option<String>) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static("packer-pm/1.0"),
        );
        if let Some(ref token) = token {
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("token {}", token)).unwrap(),
            );
        }
        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        Self { client, _token: token }
    }
    pub async fn get_releases(&self, owner: &str, repo: &str) -> PackerResult<Vec<GitHubRelease>> {
        let url = format!("https://api.github.com/repos/{}/{}/releases", owner, repo);
        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "GitHub API error: {}", response.status()
            )));
        }
        let releases: Vec<GitHubRelease> = response.json().await?;
        Ok(releases)
    }
    pub async fn search_repositories(&self, query: &str, per_page: u32) -> PackerResult<Vec<serde_json::Value>> {
        let url = format!("https://api.github.com/search/repositories?q={}&per_page={}", query, per_page);
        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "GitHub search error: {}", response.status()
            )));
        }
        let result: serde_json::Value = response.json().await?;
        Ok(result["items"].as_array().unwrap_or(&vec![]).clone())
    }
}
impl RepositoryManager {
    pub async fn new(config: Config) -> PackerResult<Self> {
        let client = Self::create_http_client(&config)?;
        let cache_dir = PathBuf::from(&config.cache_dir);
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).await?;
        }
        let github_client = if config.auto_discover {
            Some(GitHubClient::new(config.github_token.clone()))
        } else {
            None
        };
        let mut manager = Self {
            config,
            repositories: Arc::new(DashMap::new()),
            client,
            cache_dir,
            github_client,
        };
        manager.initialize_repositories().await?;
        manager.load_repository_data().await?;
        Ok(manager)
    }
    fn create_http_client(config: &Config) -> PackerResult<Client> {
        let mut client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .user_agent(&config.user_agent)
            .https_only(true);
        if let Some(ref proxy) = config.http_proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::http(proxy)?);
        }
        if let Some(ref proxy) = config.https_proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::https(proxy)?);
        }
        Ok(client_builder.build()?)
    }
    async fn initialize_repositories(&mut self) -> PackerResult<()> {
        info!("Initializing repositories");
        for repo_config in &self.config.repositories {
            if !repo_config.enabled {
                continue;
            }
            let repository = Repository {
                name: repo_config.name.clone(),
                url: repo_config.url.clone(),
                enabled: repo_config.enabled,
                priority: repo_config.priority,
                last_update: None,
                packages: HashMap::new(),
                repo_type: repo_config.repo_type.clone(),
                trust_level: repo_config.trust_level.clone(),
                metadata: RepositoryMetadata {
                    version: "1.0".to_string(),
                    description: None,
                    maintainer: None,
                    homepage: None,
                    package_count: 0,
                    total_size: 0,
                    categories: Vec::new(),
                    languages: Vec::new(),
                },
                health: RepositoryHealth::default(),
                mirror_status: MirrorStatus::default(),
            };
            self.repositories.insert(repo_config.name.clone(), repository);
        }
        info!("Initialized {} repositories", self.repositories.len());
        Ok(())
    }
    pub async fn update_all(&mut self) -> PackerResult<()> {
        info!("Updating all repositories");
        let repo_names: Vec<String> = self
            .repositories
            .iter()
            .filter(|entry| entry.value().enabled)
            .map(|entry| entry.key().clone())
            .collect();
        let tasks: Vec<_> = repo_names.iter().map(|repo_name| {
            self.update_repository_concurrent(repo_name)
        }).collect();
        let results = futures::future::join_all(tasks).await;
        for (_i, result) in results.into_iter().enumerate() {
            if let Err(e) = result {
                warn!("Failed to update repository: {}", e);
            }
        }
        self.save_repository_data().await?;
        info!("All repositories updated successfully");
        Ok(())
    }
    async fn update_repository_concurrent(&self, name: &str) -> PackerResult<()> {
        let repo_config = self.config.get_repository(name)
            .ok_or_else(|| PackerError::RepositoryError(format!("Repository {} not found ", name)))?;
        match repo_config.repo_type {
            RepositoryType::Packer => self.update_packer_repository(name).await,
            RepositoryType::AUR => self.update_aur_repository(name).await,
            RepositoryType::Arch => self.update_arch_repository(name).await,
            RepositoryType::GitHub => self.update_github_repository(name).await,
            RepositoryType::NPM => self.update_npm_repository(name).await,
            RepositoryType::PyPI => self.update_pypi_repository(name).await,
            RepositoryType::Debian => self.update_debian_repository(name).await,
            RepositoryType::Ubuntu => self.update_ubuntu_repository(name).await,
            RepositoryType::Fedora => self.update_fedora_repository(name).await,
            RepositoryType::Custom => self.update_custom_repository(name).await,
            RepositoryType::Flatpak => {
                println!("Flatpak repository updates not yet implemented");
                Ok(())
            },
            RepositoryType::AppImage => {
                println!("AppImage repository updates not yet implemented");
                Ok(())
            }
            RepositoryType::Cargo => {
                println!("Cargo repository updates not yet implemented");
                Ok(())
            },
            RepositoryType::Nix => {
                println!("Nix repository updates not yet implemented");
                Ok(())
            },
            RepositoryType::Homebrew => {
                println!("Homebrew repository updates not yet implemented");
                Ok(())
            },
        }
    }
    async fn update_packer_repository(&self, name: &str) -> PackerResult<()> {
        let repo_url = {
            let repo = self.repositories.get(name)
                .ok_or_else(|| PackerError::RepositoryError(format!("Repository {} not found ", name)))?;
            repo.url.clone()
        };
        info!("Updating Packer repository: {}", name);
        let index_url = format!("{}/index.json", repo_url);
        let response = self.client.get(&index_url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "Failed to fetch repository index: {}",
                response.status()
            )));
        }
        let index: RepositoryIndex = response.json().await?;
        if let Some(signature) = &index.signature {
            self.verify_repository_signature(&index, signature, name).await?;
        }
        debug!("Repository {} has {} packages ", name, index.packages.len());
        let mut packages_to_add = Vec::new();
        for metadata in index.packages {
            packages_to_add.push(self.convert_metadata_to_package(metadata, name).await?);
        }
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages.clear();
            for package in packages_to_add {
                repo.packages.insert(package.name.clone(), package);
            }
            repo.last_update = Some(Utc::now());
            if let Some(metadata) = index.metadata {
                repo.metadata = metadata;
            }
        }
        info!("Repository {} updated with {} packages ", name, 
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    async fn update_github_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating GitHub repository: {}", name);
        let github_client = self.github_client.as_ref()
            .ok_or_else(|| PackerError::RepositoryError("GitHub client not initialized".into()))?;
        let popular_packages = github_client.search_repositories(
            "language:rust stars:>100 archived:false", 50
        ).await?;
        let mut packages = HashMap::new();
        for repo_info in popular_packages {
            if let Some(package) = self.github_repo_to_package(repo_info, name).await? {
                packages.insert(package.name.clone(), package);
            }
        }
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages = packages;
            repo.last_update = Some(Utc::now());
        }
        info!("GitHub repository {} updated with {} packages ", name,
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    async fn update_aur_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating AUR repository: {}", name);
        
        let search_url = "https://aur.archlinux.org/rpc/?v=5&type=search&by=popularity&arg=";
        let response = self.client.get(&format!("{}popular", search_url)).send().await?;
        
        let mut package_names = Vec::new();
        if response.status().is_success() {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if let Some(results) = json["results"].as_array() {
                    for result in results.iter().take(100) {
                        if let Some(name) = result["Name"].as_str() {
                            package_names.push(name.to_string());
                        }
                    }
                }
            }
        }
        
        if package_names.is_empty() {
            // Use only highly relevant, commonly searched packages for fallback
            package_names = vec![
                "git".to_string(), "neofetch".to_string(), "yay".to_string(), "paru".to_string(),
                "visual-studio-code-bin".to_string(), "google-chrome".to_string(), "firefox".to_string(),
                "discord".to_string(), "spotify".to_string(), "slack-desktop".to_string(),
                "docker".to_string(), "nodejs".to_string(), "python".to_string(), "vim".to_string(),
                "htop".to_string(), "bat".to_string(), "ripgrep".to_string(), "fd".to_string(),
                "steam".to_string(), "gimp".to_string(), "vlc".to_string(), "obs-studio".to_string()
            ];
        }
        let mut packages = HashMap::new();
        for package_name in &package_names {
            let url = format!("https://aur.archlinux.org/rpc/?v=5&type=info&arg={}", package_name);
            match self.client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(results) = json["results"].as_array() {
                                    if let Some(result) = results.first() {
                                        let package_name = result["Name"].as_str().unwrap_or("").to_string();
                                        let download_size = self.estimate_aur_package_size(result).await;
                                        let installed_size = self.estimate_aur_installed_size(result, download_size).await;
                                        let package = Package {
                                            name: package_name.clone(),
                                            version: result["Version"].as_str().unwrap_or("1.0.0").to_string(),
                                            description: result["Description"].as_str().unwrap_or("").to_string(),
                                            repository: name.to_string(),
                                            arch: "x86_64".to_string(),
                                            size: download_size,
                                            installed_size,
                                            dependencies: Vec::new(),
                                            conflicts: Vec::new(),
                                            provides: Vec::new(),
                                            replaces: Vec::new(),
                                            maintainer: result["Maintainer"].as_str().unwrap_or("").to_string(),
                                            license: result["License"].as_str().unwrap_or("Unknown").to_string(),
                                                                        url: result["URL"].as_str().unwrap_or("").to_string(),
                            checksum: "".to_string(),
                                            signature: None,
                                            build_date: Utc::now(),
                                            install_date: None,
                                            files: Vec::new(),
                                            scripts: crate::package::PackageScripts {
                                                pre_install: None,
                                                post_install: None,
                                                pre_remove: None,
                                                post_remove: None,
                                                pre_upgrade: None,
                                                post_upgrade: None,
                                            },
                                            health: crate::package::PackageHealth::default(),
                                            compatibility: crate::package::CompatibilityInfo::default(),
                                        };
                                        packages.insert(package.name.clone(), package);
                                    }
                                }
                            }
                            Err(e) => warn!("Failed to parse AUR response for {}: {}", package_name, e),
                        }
                    }
                }
                Err(e) => warn!("Failed to fetch AUR package {}: {}", package_name, e),
            }
        }
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages = packages;
            repo.last_update = Some(Utc::now());
        }
        info!("Updated AUR repository with {} packages ", 
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    async fn estimate_aur_package_size(&self, package_info: &serde_json::Value) -> u64 {
        let package_name = package_info["Name"].as_str().unwrap_or("");
        debug!("Calculating REAL size for package: {}", package_name);
        match self.get_real_aur_package_size(package_name).await {
            Ok(size) if size > 0 => {
                debug!("Got real size for {}: {} bytes ", package_name, size);
                size
            },
            Ok(_) | Err(_) => {
                debug!("Failed to get real size for {}, using fallback estimation ", package_name);
                match package_name {
                    name if name.contains("bin ") => 50 * 1024 * 1024,  
                    name if name.contains("git") => 20 * 1024 * 1024,  
                    _ => 10 * 1024 * 1024,  
                }
            }
        }
    }
    async fn get_real_aur_package_size(&self, package_name: &str) -> PackerResult<u64> {
        debug!("Downloading PKGBUILD for {} to calculate real size ", package_name);
        let pkgbuild_url = format!("https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={}", package_name);
        let response = self.client.get(&pkgbuild_url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::NetworkError(format!("Failed to download PKGBUILD for {}", package_name)));
        }
        let pkgbuild_content = response.text().await?;
        debug!("Downloaded PKGBUILD for {}, parsing sources...", package_name);
        let source_urls = self.parse_pkgbuild_sources(&pkgbuild_content)?;
        debug!("Found {} source URLs for {}", source_urls.len(), package_name);
        let mut total_size = 0u64;
        for url in source_urls {
            match self.get_url_size(&url).await {
                Ok(size) => {
                    debug!("Source {} size: {} bytes ", url, size);
                    total_size += size;
                },
                Err(e) => {
                    debug!("Failed to get size for {}: {}", url, e);
                }
            }
        }
        debug!("Total calculated size for {}: {} bytes ", package_name, total_size);
        Ok(total_size)
    }
    fn parse_pkgbuild_sources(&self, pkgbuild_content: &str) -> PackerResult<Vec<String>> {
        let mut sources = Vec::new();
        let mut variables = std::collections::HashMap::new();
        let mut in_source_array = false;
        let mut current_source = String::new();
        let mut current_array_name = String::new();
        for line in pkgbuild_content.lines() {
            let line = line.trim();
            if let Some(eq_pos) = line.find('=') {
                let var_name = line[..eq_pos].trim();
                let var_value = line[eq_pos + 1..].trim().trim_matches('"').trim_matches('\'');
                match var_name {
                    "pkgver" | "pkgrel" | "epoch" | "pkgname" | "_pkgname" => {
                        variables.insert(var_name.to_string(), var_value.to_string());
                        debug!("Found variable: {} = {}", var_name, var_value);
                    },
                    _ => {}
                }
            }
        }
        for line in pkgbuild_content.lines() {
            let line = line.trim();
            if line.starts_with("source") && line.contains("=(") {
                in_source_array = true;
                if let Some(eq_pos) = line.find('=') {
                    current_array_name = line[..eq_pos].trim().to_string();
                    debug!("Found source array: {}", current_array_name);
                }
                let after_paren = line.split("=(").nth(1).unwrap_or("");
                current_source = after_paren.to_string();
                if current_source.ends_with(')') {
                    current_source = current_source.strip_suffix(')').unwrap_or("").to_string();
                    in_source_array = false;
                    self.extract_urls_from_source_line(&current_source, &mut sources, &variables);
                    current_source.clear();
                }
            } else if in_source_array {
                if line.ends_with(')') {
                    current_source.push(' ');
                    current_source.push_str(line.strip_suffix(')').unwrap_or(""));
                    in_source_array = false;
                    self.extract_urls_from_source_line(&current_source, &mut sources, &variables);
                    current_source.clear();
                } else {
                    current_source.push(' ');
                    current_source.push_str(line);
                }
            }
        }
        debug!("Parsed {} source URLs from PKGBUILD", sources.len());
        for (i, source) in sources.iter().enumerate() {
            debug!("Source {}: {}", i + 1, source);
        }
        Ok(sources)
    }
    fn extract_urls_from_source_line(&self, source_line: &str, sources: &mut Vec<String>, variables: &std::collections::HashMap<String, String>) {
        debug!("Extracting URLs from source line: {}", source_line);
        let parts: Vec<&str> = source_line.split_whitespace().collect();
        for part in parts {
            let clean_part = part.trim_matches('"').trim_matches('\'').trim_matches(',');
            debug!("Processing source part: {}", clean_part);
            let url_part = if clean_part.contains("::") {
                clean_part.split("::").nth(1).unwrap_or(clean_part)
            } else {
                clean_part
            };
                        if url_part.starts_with("http:") ||
                url_part.starts_with("https://") ||
                url_part.starts_with("ftp:") {
                let resolved_url = self.resolve_pkgbuild_variables(url_part, variables);
                debug!("Found URL: {} -> {}", url_part, resolved_url);
                sources.push(resolved_url);
            }
        }
    }
    fn resolve_pkgbuild_variables(&self, url: &str, variables: &std::collections::HashMap<String, String>) -> String {
        let mut resolved_url = url.to_string();
        for (var_name, var_value) in variables {
            let pattern = format!("${{{}}}", var_name);
            resolved_url = resolved_url.replace(&pattern, var_value);
            let pattern2 = format!("${}", var_name);
            resolved_url = resolved_url.replace(&pattern2, var_value);
        }
        debug!("Resolved URL: {} -> {}", url, resolved_url);
        resolved_url
    }
    async fn get_url_size(&self, url: &str) -> PackerResult<u64> {
        debug!("Getting size for URL: {}", url);
        let response = self.client.head(url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::NetworkError(format!("Failed to get size for URL: {}", url)));
        }
        if let Some(content_length) = response.headers().get("content-length ") {
            if let Ok(size_str) = content_length.to_str() {
                if let Ok(size) = size_str.parse::<u64>() {
                    debug!("Got size {} bytes for URL: {}", size, url);
                    return Ok(size);
                }
            }
        }
        debug!("No content-length header for URL: {}", url);
        Ok(0)
    }
    async fn estimate_aur_installed_size(&self, package_info: &serde_json::Value, download_size: u64) -> u64 {
        let package_name = package_info["Name"].as_str().unwrap_or("");
        let base_multiplier = match package_name {
            name if name.contains("chrome") || name.contains("firefox") || name.contains("brave") => 2.0,
            name if name.contains("discord") || name.contains("slack") => 1.5,
            name if name.contains("spotify") => 2.0,
            name if name.contains("zoom") => 2.5,
            name if name.contains("vscode") || name.contains("visual-studio ") => 1.8,
            name if name == "cursor-bin " => 1.6,  
            name if name.contains("cursor") => 1.6,  
            name if name.contains("gimp") => 2.2,
            name if name.contains("vlc") => 3.0,
            name if name.contains("obs") => 3.5,
            name if name.contains("yay") || name.contains("paru") => 4.0,
            name if name.contains("neofetch") || name.contains("htop") => 3.0,
            name if name.contains("bat") || name.contains("fd") || name.contains("ripgrep") => 2.5,
            name if name.contains("exa") || name.contains("tree") => 2.0,
            name if name.ends_with("-bin ") => 1.5,
            _ => 3.0,  
        };
        (download_size as f64 * base_multiplier) as u64
    }
    async fn update_arch_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating Arch repository: {}", name);
        let _repo_config = self.config.get_repository(name)
            .ok_or_else(|| PackerError::RepositoryError(format!("Repository {} not found ", name)))?;
        let packages_api_url = format!("https://archlinux.org/packages/search/json/?repo={}", name);
        let response = self.client.get(&packages_api_url).send().await?;
        
        let mut packages = Vec::new();
        if response.status().is_success() {
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if let Some(results) = json["results"].as_array() {
                    for result in results.iter().take(500) {
                        if let Some(package) = self.parse_arch_api_package(result, name).await? {
                            packages.push(package);
                        }
                    }
                }
            }
        }
        
        if packages.is_empty() {
            warn!("No packages found for repository {}, using fallback data", name);
            packages = self.get_fallback_arch_packages(name);
        }
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages.clear();
            for package in packages {
                repo.packages.insert(package.name.clone(), package);
            }
            repo.last_update = Some(Utc::now());
            repo.metadata.package_count = repo.packages.len();
        }
        info!("Successfully updated Arch repository: {} with {} packages ", name, 
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    async fn parse_arch_api_package(&self, json: &serde_json::Value, repository_name: &str) -> PackerResult<Option<Package>> {
        let name = json["pkgname"].as_str().unwrap_or("").to_string();
        if name.is_empty() {
            return Ok(None);
        }
        
        let version = format!("{}{}",
            json["pkgver"].as_str().unwrap_or("1.0.0"),
            json["pkgrel"].as_str().map(|r| format!("-{}", r)).unwrap_or_default()
        );
        
        let description = json["pkgdesc"].as_str().unwrap_or("").to_string();
        let arch = json["arch"].as_str().unwrap_or("x86_64").to_string();
        let maintainer = json["maintainers"].as_array()
            .and_then(|m| m.first())
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        
        let url = json["url"].as_str().unwrap_or("").to_string();
        let license = json["licenses"].as_array()
            .and_then(|l| l.first())
            .and_then(|l| l.as_str())
            .unwrap_or("Unknown")
            .to_string();
            
        let dependencies = json["depends"].as_array()
            .map(|deps| {
                deps.iter()
                    .filter_map(|d| d.as_str())
                    .map(|d| crate::dependency::Dependency {
                        name: d.to_string(),
                        version_req: None,
                        arch: None,
                        os: None,
                        optional: false,
                        description: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
            
        let build_date = json["build_date"].as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        
        Ok(Some(Package {
            name,
            version,
            description,
            repository: repository_name.to_string(),
            arch,
            size: json["compressed_size"].as_u64().unwrap_or(0),
            installed_size: json["installed_size"].as_u64().unwrap_or(0),
            dependencies,
            conflicts: Vec::new(),
            provides: Vec::new(),
            replaces: Vec::new(),
            maintainer,
            license,
            url,
            checksum: json["sha256sum"].as_str().unwrap_or("").to_string(),
            signature: None,
            build_date,
            install_date: None,
            files: Vec::new(),
            scripts: crate::package::PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
                pre_upgrade: None,
                post_upgrade: None,
            },
            compatibility: crate::package::CompatibilityInfo::default(),
            health: crate::package::PackageHealth::default(),
        }))
    }
    
    fn get_fallback_arch_packages(&self, repo_name: &str) -> Vec<Package> {
        let packages = match repo_name {
            "core" => vec![
                ("bash", "5.2.037-1", "The GNU Bourne Again shell"),
                ("systemd", "255.10-2", "System and service manager"),
                ("glibc", "2.40+r16+gaa533d58ff-2", "GNU C Library"),
                ("linux", "6.11.3.arch1-1", "The Linux kernel and modules"),
                ("gcc", "14.2.1+r134+gab884fffe3fc-1", "The GNU Compiler Collection"),
            ],
            "extra" => vec![
                ("firefox", "131.0.2-1", "Fast, Private & Safe Web Browser"),
                ("vlc", "3.0.21-4", "Multi-platform MPEG, VCD/DVD, and DivX player"),
                ("gimp", "2.10.38-2", "GNU Image Manipulation Program"),
                ("libreoffice-fresh", "24.8.2-1", "LibreOffice branch with new features"),
                ("code", "1.94.2-1", "Visual Studio Code"),
            ],
            "multilib" => vec![
                ("lib32-glibc", "2.40+r16+gaa533d58ff-2", "GNU C Library (32-bit)"),
                ("steam", "1.0.0.81-1", "Valve's digital software delivery system"),
                ("wine", "9.18-1", "Compatibility layer for running Windows programs"),
            ],
            _ => vec![],
        };
        
        packages.into_iter().map(|(name, version, desc)| {
            Package {
                name: name.to_string(),
                version: version.to_string(),
                description: desc.to_string(),
                repository: repo_name.to_string(),
                arch: "x86_64".to_string(),
                size: 1024 * 1024,
                installed_size: 5 * 1024 * 1024,
                dependencies: Vec::new(),
                conflicts: Vec::new(),
                provides: Vec::new(),
                replaces: Vec::new(),
                maintainer: "Arch Linux Team".to_string(),
                license: "GPL".to_string(),
                url: "https://archlinux.org".to_string(),
                checksum: String::new(),
                signature: None,
                build_date: Utc::now(),
                install_date: None,
                files: Vec::new(),
                scripts: crate::package::PackageScripts {
                    pre_install: None,
                    post_install: None,
                    pre_remove: None,
                    post_remove: None,
                    pre_upgrade: None,
                    post_upgrade: None,
                },
                compatibility: crate::package::CompatibilityInfo::default(),
                health: crate::package::PackageHealth::default(),
            }
        }).collect()
    }

    async fn update_npm_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating NPM repository: {}", name);
        let registry_url = "https://registry.npmjs.org";
        let popular_packages = [
            "react", "vue", "angular", "express", "lodash", "moment", "axios", 
            "webpack", "babel", "typescript", "eslint", "prettier", "jest"
        ];
        let mut packages = Vec::new();
        for package_name in &popular_packages {
            match self.fetch_npm_package_info(registry_url, package_name).await {
                Ok(package) => packages.push(package),
                Err(e) => warn!("Failed to fetch NPM package {}: {}", package_name, e),
            }
        }
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages.clear();
            for package in packages {
                repo.packages.insert(package.name.clone(), package);
            }
            repo.last_update = Some(Utc::now());
            repo.metadata.package_count = repo.packages.len();
        }
        info!("Updated NPM repository with {} packages ", 
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    async fn fetch_npm_package_info(&self, registry_url: &str, package_name: &str) -> PackerResult<Package> {
        let url = format!("{}/{}", registry_url, package_name);
        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "Failed to fetch NPM package {}: HTTP {}", 
                package_name, response.status()
            )));
        }
        let package_info: serde_json::Value = response.json().await?;
        let name = package_info["name"].as_str()
            .unwrap_or(package_name)
            .to_string();
        let latest_version = package_info["dist-tags"]["latest"].as_str()
            .unwrap_or("0.0.0")
            .to_string();
        let description = package_info["description"].as_str()
            .unwrap_or("")
            .to_string();
        let maintainer = package_info["maintainers"]
            .as_array()
            .and_then(|m| m.first())
            .and_then(|m| m["name"].as_str())
            .unwrap_or("unknown")
            .to_string();
        let license = package_info["license"].as_str()
            .unwrap_or("unknown")
            .to_string();
        let url = package_info["homepage"].as_str()
            .unwrap_or("")
            .to_string();
        let size = package_info["versions"][&latest_version]["dist"]["unpackedSize"]
            .as_u64()
            .unwrap_or(0);
        let dependencies = package_info["versions"][&latest_version]["dependencies"]
            .as_object()
            .map(|deps| {
                deps.keys().map(|dep_name| Dependency {
                    name: dep_name.clone(),
                    version_req: deps[dep_name].as_str().map(|v| v.to_string()),
                    arch: None,
                    os: None,
                    optional: false,
                    description: None,
                }).collect()
            })
            .unwrap_or_default();
        Ok(Package {
            name,
            version: latest_version,
            description,
            repository: "npm".to_string(),
            arch: "any".to_string(),
            size,
            installed_size: size,
            dependencies,
            conflicts: Vec::new(),
            provides: Vec::new(),
            replaces: Vec::new(),
            maintainer,
            license,
            url,
            checksum: String::new(),
            signature: None,
            build_date: Utc::now(),
            install_date: None,
            files: Vec::new(),
            scripts: crate::package::PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
                pre_upgrade: None,
                post_upgrade: None,
            },
            compatibility: crate::package::CompatibilityInfo::default(),
            health: crate::package::PackageHealth::default(),
        })
    }
    async fn update_pypi_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating PyPI repository: {}", name);
        let pypi_url = "https://pypi.org/pypi";
        let popular_packages = [
            "requests", "numpy", "pandas", "matplotlib", "django", "flask", 
            "tensorflow", "pytorch", "scikit-learn", "boto3", "click", "pillow"
        ];
        let mut packages = Vec::new();
        for package_name in &popular_packages {
            match self.fetch_pypi_package_info(pypi_url, package_name).await {
                Ok(package) => packages.push(package),
                Err(e) => warn!("Failed to fetch PyPI package {}: {}", package_name, e),
            }
        }
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages.clear();
            for package in packages {
                repo.packages.insert(package.name.clone(), package);
            }
            repo.last_update = Some(Utc::now());
            repo.metadata.package_count = repo.packages.len();
        }
        info!("Updated PyPI repository with {} packages ", 
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    async fn fetch_pypi_package_info(&self, pypi_url: &str, package_name: &str) -> PackerResult<Package> {
        let url = format!("{}/{}/json", pypi_url, package_name);
        let response = self.client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "Failed to fetch PyPI package {}: HTTP {}", 
                package_name, response.status()
            )));
        }
        let package_info: serde_json::Value = response.json().await?;
        let info = &package_info["info"];
        let name = info["name"].as_str()
            .unwrap_or(package_name)
            .to_string();
        let version = info["version"].as_str()
            .unwrap_or("0.0.0")
            .to_string();
        let description = info["summary"].as_str()
            .unwrap_or("")
            .to_string();
        let maintainer = info["maintainer"].as_str()
            .or_else(|| info["author"].as_str())
            .unwrap_or("unknown")
            .to_string();
        let license = info["license"].as_str()
            .unwrap_or("unknown")
            .to_string();
        let url = info["home_page"].as_str()
            .unwrap_or("")
            .to_string();
        let mut size = 0u64;
        if let Some(releases) = package_info["releases"][&version].as_array() {
            if let Some(release) = releases.first() {
                size = release["size "].as_u64().unwrap_or(0);
            }
        }
        let dependencies = info["requires_dist"]
            .as_array()
            .map(|deps| {
                deps.iter().filter_map(|dep| {
                    dep.as_str().map(|dep_str| {
                        let dep_name = dep_str.split_whitespace().next().unwrap_or(dep_str);
                        Dependency {
                            name: dep_name.to_string(),
                            version_req: None,
                            arch: None,
                            os: None,
                            optional: false,
                            description: None,
                        }
                    })
                }).collect()
            })
            .unwrap_or_default();
        Ok(Package {
            name,
            version,
            description,
            repository: "pypi".to_string(),
            arch: "any".to_string(),
            size,
            installed_size: size,
            dependencies,
            conflicts: Vec::new(),
            provides: Vec::new(),
            replaces: Vec::new(),
            maintainer,
            license,
            url,
            checksum: String::new(),
            signature: None,
            build_date: Utc::now(),
            install_date: None,
            files: Vec::new(),
            scripts: crate::package::PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
                pre_upgrade: None,
                post_upgrade: None,
            },
            compatibility: crate::package::CompatibilityInfo::default(),
            health: crate::package::PackageHealth::default(),
        })
    }
    async fn update_debian_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating Debian repository: {}", name);
        let repo_config = self.config.get_repository(name)
            .ok_or_else(|| PackerError::RepositoryError(format!("Repository {} not found ", name)))?;
        let packages_url = format!("{}/dists/stable/main/binary-amd64/Packages.gz", repo_config.url);
        let response = self.client.get(&packages_url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "Failed to download Debian packages list: HTTP {}", 
                response.status()
            )));
        }
        let compressed_content = response.bytes().await?;
        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(&compressed_content[..]);
        let mut packages_content = String::new();
        decoder.read_to_string(&mut packages_content)?;
        let packages = self.parse_debian_packages(&packages_content, name)?;
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages.clear();
            for package in packages {
                repo.packages.insert(package.name.clone(), package);
            }
            repo.last_update = Some(Utc::now());
            repo.metadata.package_count = repo.packages.len();
        }
        info!("Updated Debian repository with {} packages ", 
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    fn parse_debian_packages(&self, content: &str, repository_name: &str) -> PackerResult<Vec<Package>> {
        let mut packages = Vec::new();
        let mut current_package = HashMap::new();
        for line in content.lines() {
            if line.is_empty() {
                if !current_package.is_empty() {
                    if let Ok(package) = self.debian_map_to_package(&current_package, repository_name) {
                        packages.push(package);
                    }
                    current_package.clear();
                }
            } else if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim();
                let value = line[colon_pos + 1..].trim();
                current_package.insert(key.to_string(), value.to_string());
            }
        }
        if !current_package.is_empty() {
            if let Ok(package) = self.debian_map_to_package(&current_package, repository_name) {
                packages.push(package);
            }
        }
        Ok(packages)
    }
    fn debian_map_to_package(&self, package_info: &HashMap<String, String>, repository_name: &str) -> PackerResult<Package> {
        let name = package_info.get("Package")
            .ok_or_else(|| PackerError::RepositoryError("Package name not found ".to_string()))?
            .clone();
        let version = package_info.get("Version")
            .ok_or_else(|| PackerError::RepositoryError("Package version not found ".to_string()))?
            .clone();
        let description = package_info.get("Description")
            .cloned()
            .unwrap_or_default();
        let arch = package_info.get("Architecture")
            .cloned()
            .unwrap_or_else(|| "amd64".to_string());
        let size = package_info.get("Size")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let installed_size = package_info.get("Installed-Size")
            .and_then(|s| s.parse::<u64>().ok())
            .map(|s| s * 1024) 
            .unwrap_or(0);
        let dependencies = package_info.get("Depends")
            .map(|deps| {
                deps.split(',')
                    .map(|dep| {
                        let dep_name = dep.trim().split_whitespace().next().unwrap_or(dep.trim());
                        Dependency {
                            name: dep_name.to_string(),
                            version_req: None,
                            arch: None,
                            os: None,
                            optional: false,
                            description: None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let conflicts = package_info.get("Conflicts")
            .map(|conflicts| {
                conflicts.split(',')
                    .map(|c| c.trim().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let provides = package_info.get("Provides")
            .map(|provides| {
                provides.split(',')
                    .map(|p| p.trim().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let replaces = package_info.get("Replaces")
            .map(|replaces| {
                replaces.split(',')
                    .map(|r| r.trim().to_string())
                    .collect()
            })
            .unwrap_or_default();
        let maintainer = package_info.get("Maintainer")
            .cloned()
            .unwrap_or_default();
        let url = package_info.get("Homepage")
            .cloned()
            .unwrap_or_default();
        let checksum = package_info.get("SHA256")
            .cloned()
            .unwrap_or_default();
        Ok(Package {
            name,
            version,
            description,
            repository: repository_name.to_string(),
            arch,
            size,
            installed_size,
            dependencies,
            conflicts,
            provides,
            replaces,
            maintainer,
            license: "unknown".to_string(),
            url,
            checksum,
            signature: None,
            build_date: Utc::now(),
            install_date: None,
            files: Vec::new(),
            scripts: crate::package::PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
                pre_upgrade: None,
                post_upgrade: None,
            },
            compatibility: crate::package::CompatibilityInfo::default(),
            health: crate::package::PackageHealth::default(),
        })
    }
    async fn update_ubuntu_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating Ubuntu repository: {}", name);
        self.update_debian_repository(name).await
    }
    async fn update_fedora_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating Fedora repository: {}", name);
        let repo_config = self.config.get_repository(name)
            .ok_or_else(|| PackerError::RepositoryError(format!("Repository {} not found ", name)))?;
        let repodata_url = format!("{}/repodata/repomd.xml", repo_config.url);
        let response = self.client.get(&repodata_url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "Failed to download Fedora repodata: HTTP {}", 
                response.status()
            )));
        }
        let repomd_content = response.text().await?;
        let primary_db_url = self.extract_primary_db_url(&repomd_content, &repo_config.url)?;
        let primary_response = self.client.get(&primary_db_url).send().await?;
        if !primary_response.status().is_success() {
            return Err(PackerError::RepositoryError(format!(
                "Failed to download Fedora primary database: HTTP {}", 
                primary_response.status()
            )));
        }
        let primary_content = primary_response.bytes().await?;
        let decompressed_content = if primary_db_url.ends_with(".gz") {
            use flate2::read::GzDecoder;
            use std::io::Read;
            let mut decoder = GzDecoder::new(&primary_content[..]);
            let mut content = String::new();
            decoder.read_to_string(&mut content)?;
            content
        } else {
            String::from_utf8_lossy(&primary_content).to_string()
        };
        let packages = self.parse_fedora_primary_xml(&decompressed_content, name)?;
        if let Some(mut repo) = self.repositories.get_mut(name) {
            repo.packages.clear();
            for package in packages {
                repo.packages.insert(package.name.clone(), package);
            }
            repo.last_update = Some(Utc::now());
            repo.metadata.package_count = repo.packages.len();
        }
        info!("Updated Fedora repository with {} packages ", 
              self.repositories.get(name).map(|r| r.packages.len()).unwrap_or(0));
        Ok(())
    }
    fn extract_primary_db_url(&self, repomd_content: &str, base_url: &str) -> PackerResult<String> {
        for line in repomd_content.lines() {
            if line.contains("primary") && line.contains("location href") {
                if let Some(start) = line.find("href=\"") {
                    let start = start + 6;
                    if let Some(end) = line[start..].find("\"") {
                        let relative_path = &line[start..start + end];
                        return Ok(format!("{}/{}", base_url, relative_path));
                    }
                }
            }
        }
        Err(PackerError::RepositoryError("Primary database URL not found in repomd.xml".to_string()))
    }
    fn parse_fedora_primary_xml(&self, content: &str, repository_name: &str) -> PackerResult<Vec<Package>> {
        let mut packages = Vec::new();
        let mut current_package = HashMap::new();
        let mut in_package = false;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("<package ") {
                in_package = true;
                current_package.clear();
            } else if line == "</package>" {
                in_package = false;
                if !current_package.is_empty() {
                    if let Ok(package) = self.fedora_map_to_package(&current_package, repository_name) {
                        packages.push(package);
                    }
                }
            } else if in_package {
                if let Some(name) = self.extract_xml_tag_content(line, "name") {
                    current_package.insert("name".to_string(), name);
                } else if let Some(version) = self.extract_xml_tag_content(line, "version") {
                    current_package.insert("version".to_string(), version);
                } else if let Some(summary) = self.extract_xml_tag_content(line, "summary") {
                    current_package.insert("summary".to_string(), summary);
                } else if let Some(arch) = self.extract_xml_tag_content(line, "arch") {
                    current_package.insert("arch".to_string(), arch);
                } else if line.contains("<size ") {
                    if let Some(size) = self.extract_xml_attribute(line, "package") {
                        current_package.insert("size ".to_string(), size);
                    }
                }
            }
        }
        Ok(packages)
    }
    fn extract_xml_tag_content(&self, line: &str, tag: &str) -> Option<String> {
        let start_tag = format!("<{}>", tag);
        let end_tag = format!("</{}>", tag);
        if let Some(start) = line.find(&start_tag) {
            let content_start = start + start_tag.len();
            if let Some(end) = line[content_start..].find(&end_tag) {
                return Some(line[content_start..content_start + end].to_string());
            }
        }
        None
    }
    fn extract_xml_attribute(&self, line: &str, attr: &str) -> Option<String> {
        let attr_pattern = format!("{}=\"", attr);
        if let Some(start) = line.find(&attr_pattern) {
            let value_start = start + attr_pattern.len();
            if let Some(end) = line[value_start..].find("\"") {
                return Some(line[value_start..value_start + end].to_string());
            }
        }
        None
    }
    fn fedora_map_to_package(&self, package_info: &HashMap<String, String>, repository_name: &str) -> PackerResult<Package> {
        let name = package_info.get("name")
            .ok_or_else(|| PackerError::RepositoryError("Package name not found ".to_string()))?
            .clone();
        let version = package_info.get("version")
            .ok_or_else(|| PackerError::RepositoryError("Package version not found ".to_string()))?
            .clone();
        let description = package_info.get("summary")
            .cloned()
            .unwrap_or_default();
        let arch = package_info.get("arch")
            .cloned()
            .unwrap_or_else(|| "x86_64".to_string());
        let size = package_info.get("size ")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(Package {
            name,
            version,
            description,
            repository: repository_name.to_string(),
            arch,
            size,
            installed_size: size,
            dependencies: Vec::new(), 
            conflicts: Vec::new(),
            provides: Vec::new(),
            replaces: Vec::new(),
            maintainer: "unknown".to_string(),
            license: "unknown".to_string(),
            url: String::new(),
            checksum: String::new(),
            signature: None,
            build_date: Utc::now(),
            install_date: None,
            files: Vec::new(),
            scripts: crate::package::PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
                pre_upgrade: None,
                post_upgrade: None,
            },
            compatibility: crate::package::CompatibilityInfo::default(),
            health: crate::package::PackageHealth::default(),
        })
    }
    async fn update_custom_repository(&self, name: &str) -> PackerResult<()> {
        info!("Updating custom repository: {}", name);
        self.update_packer_repository(name).await
    }
    async fn github_repo_to_package(&self, repo_info: serde_json::Value, repository_name: &str) -> PackerResult<Option<Package>> {
        let name = repo_info["name"].as_str().unwrap_or("").to_string();
        let full_name = repo_info["full_name"].as_str().unwrap_or("").to_string();
        let description = repo_info["description"].as_str().unwrap_or("").to_string();
        let homepage = repo_info["html_url"].as_str().unwrap_or("").to_string();
        let _stars = repo_info["stargazers_count"].as_u64().unwrap_or(0);
        if name.is_empty() || full_name.is_empty() {
            return Ok(None);
        }
        let parts: Vec<&str> = full_name.split('/').collect();
        if parts.len() != 2 {
            return Ok(None);
        }
        let (owner, repo) = (parts[0], parts[1]);
        let github_client = self.github_client.as_ref().unwrap();
        let releases = github_client.get_releases(owner, repo).await.unwrap_or_default();
        let latest_release = releases.into_iter()
            .filter(|r| !r.draft && !r.prerelease)
            .next();
        let (version, _download_url, size) = if let Some(release) = latest_release {
            let asset = release.assets.iter()
                .find(|a| a.name.contains("linux") || a.name.contains("x86_64"))
                .or_else(|| release.assets.first());
            if let Some(asset) = asset {
                (release.tag_name, asset.browser_download_url.clone(), asset.size)
            } else {
                ("0.1.0".to_string(), format!("https://placeholder.example.com"), 0)
            }
        } else {
            ("0.1.0".to_string(), format!("https://placeholder.example.com"), 0)
        };
        let package = Package {
            name,
            version,
            description,
            repository: repository_name.to_string(),
            arch: "x86_64".to_string(),
            size,
            installed_size: size * 2,
            dependencies: Vec::new(),
            conflicts: Vec::new(),
            provides: Vec::new(),
            replaces: Vec::new(),
            maintainer: owner.to_string(),
            license: "Unknown".to_string(),
            url: homepage,
            checksum: "".to_string(),
            signature: None,
            build_date: Utc::now(),
            install_date: None,
            files: Vec::new(),
            scripts: crate::package::PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
                pre_upgrade: None,
                post_upgrade: None,
            },
            compatibility: crate::package::CompatibilityInfo::default(),
            health: crate::package::PackageHealth::default(),
        };
        Ok(Some(package))
    }
    async fn verify_repository_signature(&self, _index: &RepositoryIndex, _signature: &str, repo_name: &str) -> PackerResult<()> {
        let repo_config = self.config.get_repository(repo_name)
            .ok_or_else(|| PackerError::RepositoryError(format!("Repository {} not found ", repo_name)))?;
        if !self.config.should_verify_signature(repo_config) {
            return Ok(());
        }
        warn!("Signature verification not yet implemented for repository: {}", repo_name);
        Ok(())
    }
    async fn convert_metadata_to_package(
        &self,
        metadata: PackageMetadata,
        repository_name: &str,
    ) -> PackerResult<Package> {
        let dependencies = metadata
            .dependencies
            .into_iter()
            .filter(|dep_str| !dep_str.trim().is_empty())
            .map(|dep_str| Dependency::parse(&dep_str))
            .collect::<PackerResult<Vec<_>>>()?;
        Ok(Package {
            name: metadata.name,
            version: metadata.version,
            description: metadata.description,
            repository: repository_name.to_string(),
            arch: metadata.arch,
            size: metadata.size,
            installed_size: metadata.installed_size,
            dependencies,
            conflicts: metadata.conflicts,
            provides: metadata.provides,
            replaces: metadata.replaces,
            maintainer: metadata.maintainer,
            license: metadata.license,
            url: metadata.url,
            checksum: metadata.checksum,
            signature: metadata.signature,
            build_date: metadata.build_date,
            install_date: None,
            files: Vec::new(),
            scripts: crate::package::PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
                pre_upgrade: None,
                post_upgrade: None,
            },
            compatibility: crate::package::CompatibilityInfo::default(),
            health: crate::package::PackageHealth::default(),
        })
    }
    pub async fn get_package(&self, name: &str) -> PackerResult<Option<Package>> {
        let mut repositories: Vec<_> = self.repositories.iter()
            .map(|entry| entry.value().clone())
            .collect();
        repositories.sort_by_key(|repo| repo.priority);
        for repository in repositories {
            if let Some(package) = repository.packages.get(name) {
                return Ok(Some(package.clone()));
            }
        }
        if let Some(aur_results) = self.search_aur_directly(name, true).await? {
            if let Some(package) = aur_results.into_iter().find(|p| p.name == name) {
                return Ok(Some(package));
            }
        }
        if self.config.auto_discover {
            if let Some(package) = self.discover_package(name).await? {
                return Ok(Some(package));
            }
        }
        Ok(None)
    }
    async fn discover_package(&self, name: &str) -> PackerResult<Option<Package>> {
        info!("Auto-discovering package: {}", name);
        if let Some(github_client) = &self.github_client {
            let search_results = github_client.search_repositories(&format!("\"{}\" in:name", name), 5).await?;
            for repo_info in search_results {
                if let Some(package) = self.github_repo_to_package(repo_info, "auto-discovered").await? {
                    if package.name.to_lowercase().contains(&name.to_lowercase()) {
                        info!("Auto-discovered package: {} from GitHub", package.name);
                        return Ok(Some(package));
                    }
                }
            }
        }
        Ok(None)
    }
    pub async fn search_packages(&self, query: &str, exact: bool) -> PackerResult<Vec<Package>> {
        let mut results = Vec::new();
        let mut seen_packages = HashSet::new();
        let query_lower = query.to_lowercase();
        debug!("Searching for '{}' in {} repositories", query, self.repositories.len());
        
        debug!("Trying AUR search first");
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.search_aur_directly(query, exact)
        ).await {
            Ok(Ok(Some(aur_results))) => {
                debug!("AUR search returned {} results", aur_results.len());
                for package in aur_results {
                    if !seen_packages.contains(&package.name) {
                        seen_packages.insert(package.name.clone());
                        results.push(package);
                    }
                }
            }
            Ok(Ok(None)) => {
                debug!("No AUR results found");
            }
            Ok(Err(e)) => {
                warn!("AUR search failed: {}", e);
            }
            Err(_) => {
                warn!("AUR search timed out");
            }
        }
        
        for repository in self.repositories.iter() {
            debug!("Repository '{}' has {} packages ", repository.name, repository.packages.len());
            for package in repository.packages.values() {
                debug!("Checking package '{}'", package.name);
                let matches = if exact {
                    package.name == query
                } else {
                    package.name.to_lowercase().contains(&query_lower)
                        || package.description.to_lowercase().contains(&query_lower)
                };
                if matches && !seen_packages.contains(&package.name) {
                    debug!("Package '{}' matches query '{}'", package.name, query);
                    seen_packages.insert(package.name.clone());
                    results.push(package.clone());
                }
            }
        }
        
        if results.is_empty() {
            debug!("No results in cached data, trying system pacman search");
            if let Ok(pacman_results) = self.search_with_pacman(query).await {
                debug!("Pacman search returned {} results", pacman_results.len());
                for package in pacman_results {
                    if !seen_packages.contains(&package.name) {
                        seen_packages.insert(package.name.clone());
                        results.push(package);
                    }
                }
            }
        }
        
        results.sort_by(|a, b| {
            let relevance_a = calculate_relevance_score(&a.name, &a.description, query);
            let relevance_b = calculate_relevance_score(&b.name, &b.description, query);
            let priority_a = self.repositories.get(&a.repository)
                .map(|repo| repo.priority)
                .unwrap_or(1000); 
            let priority_b = self.repositories.get(&b.repository)
                .map(|repo| repo.priority)
                .unwrap_or(1000); 
            relevance_b.partial_cmp(&relevance_a).unwrap_or(std::cmp::Ordering::Equal)
                .then(priority_a.cmp(&priority_b))
                .then(a.name.cmp(&b.name))
        });
        
        debug!("Search completed. Found {} packages ", results.len());
        Ok(results)
    }
    pub async fn search_packages_in_repo(&self, query: &str, repo_name: &str) -> PackerResult<Vec<Package>> {
        let mut results = Vec::new();
        let query_lower = query.to_lowercase();
        debug!("Searching for '{}' in repository '{}'", query, repo_name);
        if let Some(repository) = self.repositories.get(repo_name) {
            for package in repository.packages.values() {
                let matches = package.name.to_lowercase().contains(&query_lower)
                    || package.description.to_lowercase().contains(&query_lower);
                if matches {
                    results.push(package.clone());
                }
            }
        } else if repo_name == "aur" {
            if let Some(aur_results) = self.search_aur_directly(query, false).await? {
                results.extend(aur_results);
            }
        }
        results.sort_by(|a, b| {
            let relevance_a = calculate_relevance_score(&a.name, &a.description, query);
            let relevance_b = calculate_relevance_score(&b.name, &b.description, query);
            relevance_b.partial_cmp(&relevance_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(results)
    }
    pub async fn search_aur_directly(&self, query: &str, exact: bool) -> PackerResult<Option<Vec<Package>>> {
        info!("Searching AUR directly for: {}", query);
        let _search_type = if exact { "info" } else { "search" };
        let url = if exact {
            format!("https://aur.archlinux.org/rpc/?v=5&type=info&arg={}", query)
        } else {
            format!("https://aur.archlinux.org/rpc/?v=5&type=search&arg={}", query)
        };
        debug!("AUR search URL: {}", url);
        let timeout_duration = std::time::Duration::from_secs(10);
        match tokio::time::timeout(timeout_duration, self.client.get(&url).send()).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    match response.json::<serde_json::Value>().await {
                        Ok(json) => {
                            debug!("AUR API response: {}", json);
                            if let Some(results) = json["results"].as_array() {
                                let mut packages = Vec::new();
                                for result in results {
                                    let package_name = result["Name"].as_str().unwrap_or("").to_string();
                                    if package_name.is_empty() {
                                        continue;
                                    }
                                    let matches = if exact {
                                        package_name == query
                                    } else {
                                        package_name.to_lowercase().contains(&query.to_lowercase()) ||
                                        result["Description"].as_str().unwrap_or("").to_lowercase().contains(&query.to_lowercase())
                                    };
                                    if !matches {
                                        continue;
                                    }
                                    let download_size = self.estimate_aur_package_size(result).await;
                                    let installed_size = self.estimate_aur_installed_size(result, download_size).await;
                                    let package = Package {
                                        name: package_name,
                                        version: result["Version"].as_str().unwrap_or("unknown").to_string(),
                                        description: result["Description"].as_str().unwrap_or("").to_string(),
                                        repository: "aur".to_string(),
                                        arch: "any".to_string(),
                                        size: download_size,
                                        installed_size,
                                        dependencies: Vec::new(),
                                        conflicts: Vec::new(),
                                        provides: Vec::new(),
                                        replaces: Vec::new(),
                                        maintainer: result["Maintainer"].as_str().unwrap_or("").to_string(),
                                        license: "unknown".to_string(),
                                        url: result["URL"].as_str().unwrap_or("").to_string(),
                                        checksum: String::new(),
                                        signature: None,
                                        build_date: chrono::Utc::now(),
                                        install_date: None,
                                        files: Vec::new(),
                                        scripts: crate::package::PackageScripts {
                                            pre_install: None,
                                            post_install: None,
                                            pre_remove: None,
                                            post_remove: None,
                                            pre_upgrade: None,
                                            post_upgrade: None,
                                        },
                                        compatibility: crate::package::CompatibilityInfo::default(),
                                        health: crate::package::PackageHealth::default(),
                                    };
                                    packages.push(package);
                                }
                                info!("Found {} packages in AUR for query '{}'", packages.len(), query);
                                return Ok(Some(packages));
                            } else {
                                debug!("No results array in AUR response");
                                return Ok(Some(Vec::new()));
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse AUR response for '{}': {}", query, e);
                            return Ok(Some(Vec::new()));
                        }
                    }
                } else {
                    warn!("AUR API request failed with status: {}", response.status());
                    return Ok(Some(Vec::new()));
                }
            }
            Ok(Err(e)) => {
                warn!("Failed to send AUR request for '{}': {}", query, e);
                return Ok(Some(Vec::new()));
            }
            Err(_) => {
                warn!("AUR search timed out for query '{}'", query);
                return Ok(Some(Vec::new()));
            }
        }
    }
    
    async fn search_with_pacman(&self, query: &str) -> PackerResult<Vec<Package>> {
        info!("Searching with system pacman for: {}", query);
        use tokio::process::Command;
        
        let output = Command::new("pacman")
            .arg("-Ss")
            .arg(query)
            .output()
            .await?;
            
        if !output.status.success() {
            warn!("Pacman search failed");
            return Ok(Vec::new());
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut packages = Vec::new();
        let mut lines = stdout.lines();
        
        while let Some(line) = lines.next() {
            if line.trim().is_empty() {
                continue;
            }
            
            if let Some(space_pos) = line.find(' ') {
                let name_part = &line[..space_pos];
                let rest = &line[space_pos..].trim();
                
                if let Some(slash_pos) = name_part.find('/') {
                    let repo_name = &name_part[..slash_pos];
                    let package_name = &name_part[slash_pos + 1..];
                    
                    let version = if let Some(bracket_pos) = rest.find('[') {
                        rest[..bracket_pos].trim()
                    } else {
                        rest.trim()
                    }.to_string();
                    
                    let description = lines.next()
                        .map(|desc_line| desc_line.trim().to_string())
                        .unwrap_or_default();
                    
                    let package = Package {
                        name: package_name.to_string(),
                        version,
                        description,
                        repository: repo_name.to_string(),
                        arch: "x86_64".to_string(),
                        size: 0,
                        installed_size: 0,
                        dependencies: Vec::new(),
                        conflicts: Vec::new(),
                        provides: Vec::new(),
                        replaces: Vec::new(),
                        maintainer: "Arch Linux Team".to_string(),
                        license: "Unknown".to_string(),
                        url: String::new(),
                        checksum: String::new(),
                        signature: None,
                        build_date: chrono::Utc::now(),
                        install_date: None,
                        files: Vec::new(),
                        scripts: crate::package::PackageScripts {
                            pre_install: None,
                            post_install: None,
                            pre_remove: None,
                            post_remove: None,
                            pre_upgrade: None,
                            post_upgrade: None,
                        },
                        compatibility: crate::package::CompatibilityInfo::default(),
                        health: crate::package::PackageHealth::default(),
                    };
                    packages.push(package);
                }
            }
        }
        
        info!("Found {} packages via pacman search", packages.len());
        Ok(packages)
    }
    pub async fn get_newer_version(&self, package: &Package) -> PackerResult<Option<Package>> {
        if let Some(repo_package) = self.get_package(&package.name).await? {
            use semver::Version;
            let current_version = Version::parse(&package.version)
                .map_err(|e| PackerError::InvalidVersion(format!("Invalid current version {}: {}", package.version, e)))?;
            let repo_version = Version::parse(&repo_package.version)
                .map_err(|e| PackerError::InvalidVersion(format!("Invalid repo version {}: {}", repo_package.version, e)))?;
            if repo_version > current_version {
                Ok(Some(repo_package))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    pub async fn download_package(&self, package: &Package, progress_bar: &ProgressBar) -> PackerResult<PathBuf> {
        let cache_file = self.cache_dir.join(format!("{}-{}.pkg", package.name, package.version));
        if cache_file.exists() && self.verify_cached_package(&cache_file, package).await? {
            debug!("Package {} already cached and verified", package.name);
            return Ok(cache_file);
        }
        let repository = self
            .repositories
            .get(&package.repository)
            .ok_or_else(|| PackerError::RepositoryError(format!("Repository {} not found ", package.repository)))?;
        let download_url = self.resolve_download_url(package, &repository).await?;
        info!("Downloading package {} from {}", package.name, download_url);
        progress_bar.set_message(format!("Downloading {}", package.name));
        let mut attempts = 0;
        let max_attempts = self.config.retry_attempts;
        loop {
            attempts += 1;
            match self.download_file_with_resume(&download_url, &cache_file, progress_bar).await {
                Ok(_) => {
                    if self.verify_package_integrity(&cache_file, package).await? {
                        info!("Successfully downloaded and verified package {}", package.name);
                        return Ok(cache_file);
                    } else {
                        warn!("Package {} failed integrity check, retrying...", package.name);
                        let _ = fs::remove_file(&cache_file).await;
                    }
                }
                Err(e) => {
                    warn!("Download attempt {} failed for {}: {}", attempts, package.name, e);
                }
            }
            if attempts >= max_attempts {
                return Err(PackerError::DownloadFailed(format!(
                    "Failed to download {} after {} attempts",
                    package.name, max_attempts
                )));
            }
            sleep(Duration::from_secs(self.config.retry_delay_seconds)).await;
        }
    }
    async fn resolve_download_url(&self, package: &Package, repository: &Repository) -> PackerResult<String> {
        match repository.repo_type {
            RepositoryType::AUR => {
                Ok(format!("https://aur.archlinux.org/cgit/aur.git/snapshot/{}.tar.gz", package.name))
            }
            RepositoryType::GitHub => {
                if package.url.contains("github.com") {
                    Ok(format!("{}/archive/{}.tar.gz", package.url, package.version))
                } else {
                    Ok(format!("{}/packages/{}-{}.pkg", repository.url, package.name, package.version))
                }
            }
            _ => Ok(format!("{}/packages/{}-{}.pkg", repository.url, package.name, package.version))
        }
    }
    async fn download_file_with_resume(&self, url: &str, path: &PathBuf, progress_bar: &ProgressBar) -> PackerResult<()> {
        let mut file_size = 0u64;
        if path.exists() {
            file_size = fs::metadata(path).await?.len();
        }
        let mut request = self.client.get(url);
        if file_size > 0 {
            request = request.header("Range", format!("bytes={}-", file_size));
        }
        let response = request.send().await?;
        if !response.status().is_success() && response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            return Err(PackerError::DownloadFailed(format!(
                "HTTP error: {}",
                response.status()
            )));
        }
        let content_length = response.content_length().unwrap_or(0);
        let total_size = content_length + file_size;
        if total_size > 0 {
            progress_bar.set_length(total_size);
            progress_bar.set_position(file_size);
        } else {
            progress_bar.set_length(0);
            progress_bar.set_position(0);
        }
        let mut file = if file_size > 0 {
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?
        } else {
            tokio::fs::File::create(path).await?
        };
        let mut stream = response.bytes_stream();
        use tokio::io::AsyncWriteExt;
        let mut downloaded_bytes = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            downloaded_bytes += chunk.len() as u64;
            if total_size > 0 {
                progress_bar.inc(chunk.len() as u64);
            } else {
                progress_bar.set_position(downloaded_bytes);
                progress_bar.set_length(downloaded_bytes.max(1)); 
            }
        }
        file.flush().await?;
        if total_size == 0 {
            progress_bar.set_length(downloaded_bytes);
            progress_bar.set_position(downloaded_bytes);
        }
        Ok(())
    }
    async fn verify_cached_package(&self, path: &PathBuf, package: &Package) -> PackerResult<bool> {
        if !package.checksum.is_empty() {
            return self.verify_package_integrity(path, package).await;
        }
        Ok(true)
    }
    async fn verify_package_integrity(&self, path: &PathBuf, package: &Package) -> PackerResult<bool> {
        if package.checksum.is_empty() {
            return Ok(true);
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
        Ok(calculated == package.checksum)
    }
    pub fn get_repository_info(&self) -> Vec<RepositoryInfo> {
        self.repositories
            .iter()
            .map(|entry| {
                let repo = entry.value();
                RepositoryInfo {
                    name: repo.name.clone(),
                    url: repo.url.clone(),
                    enabled: repo.enabled,
                    priority: repo.priority,
                    package_count: repo.packages.len(),
                    last_update: repo.last_update,
                    repo_type: repo.repo_type.clone(),
                    trust_level: repo.trust_level.clone(),
                }
            })
            .collect()
    }
    pub fn get_package_count(&self) -> usize {
        self.repositories
            .iter()
            .map(|entry| entry.value().packages.len())
            .sum()
    }
    pub fn clear_cache(&self) -> PackerResult<()> {
        if self.cache_dir.exists() {
            std::fs::remove_dir_all(&self.cache_dir)?;
            std::fs::create_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }
    async fn save_repository_data(&self) -> PackerResult<()> {
        let data_file = self.cache_dir.join("repository_data.json");
        let mut data = HashMap::new();
        for entry in self.repositories.iter() {
            data.insert(entry.key().clone(), entry.value().clone());
        }
        let content = serde_json::to_string_pretty(&data)?;
        tokio::fs::write(&data_file, content).await?;
        debug!("Saved repository data to {:?}", data_file);
        Ok(())
    }
    async fn load_repository_data(&mut self) -> PackerResult<()> {
        let data_file = self.cache_dir.join("repository_data.json");
        if !data_file.exists() {
            debug!("No saved repository data found ");
            return Ok(());
        }
        let content = tokio::fs::read_to_string(&data_file).await?;
        let data: HashMap<String, Repository> = serde_json::from_str(&content)?;
        for (name, repo) in data {
            self.repositories.insert(name, repo);
        }
        debug!("Loaded repository data from {:?}", data_file);
        Ok(())
    }
    pub async fn add_repository(&mut self, config: RepositoryConfig) -> PackerResult<()> {
        info!("Adding repository: {}", config.name);
        let repository = Repository {
            name: config.name.clone(),
            url: config.url.clone(),
            enabled: config.enabled,
            priority: config.priority,
            last_update: None,
            packages: HashMap::new(),
            repo_type: config.repo_type.clone(),
            trust_level: config.trust_level.clone(),
            metadata: RepositoryMetadata {
                version: "1.0".to_string(),
                description: None,
                maintainer: None,
                homepage: None,
                package_count: 0,
                total_size: 0,
                categories: Vec::new(),
                languages: Vec::new(),
            },
            health: RepositoryHealth::default(),
            mirror_status: MirrorStatus::default(),
        };
        self.repositories.insert(config.name.clone(), repository);
        if config.enabled {
            self.update_repository_concurrent(&config.name).await?;
        }
        Ok(())
    }
    pub async fn remove_repository(&mut self, name: &str) -> PackerResult<()> {
        info!("Removing repository: {}", name);
        self.repositories.remove(name);
        Ok(())
    }
    pub async fn update_repository(&mut self, repository_name: &str, _force: bool) -> PackerResult<()> {
        if let Some(repo) = self.repositories.get(repository_name) {
            match repo.repo_type {
                RepositoryType::Packer => self.update_packer_repository(repository_name).await,
                RepositoryType::AUR => self.update_aur_repository(repository_name).await,
                RepositoryType::GitHub => self.update_github_repository(repository_name).await,
                RepositoryType::Arch => self.update_arch_repository(repository_name).await,
                _ => Ok(()),
            }
        } else {
            Err(PackerError::RepositoryError(format!("Repository {} not found ", repository_name)))
        }
    }
    pub async fn check_repository_health(&self, repo_name: &str) -> PackerResult<RepositoryHealth> {
        let mut health = RepositoryHealth::default();
        if let Some(repo) = self.repositories.get(repo_name) {
            let start_time = std::time::Instant::now();
            let connectivity_result = self.check_repository_connectivity(&repo.url).await;
            let response_time = start_time.elapsed().as_millis() as u64;
            health.response_time_ms = response_time;
            health.last_health_check = Utc::now();
            match connectivity_result {
                Ok(_) => {
                    health.status = RepositoryStatus::Healthy;
                    health.success_rate = 1.0;
                    health.uptime_score = 1.0;
                }
                Err(_) => {
                    health.status = RepositoryStatus::Unavailable;
                    health.success_rate = 0.0;
                    health.uptime_score = 0.0;
                    health.issues.push(RepositoryIssue {
                        severity: IssueSeverity::Critical,
                        category: IssueCategory::Connectivity,
                        description: "Repository is unreachable".to_string(),
                        detected_at: Utc::now(),
                        resolution: Some("Check network connection and repository URL".to_string()),
                    });
                }
            }
            if response_time > 5000 {
                health.status = RepositoryStatus::Degraded;
                health.issues.push(RepositoryIssue {
                    severity: IssueSeverity::Medium,
                    category: IssueCategory::Performance,
                    description: "Repository response time is slow".to_string(),
                    detected_at: Utc::now(),
                    resolution: Some("Consider switching to a faster mirror".to_string()),
                });
            }
            health.security_score = match (&repo.url.starts_with("https://"), &repo.trust_level) {
                (true, TrustLevel::Trusted) => 1.0,
                (true, TrustLevel::Verified) => 0.8,
                (true, TrustLevel::Community) => 0.6,
                (false, TrustLevel::Trusted) => 0.5,
                (false, _) => 0.3,
                (true, TrustLevel::Untrusted) => 0.2,
            };
        }
        Ok(health)
    }
    async fn check_repository_connectivity(&self, url: &str) -> PackerResult<()> {
        let response = self.client.head(url).send().await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(PackerError::RepositorySyncFailed(format!("HTTP {}", response.status())))
        }
    }

    pub async fn find_alternatives(&self, package_name: &str) -> PackerResult<Vec<String>> {
        let mut alternatives = Vec::new();
        
        for repository in self.repositories.iter() {
            if let Ok(packages) = self.search_packages_in_repo(package_name, &repository.key()).await {
                for package in packages {
                    if package.provides.iter().any(|p| p.contains(package_name)) ||
                       package.name.contains(package_name) {
                        alternatives.push(package.name);
                    }
                }
            }
        }
        
        Ok(alternatives)
    }

    pub async fn find_package(&self, name: &str, exact: bool) -> PackerResult<Option<Package>> {
        for repository in self.repositories.iter() {
            if let Ok(packages) = self.search_packages_in_repo(name, &repository.key()).await {
                if let Some(package) = packages.into_iter().find(|p| if exact { p.name == name } else { p.name.contains(name) }) {
                    return Ok(Some(package));
                }
            }
        }
        Ok(None)
    }

    pub async fn get_package_versions(&self, _package_name: &str) -> PackerResult<Vec<String>> {
        let mut versions = Vec::new();
        
        // for now, return a placeholder version
        versions.push("1.0.0".to_string());
        
        Ok(versions)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryInfo {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub priority: i32,
    pub package_count: usize,
    pub last_update: Option<DateTime<Utc>>,
    pub repo_type: RepositoryType,
    pub trust_level: TrustLevel,
}
impl Default for RepositoryHealth {
    fn default() -> Self {
        Self {
            status: RepositoryStatus::Unknown,
            last_health_check: Utc::now(),
            response_time_ms: 0,
            success_rate: 0.0,
            issues: Vec::new(),
            uptime_score: 0.0,
            security_score: 0.0,
        }
    }
}
impl Default for MirrorStatus {
    fn default() -> Self {
        Self {
            available_mirrors: Vec::new(),
            current_mirror: None,
            failover_enabled: false,
            last_failover: None,
            auto_select_best: true,
        }
    }
}
fn calculate_relevance_score(name: &str, description: &str, query: &str) -> f32 {
    let mut score: f32 = 0.0;
    let name_lower = name.to_lowercase();
    let description_lower = description.to_lowercase();
    let query_lower = query.to_lowercase();
    
    if name_lower == query_lower {
        score += 100.0;
    } 
    else if name_lower.starts_with(&query_lower) {
        score += 80.0;
    } 
    else if name_lower.contains(&query_lower) {
        score += 60.0;
    }
    
    if name_lower != query_lower {
        let query_parts: Vec<&str> = query_lower.split(&['-', '_', ' '][..]).collect();
        let name_parts: Vec<&str> = name_lower.split(&['-', '_', ' '][..]).collect();
        for query_part in &query_parts {
            if query_part.len() > 2 { 
                for name_part in &name_parts {
                    if name_part == query_part {
                        score += 40.0;
                    } else if name_part.starts_with(query_part) {
                        score += 25.0;
                    } else if name_part.contains(query_part) {
                        score += 15.0;
                    }
                }
            }
        }
    }
    
    if description_lower.contains(&query_lower) {
        let query_len = query_lower.len();
        let desc_len = description_lower.len();
        if query_len >= 3 && (query_len as f32 / desc_len as f32) > 0.05 {
            score += 20.0;
        } else if query_len >= 3 {
            score += 10.0;
        }
    }
    
    match name_lower.as_str() {
        "git" => score += 15.0,
        "neofetch" => score += 15.0,
        name if name.contains("visual-studio-code") || name.contains("vscode") => score += 10.0,
        name if name.contains("chrome") || name.contains("firefox") => score += 8.0,
        name if name.contains("discord") || name.contains("spotify") => score += 6.0,
        _ => {}
    }
    
    if name.len() > 30 {
        score -= 5.0;
    }
    
    if description.is_empty() || description.len() < 10 {
        score -= 2.0;
    }
    
    score.max(0.0) 
}
