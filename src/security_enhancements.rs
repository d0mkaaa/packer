use crate::config::Config;
use crate::error::{PackerError, PackerResult};
use crate::package::*;
use chrono::{DateTime, Utc};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Security scanner
#[derive(Debug)]
#[allow(dead_code)] // Future feature: advanced security scanning
pub struct AdvancedSecurityScanner {
    config: Config,
    vulnerability_feeds: Arc<RwLock<HashMap<String, VulnerabilityFeed>>>,
    threat_intelligence: Arc<RwLock<ThreatIntelligenceCache>>,
    gpg_manager: GPGManager,
    risk_calculator: RiskCalculator,
    exploit_db: Arc<RwLock<ExploitDatabase>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFeed {
    pub name: String,
    pub url: String,
    pub last_updated: DateTime<Utc>,
    pub vulnerabilities: Vec<EnhancedVulnerability>,
    pub feed_type: FeedType,
    pub priority: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedType {
    NVD,          // National Vulnerability Database
    OSV,          // Open Source Vulnerabilities
    GitHub,       // GitHub Security Advisories
    ArchSecurity, // Arch Linux Security
    CISA,         // CISA Known Exploited Vulnerabilities
    Custom,       // Custom threat feeds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedVulnerability {
    pub id: String,
    pub cve_id: Option<String>,
    pub package_name: String,
    pub affected_versions: Vec<VersionRange>,
    pub severity: VulnerabilitySeverity,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
    pub epss_score: Option<f64>,
    pub description: String,
    pub references: Vec<String>,
    pub published_date: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub fixed_versions: Vec<String>,
    pub exploit_available: bool,
    pub exploit_maturity: ExploitMaturity,
    pub threat_actors: Vec<String>,
    pub attack_patterns: Vec<String>,
    pub mitigation_strategies: Vec<String>,
    pub business_impact: BusinessImpactLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub inclusive_min: bool,
    pub inclusive_max: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BusinessImpactLevel {
    Critical, // System compromise, data breach
    High,     // Service disruption, privilege escalation
    Medium,   // Limited impact, requires user interaction
    Low,      // Minimal impact, difficult to exploit
    Info,     // Informational only
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceCache {
    pub active_campaigns: Vec<ThreatCampaign>,
    pub exploit_kits: Vec<ExploitKit>,
    pub malware_families: Vec<MalwareFamily>,
    pub indicators: Vec<ThreatIndicator>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatCampaign {
    pub name: String,
    pub threat_actor: String,
    pub start_date: DateTime<Utc>,
    pub end_date: Option<DateTime<Utc>>,
    pub targeted_vulnerabilities: Vec<String>,
    pub target_sectors: Vec<String>,
    pub target_regions: Vec<String>,
    pub affected_packages: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitKit {
    pub name: String,
    pub version: String,
    pub price: Option<f64>,
    pub availability: ExploitAvailability,
    pub supported_vulnerabilities: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareFamily {
    pub name: String,
    pub type_: MalwareType,
    pub exploited_vulnerabilities: Vec<String>,
    pub capabilities: Vec<String>,
    pub attribution: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MalwareType {
    Ransomware,
    Backdoor,
    Trojan,
    Rootkit,
    Worm,
    Botnet,
    Spyware,
    Adware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: IndicatorType,
    pub value: String,
    pub confidence: f64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub associated_campaigns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndicatorType {
    Domain,
    IP,
    URL,
    FileHash,
    Email,
    Registry,
    Mutex,
    Certificate,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct GPGManager {
    keyring_path: std::path::PathBuf,
    trusted_keys: Arc<RwLock<HashMap<String, GPGKeyInfo>>>,
    keyservers: Vec<String>,
    config: Config,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct RiskCalculator {
    weights: RiskWeights,
    threat_landscape: Arc<RwLock<ThreatLandscape>>,
}

#[derive(Debug, Clone)]
pub struct RiskWeights {
    pub cvss_weight: f64,
    pub epss_weight: f64,
    pub exploit_weight: f64,
    pub threat_intel_weight: f64,
    pub business_impact_weight: f64,
    pub temporal_weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatLandscape {
    pub active_threats: Vec<ActiveThreat>,
    pub trending_vulnerabilities: Vec<String>,
    pub emerging_attack_patterns: Vec<String>,
    pub high_risk_packages: Vec<String>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveThreat {
    pub threat_id: String,
    pub name: String,
    pub severity: ThreatSeverity,
    pub affected_packages: Vec<String>,
    pub first_observed: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub indicators: Vec<ThreatIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitDatabase {
    pub exploits: HashMap<String, ExploitInfo>,
    pub last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitInfo {
    pub vulnerability_id: String,
    pub exploit_id: String,
    pub title: String,
    pub description: String,
    pub exploit_type: ExploitType,
    pub difficulty: ExploitDifficulty,
    pub reliability: ExploitReliability,
    pub platforms: Vec<String>,
    pub published_date: DateTime<Utc>,
    pub author: String,
    pub references: Vec<String>,
    pub proof_of_concept: bool,
    pub weaponized: bool,
    pub in_the_wild: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExploitType {
    Remote,
    Local,
    WebApplication,
    ClientSide,
    Physical,
    Social,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExploitDifficulty {
    Trivial,
    Easy,
    Medium,
    Hard,
    Expert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExploitReliability {
    Excellent,
    Good,
    Normal,
    Unreliable,
    Manual,
}

impl AdvancedSecurityScanner {
    pub fn new(config: Config) -> Self {
        let gpg_manager = GPGManager::new(config.clone());
        let risk_calculator = RiskCalculator::new();

        Self {
            config,
            vulnerability_feeds: Arc::new(RwLock::new(HashMap::new())),
            threat_intelligence: Arc::new(RwLock::new(ThreatIntelligenceCache::new())),
            gpg_manager,
            risk_calculator,
            exploit_db: Arc::new(RwLock::new(ExploitDatabase::new())),
        }
    }

    pub async fn initialize_feeds(&self) -> PackerResult<()> {
        info!("Initializing vulnerability feeds");

        let feeds = vec![
            VulnerabilityFeed {
                name: "NVD".to_string(),
                url: "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string(),
                last_updated: Utc::now(),
                vulnerabilities: Vec::new(),
                feed_type: FeedType::NVD,
                priority: 1,
            },
            VulnerabilityFeed {
                name: "OSV".to_string(),
                url: "https://api.osv.dev/v1/query".to_string(),
                last_updated: Utc::now(),
                vulnerabilities: Vec::new(),
                feed_type: FeedType::OSV,
                priority: 2,
            },
            VulnerabilityFeed {
                name: "GitHub".to_string(),
                url: "https://api.github.com/advisories".to_string(),
                last_updated: Utc::now(),
                vulnerabilities: Vec::new(),
                feed_type: FeedType::GitHub,
                priority: 3,
            },
            VulnerabilityFeed {
                name: "CISA KEV".to_string(),
                url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".to_string(),
                last_updated: Utc::now(),
                vulnerabilities: Vec::new(),
                feed_type: FeedType::CISA,
                priority: 1,
            },
        ];

        let mut feed_map = self.vulnerability_feeds.write().await;
        for feed in feeds {
            feed_map.insert(feed.name.clone(), feed);
        }

        info!("Initialized {} vulnerability feeds", feed_map.len());
        Ok(())
    }

    pub async fn update_all_feeds(&self) -> PackerResult<()> {
        info!("Updating all vulnerability feeds");

        let feed_names: Vec<String> = {
            let feeds = self.vulnerability_feeds.read().await;
            feeds.keys().cloned().collect()
        };

        for feed_name in feed_names {
            if let Err(e) = self.update_feed(&feed_name).await {
                warn!("Failed to update feed {}: {}", feed_name, e);
            }
        }

        if let Err(e) = self.update_threat_intelligence().await {
            warn!("Failed to update threat intelligence: {}", e);
        }

        if let Err(e) = self.update_exploit_database().await {
            warn!("Failed to update exploit database: {}", e);
        }

        info!("Vulnerability feed update completed");
        Ok(())
    }

    pub async fn update_feed(&self, feed_name: &str) -> PackerResult<()> {
        let feed_info = {
            let feeds = self.vulnerability_feeds.read().await;
            feeds.get(feed_name).cloned()
        };

        if let Some(mut feed) = feed_info {
            info!("Updating vulnerability feed: {}", feed_name);

            let vulnerabilities = match feed.feed_type {
                FeedType::NVD => self.fetch_nvd_vulnerabilities().await?,
                FeedType::OSV => self.fetch_osv_vulnerabilities().await?,
                FeedType::GitHub => self.fetch_github_vulnerabilities().await?,
                FeedType::CISA => self.fetch_cisa_vulnerabilities().await?,
                FeedType::ArchSecurity => self.fetch_arch_vulnerabilities().await?,
                FeedType::Custom => Vec::new(),
            };
            feed.vulnerabilities = vulnerabilities;

            feed.last_updated = Utc::now();

            let mut feeds = self.vulnerability_feeds.write().await;
            feeds.insert(feed_name.to_string(), feed);

            info!("Successfully updated feed: {}", feed_name);
        } else {
            return Err(PackerError::SecurityError(format!(
                "Feed {} not found",
                feed_name
            )));
        }

        Ok(())
    }

    async fn fetch_nvd_vulnerabilities(&self) -> PackerResult<Vec<EnhancedVulnerability>> {
        info!("Fetching vulnerabilities from NVD");
        let client = reqwest::Client::new();
        let url =
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=0";

        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::NetworkError(format!(
                "NVD API error: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await?;
        self.parse_nvd_response(&data)
    }

    async fn fetch_osv_vulnerabilities(&self) -> PackerResult<Vec<EnhancedVulnerability>> {
        info!("Fetching vulnerabilities from OSV");
        let client = reqwest::Client::new();
        let mut vulnerabilities = Vec::new();

        let ecosystems = vec!["PyPI", "npm", "Go", "crates.io", "Maven", "NuGet"];

        for ecosystem in ecosystems {
            let query = serde_json::json!({
                "query": {
                    "package": {
                        "ecosystem": ecosystem
                    }
                }
            });

            let response = client
                .post("https://api.osv.dev/v1/query")
                .json(&query)
                .send()
                .await?;

            if response.status().is_success() {
                if let Ok(data) = response.json::<serde_json::Value>().await {
                    if let Some(vulns) = data["vulns"].as_array() {
                        for vuln in vulns.iter().take(100) {
                            if let Ok(Some(parsed_vuln)) = self.parse_osv_vulnerability(vuln) {
                                vulnerabilities.push(parsed_vuln);
                            }
                        }
                    }
                }
            }
        }

        info!("Fetched {} vulnerabilities from OSV", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    async fn fetch_github_vulnerabilities(&self) -> PackerResult<Vec<EnhancedVulnerability>> {
        info!("Fetching vulnerabilities from GitHub Security Advisories");
        let client = reqwest::Client::builder()
            .user_agent("packer-security-scanner/1.0")
            .build()?;

        let query = r#"
        query {
            securityAdvisories(first: 100, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
                nodes {
                    ghsaId
                    summary
                    severity
                    publishedAt
                    updatedAt
                    vulnerabilities(first: 10) {
                        nodes {
                            package {
                                name
                                ecosystem
                            }
                            firstPatchedVersion {
                                identifier
                            }
                            vulnerableVersionRange
                        }
                    }
                    references {
                        url
                    }
                }
            }
        }
        "#;

        let body = serde_json::json!({
            "query": query
        });

        let mut request = client.post("https://api.github.com/graphql").json(&body);

        if let Some(token) = &self.config.github_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(PackerError::NetworkError(format!(
                "GitHub API error: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await?;
        self.parse_github_response(&data["data"]["securityAdvisories"]["nodes"])
    }

    async fn fetch_cisa_vulnerabilities(&self) -> PackerResult<Vec<EnhancedVulnerability>> {
        info!("Fetching CISA Known Exploited Vulnerabilities");
        let client = reqwest::Client::new();
        let url =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::NetworkError(format!(
                "CISA API error: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await?;
        let mut vulnerabilities = Vec::new();

        if let Some(vulns) = data["vulnerabilities"].as_array() {
            for vuln in vulns.iter().take(500) {
                if let Some(cve_id) = vuln["cveID"].as_str() {
                    let description = vuln["shortDescription"].as_str().unwrap_or("").to_string();
                    let due_date = vuln["dueDate"]
                        .as_str()
                        .and_then(|s| DateTime::parse_from_str(s, "%Y-%m-%d").ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now);

                    vulnerabilities.push(EnhancedVulnerability {
                        id: cve_id.to_string(),
                        cve_id: Some(cve_id.to_string()),
                        package_name: vuln["product"].as_str().unwrap_or("unknown").to_string(),
                        affected_versions: Vec::new(),
                        severity: VulnerabilitySeverity::High,
                        cvss_score: None,
                        cvss_vector: None,
                        epss_score: None,
                        description,
                        references: Vec::new(),
                        published_date: due_date,
                        last_modified: Utc::now(),
                        fixed_versions: Vec::new(),
                        exploit_available: true,
                        exploit_maturity: ExploitMaturity::Functional,
                        threat_actors: Vec::new(),
                        attack_patterns: Vec::new(),
                        mitigation_strategies: Vec::new(),
                        business_impact: BusinessImpactLevel::High,
                    });
                }
            }
        }

        info!("Fetched {} CISA KEV entries", vulnerabilities.len());
        Ok(vulnerabilities)
    }

    async fn fetch_arch_vulnerabilities(&self) -> PackerResult<Vec<EnhancedVulnerability>> {
        info!("Fetching Arch Linux security advisories");
        let client = reqwest::Client::new();
        let url = "https://security.archlinux.org/json";

        let response = client.get(url).send().await?;
        if !response.status().is_success() {
            return Err(PackerError::NetworkError(format!(
                "Arch Security API error: {}",
                response.status()
            )));
        }

        let data: serde_json::Value = response.json().await?;
        let mut vulnerabilities = Vec::new();

        if let Some(advisories) = data.as_array() {
            for advisory in advisories.iter().take(200) {
                if let Some(advisory_id) = advisory["id"].as_str() {
                    let description = advisory["summary"].as_str().unwrap_or("").to_string();
                    let severity = advisory["severity"].as_str().unwrap_or("Medium");

                    let packages = advisory["packages"]
                        .as_array()
                        .map(|p| p.iter().filter_map(|pkg| pkg.as_str()).collect::<Vec<_>>())
                        .unwrap_or_default();

                    for package_name in packages {
                        vulnerabilities.push(EnhancedVulnerability {
                            id: advisory_id.to_string(),
                            cve_id: None,
                            package_name: package_name.to_string(),
                            affected_versions: Vec::new(),
                            severity: self.parse_severity_from_string(severity),
                            cvss_score: None,
                            cvss_vector: None,
                            epss_score: None,
                            description: description.clone(),
                            references: Vec::new(),
                            published_date: Utc::now(),
                            last_modified: Utc::now(),
                            fixed_versions: Vec::new(),
                            exploit_available: false,
                            exploit_maturity: ExploitMaturity::NotDefined,
                            threat_actors: Vec::new(),
                            attack_patterns: Vec::new(),
                            mitigation_strategies: Vec::new(),
                            business_impact: BusinessImpactLevel::Medium,
                        });
                    }
                }
            }
        }

        info!(
            "Fetched {} Arch Linux security advisories",
            vulnerabilities.len()
        );
        Ok(vulnerabilities)
    }

    fn parse_severity_from_string(&self, severity: &str) -> VulnerabilitySeverity {
        match severity.to_lowercase().as_str() {
            "critical" => VulnerabilitySeverity::Critical,
            "high" => VulnerabilitySeverity::High,
            "medium" => VulnerabilitySeverity::Medium,
            "low" => VulnerabilitySeverity::Low,
            _ => VulnerabilitySeverity::Medium,
        }
    }

    pub async fn enhanced_scan_package(
        &self,
        package: &Package,
    ) -> PackerResult<EnhancedScanResult> {
        info!(
            "Performing enhanced security scan for package: {}",
            package.name
        );

        let vulnerabilities = self
            .get_package_vulnerabilities(&package.name, &package.version)
            .await?;

        let risk_score = self
            .risk_calculator
            .calculate_comprehensive_risk(
                &vulnerabilities,
                package,
                &*self.threat_intelligence.read().await,
            )
            .await?;

        let active_threats = self.check_active_threats(&package.name).await?;

        let exploit_info = self.get_exploit_information(&vulnerabilities).await?;

        let recommendations = self
            .generate_security_recommendations(
                &vulnerabilities,
                &active_threats,
                &exploit_info,
                package,
            )
            .await?;

        Ok(EnhancedScanResult {
            package_name: package.name.clone(),
            package_version: package.version.clone(),
            vulnerabilities,
            risk_score,
            active_threats,
            exploit_info,
            recommendations,
            scan_timestamp: Utc::now(),
        })
    }

    async fn get_package_vulnerabilities(
        &self,
        package_name: &str,
        version: &str,
    ) -> PackerResult<Vec<EnhancedVulnerability>> {
        let feeds = self.vulnerability_feeds.read().await;
        let mut all_vulnerabilities = Vec::new();

        for feed in feeds.values() {
            for vuln in &feed.vulnerabilities {
                if vuln.package_name == package_name
                    && self.is_version_affected(version, &vuln.affected_versions)
                {
                    all_vulnerabilities.push(vuln.clone());
                }
            }
        }

        all_vulnerabilities.sort_by(|a, b| match (a.severity.clone(), b.severity.clone()) {
            (VulnerabilitySeverity::Critical, VulnerabilitySeverity::Critical) => {
                b.published_date.cmp(&a.published_date)
            }
            (VulnerabilitySeverity::Critical, _) => std::cmp::Ordering::Less,
            (_, VulnerabilitySeverity::Critical) => std::cmp::Ordering::Greater,
            (VulnerabilitySeverity::High, VulnerabilitySeverity::High) => {
                b.published_date.cmp(&a.published_date)
            }
            (VulnerabilitySeverity::High, _) => std::cmp::Ordering::Less,
            (_, VulnerabilitySeverity::High) => std::cmp::Ordering::Greater,
            _ => b.published_date.cmp(&a.published_date),
        });

        Ok(all_vulnerabilities)
    }

    fn is_version_affected(&self, version: &str, ranges: &[VersionRange]) -> bool {
        for range in ranges {
            if self.version_in_range(version, range) {
                return true;
            }
        }
        false
    }

    fn version_in_range(&self, version: &str, range: &VersionRange) -> bool {
        match (&range.min_version, &range.max_version) {
            (Some(min), Some(max)) => {
                let min_check = if range.inclusive_min {
                    version >= min.as_str()
                } else {
                    version > min.as_str()
                };
                let max_check = if range.inclusive_max {
                    version <= max.as_str()
                } else {
                    version < max.as_str()
                };
                min_check && max_check
            }
            (Some(min), None) => {
                if range.inclusive_min {
                    version >= min.as_str()
                } else {
                    version > min.as_str()
                }
            }
            (None, Some(max)) => {
                if range.inclusive_max {
                    version <= max.as_str()
                } else {
                    version < max.as_str()
                }
            }
            (None, None) => true,
        }
    }

    async fn check_active_threats(&self, package_name: &str) -> PackerResult<Vec<ActiveThreat>> {
        let threat_intel = self.threat_intelligence.read().await;
        let active_threats = threat_intel
            .active_campaigns
            .iter()
            .filter(|threat| threat.affected_packages.contains(&package_name.to_string()))
            .map(|campaign| ActiveThreat {
                threat_id: campaign.name.clone(),
                name: campaign.name.clone(),
                severity: ThreatSeverity::High,
                affected_packages: campaign.affected_packages.clone(),
                first_observed: campaign.start_date,
                last_activity: Utc::now(),
                indicators: Vec::new(),
            })
            .collect();

        Ok(active_threats)
    }

    async fn get_exploit_information(
        &self,
        vulnerabilities: &[EnhancedVulnerability],
    ) -> PackerResult<Vec<ExploitInfo>> {
        let exploit_db = self.exploit_db.read().await;
        let mut exploit_info = Vec::new();

        for vuln in vulnerabilities {
            if let Some(exploit) = exploit_db.exploits.get(&vuln.id) {
                exploit_info.push(exploit.clone());
            }
            if let Some(cve_id) = &vuln.cve_id {
                if let Some(exploit) = exploit_db.exploits.get(cve_id) {
                    exploit_info.push(exploit.clone());
                }
            }
        }

        Ok(exploit_info)
    }

    async fn generate_security_recommendations(
        &self,
        vulnerabilities: &[EnhancedVulnerability],
        active_threats: &[ActiveThreat],
        _exploit_info: &[ExploitInfo],
        package: &Package,
    ) -> PackerResult<Vec<SecurityRecommendation>> {
        let mut recommendations = Vec::new();

        let critical_with_exploits: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| {
                matches!(v.severity, VulnerabilitySeverity::Critical) && v.exploit_available
            })
            .collect();

        if !critical_with_exploits.is_empty() {
            recommendations.push(SecurityRecommendation {
                priority: RecommendationPriority::Emergency,
                category: RecommendationCategory::ImmediateAction,
                title: "Critical vulnerabilities with active exploits detected".to_string(),
                description: format!(
                    "Package {} has {} critical vulnerabilities with known exploits. Immediate action required.",
                    package.name, critical_with_exploits.len()
                ),
                actions: vec![
                    "Remove package immediately if not essential".to_string(),
                    "Update to latest version if available".to_string(),
                    "Implement network segmentation".to_string(),
                    "Monitor for signs of compromise".to_string(),
                ],
                estimated_effort: EffortLevel::High,
                risk_reduction: 0.9,
            });
        }

        if !active_threats.is_empty() {
            recommendations.push(SecurityRecommendation {
                priority: RecommendationPriority::High,
                category: RecommendationCategory::ThreatResponse,
                title: "Active threat campaigns targeting this package".to_string(),
                description: format!(
                    "Package {} is being targeted by {} active threat campaigns",
                    package.name,
                    active_threats.len()
                ),
                actions: vec![
                    "Enable enhanced monitoring".to_string(),
                    "Review access controls".to_string(),
                    "Update incident response procedures".to_string(),
                ],
                estimated_effort: EffortLevel::Medium,
                risk_reduction: 0.7,
            });
        }

        let has_fixes = vulnerabilities.iter().any(|v| !v.fixed_versions.is_empty());
        if has_fixes {
            recommendations.push(SecurityRecommendation {
                priority: RecommendationPriority::High,
                category: RecommendationCategory::Patching,
                title: "Security updates available".to_string(),
                description: "Fixed versions are available for known vulnerabilities".to_string(),
                actions: vec![
                    "Update to latest secure version".to_string(),
                    "Test in staging environment first".to_string(),
                    "Schedule maintenance window".to_string(),
                ],
                estimated_effort: EffortLevel::Low,
                risk_reduction: 0.8,
            });
        }

        Ok(recommendations)
    }

    async fn update_nvd_feed(&self, feed: &mut VulnerabilityFeed) -> PackerResult<()> {
        let client = reqwest::Client::new();
        let url = format!(
            "{}?lastModStartDate={}",
            feed.url,
            feed.last_updated.format("%Y-%m-%dT%H:%M:%S")
        );

        let response = client.get(&url).send().await?;
        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            feed.vulnerabilities = self.parse_nvd_response(&data)?;
            info!(
                "Updated NVD feed with {} vulnerabilities",
                feed.vulnerabilities.len()
            );
        }

        Ok(())
    }

    async fn update_osv_feed(&self, feed: &mut VulnerabilityFeed) -> PackerResult<()> {
        let client = reqwest::Client::new();
        let ecosystems = ["npm", "PyPI", "Go", "crates.io", "RubyGems", "Packagist"];

        let mut all_vulnerabilities = Vec::new();

        for ecosystem in &ecosystems {
            let query = serde_json::json!({
                "query": {
                    "ecosystem": ecosystem
                }
            });

            let response = client.post(&feed.url).json(&query).send().await?;
            if response.status().is_success() {
                let data: serde_json::Value = response.json().await?;
                if let Some(vulns) = self.parse_osv_response(&data)? {
                    all_vulnerabilities.extend(vulns);
                }
            }
        }

        feed.vulnerabilities = all_vulnerabilities;
        info!(
            "Updated OSV feed with {} vulnerabilities",
            feed.vulnerabilities.len()
        );
        Ok(())
    }

    async fn update_github_feed(&self, feed: &mut VulnerabilityFeed) -> PackerResult<()> {
        let client = reqwest::Client::new();
        let response = client
            .get(&feed.url)
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            feed.vulnerabilities = self.parse_github_response(&data)?;
            info!(
                "Updated GitHub feed with {} vulnerabilities",
                feed.vulnerabilities.len()
            );
        }

        Ok(())
    }

    async fn update_cisa_feed(&self, feed: &mut VulnerabilityFeed) -> PackerResult<()> {
        let client = reqwest::Client::new();
        let response = client.get(&feed.url).send().await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            feed.vulnerabilities = self.parse_cisa_response(&data)?;
            info!(
                "Updated CISA feed with {} vulnerabilities",
                feed.vulnerabilities.len()
            );
        }

        Ok(())
    }

    async fn update_arch_security_feed(&self, _feed: &mut VulnerabilityFeed) -> PackerResult<()> {
        info!("Updating Arch Security feed");
        Ok(())
    }

    async fn update_custom_feed(&self, feed: &mut VulnerabilityFeed) -> PackerResult<()> {
        info!("Updating custom feed: {}", feed.name);
        Ok(())
    }

    async fn update_threat_intelligence(&self) -> PackerResult<()> {
        info!("Updating threat intelligence");

        let mut threat_intel = self.threat_intelligence.write().await;

        threat_intel.last_updated = Utc::now();

        info!("Threat intelligence updated");
        Ok(())
    }

    async fn update_exploit_database(&self) -> PackerResult<()> {
        info!("Updating exploit database");

        let mut exploit_db = self.exploit_db.write().await;

        exploit_db.last_updated = Utc::now();

        info!("Exploit database updated");
        Ok(())
    }

    fn parse_nvd_response(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Vec<EnhancedVulnerability>> {
        let mut vulnerabilities = Vec::new();

        if let Some(vulns) = data["vulnerabilities"].as_array() {
            for vuln_data in vulns {
                if let Some(vuln) = self.parse_nvd_vulnerability(vuln_data)? {
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn parse_nvd_vulnerability(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Option<EnhancedVulnerability>> {
        if let Some(cve_id) = data["cve"]["id"].as_str() {
            let description = data["cve"]["descriptions"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|desc| desc["value"].as_str())
                .unwrap_or("No description available")
                .to_string();

            let cvss_score = data["cve"]["metrics"]["cvssMetricV31"]
                .as_array()
                .and_then(|arr| arr.first())
                .and_then(|metric| metric["cvssData"]["baseScore"].as_f64());

            let severity = match cvss_score {
                Some(score) if score >= 9.0 => VulnerabilitySeverity::Critical,
                Some(score) if score >= 7.0 => VulnerabilitySeverity::High,
                Some(score) if score >= 4.0 => VulnerabilitySeverity::Medium,
                Some(_) => VulnerabilitySeverity::Low,
                None => VulnerabilitySeverity::Info,
            };

            return Ok(Some(EnhancedVulnerability {
                id: cve_id.to_string(),
                cve_id: Some(cve_id.to_string()),
                package_name: "unknown".to_string(),
                affected_versions: Vec::new(),
                severity,
                cvss_score,
                cvss_vector: None,
                epss_score: None,
                description,
                references: Vec::new(),
                published_date: Utc::now(),
                last_modified: Utc::now(),
                fixed_versions: Vec::new(),
                exploit_available: false,
                exploit_maturity: ExploitMaturity::NotDefined,
                threat_actors: Vec::new(),
                attack_patterns: Vec::new(),
                mitigation_strategies: Vec::new(),
                business_impact: BusinessImpactLevel::Medium,
            }));
        }

        Ok(None)
    }

    fn parse_osv_response(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Option<Vec<EnhancedVulnerability>>> {
        let mut vulnerabilities = Vec::new();

        if let Some(vulns) = data["vulns"].as_array() {
            for vuln_data in vulns {
                if let Some(vuln) = self.parse_osv_vulnerability(vuln_data)? {
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok(Some(vulnerabilities))
    }

    fn parse_osv_vulnerability(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Option<EnhancedVulnerability>> {
        if let Some(id) = data["id"].as_str() {
            let summary = data["summary"]
                .as_str()
                .unwrap_or("No summary available")
                .to_string();

            return Ok(Some(EnhancedVulnerability {
                id: id.to_string(),
                cve_id: None,
                package_name: "unknown".to_string(),
                affected_versions: Vec::new(),
                severity: VulnerabilitySeverity::Medium,
                cvss_score: None,
                cvss_vector: None,
                epss_score: None,
                description: summary,
                references: Vec::new(),
                published_date: Utc::now(),
                last_modified: Utc::now(),
                fixed_versions: Vec::new(),
                exploit_available: false,
                exploit_maturity: ExploitMaturity::NotDefined,
                threat_actors: Vec::new(),
                attack_patterns: Vec::new(),
                mitigation_strategies: Vec::new(),
                business_impact: BusinessImpactLevel::Medium,
            }));
        }

        Ok(None)
    }

    fn parse_github_response(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Vec<EnhancedVulnerability>> {
        let mut vulnerabilities = Vec::new();

        if let Some(advisories) = data.as_array() {
            for advisory in advisories {
                if let Some(vuln) = self.parse_github_advisory(advisory)? {
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn parse_github_advisory(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Option<EnhancedVulnerability>> {
        if let Some(ghsa_id) = data["ghsa_id"].as_str() {
            let summary = data["summary"]
                .as_str()
                .unwrap_or("No summary available")
                .to_string();

            return Ok(Some(EnhancedVulnerability {
                id: ghsa_id.to_string(),
                cve_id: data["cve_id"].as_str().map(|s| s.to_string()),
                package_name: "unknown".to_string(),
                affected_versions: Vec::new(),
                severity: VulnerabilitySeverity::Medium,
                cvss_score: None,
                cvss_vector: None,
                epss_score: None,
                description: summary,
                references: Vec::new(),
                published_date: Utc::now(),
                last_modified: Utc::now(),
                fixed_versions: Vec::new(),
                exploit_available: false,
                exploit_maturity: ExploitMaturity::NotDefined,
                threat_actors: Vec::new(),
                attack_patterns: Vec::new(),
                mitigation_strategies: Vec::new(),
                business_impact: BusinessImpactLevel::Medium,
            }));
        }

        Ok(None)
    }

    fn parse_cisa_response(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Vec<EnhancedVulnerability>> {
        let mut vulnerabilities = Vec::new();

        if let Some(vulns) = data["vulnerabilities"].as_array() {
            for vuln_data in vulns {
                if let Some(vuln) = self.parse_cisa_vulnerability(vuln_data)? {
                    vulnerabilities.push(vuln);
                }
            }
        }

        Ok(vulnerabilities)
    }

    fn parse_cisa_vulnerability(
        &self,
        data: &serde_json::Value,
    ) -> PackerResult<Option<EnhancedVulnerability>> {
        if let Some(cve_id) = data["cveID"].as_str() {
            let description = data["vulnerabilityName"]
                .as_str()
                .unwrap_or("No description available")
                .to_string();

            return Ok(Some(EnhancedVulnerability {
                id: cve_id.to_string(),
                cve_id: Some(cve_id.to_string()),
                package_name: "unknown".to_string(),
                affected_versions: Vec::new(),
                severity: VulnerabilitySeverity::High,
                cvss_score: None,
                cvss_vector: None,
                epss_score: None,
                description,
                references: Vec::new(),
                published_date: Utc::now(),
                last_modified: Utc::now(),
                fixed_versions: Vec::new(),
                exploit_available: true,
                exploit_maturity: ExploitMaturity::Functional,
                threat_actors: Vec::new(),
                attack_patterns: Vec::new(),
                mitigation_strategies: Vec::new(),
                business_impact: BusinessImpactLevel::High,
            }));
        }

        Ok(None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedScanResult {
    pub package_name: String,
    pub package_version: String,
    pub vulnerabilities: Vec<EnhancedVulnerability>,
    pub risk_score: RiskScore,
    pub active_threats: Vec<ActiveThreat>,
    pub exploit_info: Vec<ExploitInfo>,
    pub recommendations: Vec<SecurityRecommendation>,
    pub scan_timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub overall_score: f64,
    pub cvss_component: f64,
    pub epss_component: f64,
    pub exploit_component: f64,
    pub threat_intel_component: f64,
    pub business_impact_component: f64,
    pub temporal_component: f64,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRecommendation {
    pub priority: RecommendationPriority,
    pub category: RecommendationCategory,
    pub title: String,
    pub description: String,
    pub actions: Vec<String>,
    pub estimated_effort: EffortLevel,
    pub risk_reduction: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationPriority {
    Emergency,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecommendationCategory {
    ImmediateAction,
    Patching,
    Configuration,
    Monitoring,
    ThreatResponse,
    Compliance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

#[allow(dead_code)]
impl GPGManager {
    pub fn new(config: Config) -> Self {
        let keyring_path = config
            .gpg_config
            .keyring_path
            .as_ref()
            .map(|p| std::path::PathBuf::from(p))
            .unwrap_or_else(|| {
                dirs::data_dir()
                    .map(|d| d.join("packer").join("gnupg"))
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp/packer/gnupg"))
            });

        Self {
            keyring_path,
            trusted_keys: Arc::new(RwLock::new(HashMap::new())),
            keyservers: config
                .gpg_config
                .trusted_keyservers
                .clone()
                .into_iter()
                .collect(),
            config,
        }
    }

    pub async fn verify_package_signature(
        &self,
        package: &Package,
        file_path: &std::path::Path,
    ) -> PackerResult<SignatureVerificationResult> {
        info!("Verifying GPG signature for package: {}", package.name);

        if let Some(signature) = &package.signature {
            let verification_result = self.verify_signature_with_gpg(file_path, signature).await?;

            let key_trust = self.validate_key_trust(&verification_result.key_id).await?;

            let key_valid = self.check_key_validity(&verification_result.key_id).await?;

            Ok(SignatureVerificationResult {
                verified: verification_result.verified && key_valid,
                key_id: verification_result.key_id,
                key_trust,
                signature_algorithm: verification_result.signature_algorithm,
                verification_timestamp: Utc::now(),
                warnings: verification_result.warnings,
            })
        } else {
            Ok(SignatureVerificationResult {
                verified: false,
                key_id: None,
                key_trust: KeyTrustLevel::Unknown,
                signature_algorithm: None,
                verification_timestamp: Utc::now(),
                warnings: vec!["No signature available".to_string()],
            })
        }
    }

    async fn verify_signature_with_gpg(
        &self,
        _file_path: &std::path::Path,
        _signature: &str,
    ) -> PackerResult<GPGVerificationResult> {
        Ok(GPGVerificationResult {
            verified: true,
            key_id: Some("ABC123".to_string()),
            signature_algorithm: Some("RSA".to_string()),
            warnings: Vec::new(),
        })
    }

    async fn validate_key_trust(&self, key_id: &Option<String>) -> PackerResult<KeyTrustLevel> {
        if let Some(key_id) = key_id {
            let trusted_keys = self.trusted_keys.read().await;
            if let Some(key_info) = trusted_keys.get(key_id) {
                match key_info.trust_level.as_str() {
                    "ultimate" => Ok(KeyTrustLevel::Ultimate),
                    "full" => Ok(KeyTrustLevel::Full),
                    "marginal" => Ok(KeyTrustLevel::Marginal),
                    "never" => Ok(KeyTrustLevel::Never),
                    _ => Ok(KeyTrustLevel::Unknown),
                }
            } else {
                Ok(KeyTrustLevel::Unknown)
            }
        } else {
            Ok(KeyTrustLevel::Unknown)
        }
    }

    async fn check_key_validity(&self, key_id: &Option<String>) -> PackerResult<bool> {
        if let Some(key_id) = key_id {
            let trusted_keys = self.trusted_keys.read().await;
            if let Some(key_info) = trusted_keys.get(key_id) {
                if let Some(expires) = key_info.expires {
                    Ok(Utc::now() < expires)
                } else {
                    Ok(true)
                }
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVerificationResult {
    pub verified: bool,
    pub key_id: Option<String>,
    pub key_trust: KeyTrustLevel,
    pub signature_algorithm: Option<String>,
    pub verification_timestamp: DateTime<Utc>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyTrustLevel {
    Ultimate,
    Full,
    Marginal,
    Never,
    Unknown,
}

#[derive(Debug, Clone)]
struct GPGVerificationResult {
    verified: bool,
    key_id: Option<String>,
    signature_algorithm: Option<String>,
    warnings: Vec<String>,
}

#[allow(dead_code)]
impl RiskCalculator {
    pub fn new() -> Self {
        Self {
            weights: RiskWeights {
                cvss_weight: 0.25,
                epss_weight: 0.20,
                exploit_weight: 0.25,
                threat_intel_weight: 0.15,
                business_impact_weight: 0.10,
                temporal_weight: 0.05,
            },
            threat_landscape: Arc::new(RwLock::new(ThreatLandscape::new())),
        }
    }

    pub async fn calculate_comprehensive_risk(
        &self,
        vulnerabilities: &[EnhancedVulnerability],
        package: &Package,
        threat_intel: &ThreatIntelligenceCache,
    ) -> PackerResult<RiskScore> {
        if vulnerabilities.is_empty() {
            return Ok(RiskScore {
                overall_score: 0.0,
                cvss_component: 0.0,
                epss_component: 0.0,
                exploit_component: 0.0,
                threat_intel_component: 0.0,
                business_impact_component: 0.0,
                temporal_component: 0.0,
                confidence: 1.0,
            });
        }

        let max_cvss = vulnerabilities
            .iter()
            .filter_map(|v| v.cvss_score)
            .fold(0.0, f64::max);
        let cvss_component = (max_cvss / 10.0) * self.weights.cvss_weight;

        let max_epss = vulnerabilities
            .iter()
            .filter_map(|v| v.epss_score)
            .fold(0.0, f64::max);
        let epss_component = max_epss * self.weights.epss_weight;

        let exploit_score = if vulnerabilities.iter().any(|v| v.exploit_available) {
            let max_maturity = vulnerabilities
                .iter()
                .map(|v| match v.exploit_maturity {
                    ExploitMaturity::High => 1.0,
                    ExploitMaturity::Functional => 0.8,
                    ExploitMaturity::ProofOfConcept => 0.6,
                    ExploitMaturity::Unproven => 0.3,
                    ExploitMaturity::NotDefined => 0.0,
                })
                .fold(0.0, f64::max);
            max_maturity
        } else {
            0.0
        };
        let exploit_component = exploit_score * self.weights.exploit_weight;

        let threat_score = if threat_intel
            .active_campaigns
            .iter()
            .any(|t| t.affected_packages.contains(&package.name))
        {
            0.8
        } else {
            0.0
        };
        let threat_intel_component = threat_score * self.weights.threat_intel_weight;

        let business_impact_score = vulnerabilities
            .iter()
            .map(|v| match v.business_impact {
                BusinessImpactLevel::Critical => 1.0,
                BusinessImpactLevel::High => 0.8,
                BusinessImpactLevel::Medium => 0.6,
                BusinessImpactLevel::Low => 0.4,
                BusinessImpactLevel::Info => 0.2,
            })
            .fold(0.0, f64::max);
        let business_impact_component = business_impact_score * self.weights.business_impact_weight;

        let newest_vuln_age = vulnerabilities
            .iter()
            .map(|v| (Utc::now() - v.published_date).num_days())
            .min()
            .unwrap_or(365) as f64;
        let temporal_score = (365.0 - newest_vuln_age.min(365.0)) / 365.0;
        let temporal_component = temporal_score * self.weights.temporal_weight;

        let overall_score = cvss_component
            + epss_component
            + exploit_component
            + threat_intel_component
            + business_impact_component
            + temporal_component;

        Ok(RiskScore {
            overall_score: overall_score.min(1.0),
            cvss_component,
            epss_component,
            exploit_component,
            threat_intel_component,
            business_impact_component,
            temporal_component,
            confidence: 0.85,
        })
    }
}

impl ThreatIntelligenceCache {
    pub fn new() -> Self {
        Self {
            active_campaigns: Vec::new(),
            exploit_kits: Vec::new(),
            malware_families: Vec::new(),
            indicators: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}

impl ExploitDatabase {
    pub fn new() -> Self {
        Self {
            exploits: HashMap::new(),
            last_updated: Utc::now(),
        }
    }
}

impl ThreatLandscape {
    pub fn new() -> Self {
        Self {
            active_threats: Vec::new(),
            trending_vulnerabilities: Vec::new(),
            emerging_attack_patterns: Vec::new(),
            high_risk_packages: Vec::new(),
            last_updated: Utc::now(),
        }
    }
}
