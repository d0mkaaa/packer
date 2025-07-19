use crate::error::{PackerError, PackerResult};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mirror {
    pub url: String,
    pub country: String,
    pub country_code: String,
    pub protocol: String,
    pub completion_pct: f64,
    pub delay: Option<Duration>,
    pub duration_avg: Option<Duration>,
    pub duration_stddev: Option<Duration>,
    pub score: Option<f64>,
    pub active: bool,
    pub isos: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub details: String,
    pub last_sync: Option<DateTime<Utc>>,
    pub last_tested: Option<DateTime<Utc>>,
    pub response_time: Option<Duration>,
    pub success_rate: f64,
    pub bandwidth_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorList {
    pub mirrors: Vec<Mirror>,
    pub last_updated: DateTime<Utc>,
    pub version: String,
    pub cutoff: DateTime<Utc>,
    pub last_check: DateTime<Utc>,
    pub num_checks: u32,
    pub check_frequency: Duration,
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorTestResult {
    pub mirror_url: String,
    pub response_time: Duration,
    pub download_speed: f64, // MB/s
    pub success: bool,
    pub error_message: Option<String>,
    pub tested_at: DateTime<Utc>,
    pub package_available: bool,
    pub ssl_valid: bool,
}

#[derive(Debug)]
pub struct MirrorManager {
    mirrors: Vec<Mirror>,
    config: MirrorConfig,
    test_results: HashMap<String, Vec<MirrorTestResult>>,
    last_mirror_update: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    pub max_mirrors_per_country: usize,
    pub test_timeout: Duration,
    pub mirror_list_url: String,
    pub preferred_countries: Vec<String>,
    pub preferred_protocols: Vec<String>,
    pub min_completion_pct: f64,
    pub enable_ipv6: bool,
    pub custom_mirrors: Vec<String>,
    pub update_interval: Duration,
    pub test_file_path: String, // relative path to test download
    pub min_bandwidth: f64,     // MB/s
    pub max_response_time: Duration,
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            max_mirrors_per_country: 3,
            test_timeout: Duration::from_secs(10),
            mirror_list_url: "https://archlinux.org/mirrorlist/all/".to_string(),
            preferred_countries: vec!["US".to_string(), "GB".to_string(), "DE".to_string()],
            preferred_protocols: vec!["https".to_string(), "http".to_string()],
            min_completion_pct: 95.0,
            enable_ipv6: false,
            custom_mirrors: vec![],
            update_interval: Duration::from_secs(3600), // 1 hour
            test_file_path: "core/os/x86_64/core.db".to_string(),
            min_bandwidth: 1.0, // 1 MB/s minimum
            max_response_time: Duration::from_secs(5),
        }
    }
}

impl MirrorManager {
    pub fn new(config: MirrorConfig) -> Self {
        Self {
            mirrors: Vec::new(),
            config,
            test_results: HashMap::new(),
            last_mirror_update: None,
        }
    }

    pub async fn initialize(&mut self) -> PackerResult<()> {
        info!("Initializing mirror manager");

        // load built-in mirror list as fallback
        self.load_builtin_mirrors();

        // try to fetch latest mirror list
        match self.fetch_mirror_list().await {
            Ok(_) => info!("Successfully fetched mirror list"),
            Err(e) => {
                warn!("Failed to fetch mirror list, using built-in mirrors: {}", e);
            }
        }

        // add custom mirrors from config
        self.add_custom_mirrors();

        // test a subset of mirrors to get initial rankings
        self.quick_test_mirrors().await?;

        info!(
            "Mirror manager initialized with {} mirrors",
            self.mirrors.len()
        );
        Ok(())
    }

    pub async fn get_best_mirrors(&mut self, repo: &str) -> PackerResult<Vec<String>> {
        // check if we need to update mirror list
        if self.should_update_mirrors() {
            if let Err(e) = self.fetch_mirror_list().await {
                warn!("Failed to update mirror list: {}", e);
            }
        }

        // get top mirrors for this repo
        let mut candidates: Vec<_> = self
            .mirrors
            .iter()
            .filter(|m| self.is_mirror_suitable(m))
            .cloned()
            .collect();

        // sort by score (best first)
        candidates.sort_by(|a, b| {
            b.score
                .unwrap_or(0.0)
                .partial_cmp(&a.score.unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // return top mirrors with repo path
        let mirrors: Vec<String> = candidates
            .into_iter()
            .take(5) // top 5 mirrors
            .map(|m| format!("{}/{}", m.url.trim_end_matches('/'), repo))
            .collect();

        if mirrors.is_empty() {
            return Err(PackerError::NetworkError(
                "No suitable mirrors available".to_string(),
            ));
        }

        debug!("Selected {} mirrors for repo {}", mirrors.len(), repo);
        Ok(mirrors)
    }

    pub async fn test_mirror_speed(&self, mirror_url: &str) -> PackerResult<MirrorTestResult> {
        let test_url = format!(
            "{}/{}",
            mirror_url.trim_end_matches('/'),
            self.config.test_file_path
        );

        debug!("Testing mirror speed: {}", test_url);
        let start_time = Instant::now();

        let client = reqwest::Client::builder()
            .timeout(self.config.test_timeout)
            .user_agent("packer/0.2.1")
            .build()?;

        let result = timeout(self.config.test_timeout, async {
            match client.head(&test_url).send().await {
                Ok(response) => {
                    let response_time = start_time.elapsed();
                    let success = response.status().is_success();
                    let ssl_valid = test_url.starts_with("https://");

                    MirrorTestResult {
                        mirror_url: mirror_url.to_string(),
                        response_time,
                        download_speed: 0.0, // we're just doing a HEAD request
                        success,
                        error_message: if success {
                            None
                        } else {
                            Some(format!("HTTP {}", response.status()))
                        },
                        tested_at: Utc::now(),
                        package_available: success,
                        ssl_valid,
                    }
                }
                Err(e) => MirrorTestResult {
                    mirror_url: mirror_url.to_string(),
                    response_time: start_time.elapsed(),
                    download_speed: 0.0,
                    success: false,
                    error_message: Some(e.to_string()),
                    tested_at: Utc::now(),
                    package_available: false,
                    ssl_valid: false,
                },
            }
        })
        .await;

        match result {
            Ok(test_result) => Ok(test_result),
            Err(_) => {
                // timeout occurred
                Ok(MirrorTestResult {
                    mirror_url: mirror_url.to_string(),
                    response_time: self.config.test_timeout,
                    download_speed: 0.0,
                    success: false,
                    error_message: Some("Request timeout".to_string()),
                    tested_at: Utc::now(),
                    package_available: false,
                    ssl_valid: false,
                })
            }
        }
    }

    pub async fn rank_mirrors(&mut self) -> PackerResult<()> {
        info!("Ranking mirrors by performance");

        let mut test_results = Vec::new();

        // test all mirrors in parallel (but limit concurrency)
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(10)); // max 10 concurrent tests
        let mut handles = Vec::new();

        for mirror in &self.mirrors {
            let permit = semaphore.clone().acquire_owned().await?;
            let mirror_url = mirror.url.clone();
            let manager = self.clone_for_testing();

            let handle = tokio::spawn(async move {
                let _permit = permit; // keep permit alive
                manager.test_mirror_speed(&mirror_url).await
            });

            handles.push(handle);
        }

        // collect results
        for handle in handles {
            match handle.await {
                Ok(Ok(result)) => test_results.push(result),
                Ok(Err(e)) => warn!("Mirror test failed: {}", e),
                Err(e) => warn!("Mirror test task failed: {}", e),
            }
        }

        // update mirror scores based on results
        for result in &test_results {
            if let Some(mirror) = self.mirrors.iter_mut().find(|m| m.url == result.mirror_url) {
                let score = Self::calculate_mirror_score(&self.config, mirror, result);
                mirror.score = Some(score);
                mirror.response_time = Some(result.response_time);
                mirror.last_tested = Some(result.tested_at);

                // update success rate
                if result.success {
                    mirror.success_rate = (mirror.success_rate * 0.9) + 0.1; // moving average
                } else {
                    mirror.success_rate *= 0.9;
                }
            }
        }

        // store test results
        for result in test_results {
            self.test_results
                .entry(result.mirror_url.clone())
                .or_insert_with(Vec::new)
                .push(result);
        }

        info!("Mirror ranking completed");
        Ok(())
    }

    fn calculate_mirror_score(
        config: &MirrorConfig,
        mirror: &Mirror,
        test_result: &MirrorTestResult,
    ) -> f64 {
        if !test_result.success {
            return 0.0;
        }

        let mut score = 100.0;

        // response time factor (lower is better)
        let response_ms = test_result.response_time.as_millis() as f64;
        score -= (response_ms / 10.0).min(50.0); // max penalty of 50 points

        // completion percentage
        score *= mirror.completion_pct / 100.0;

        // protocol preference (https > http)
        if mirror.protocol == "https" {
            score += 10.0;
        }

        // country preference
        if config.preferred_countries.contains(&mirror.country_code) {
            score += 15.0;
        }

        // success rate
        score *= mirror.success_rate;

        // delay factor (mirrors with recent sync are better)
        if let Some(delay) = mirror.delay {
            let delay_hours = delay.as_secs() as f64 / 3600.0;
            score -= delay_hours.min(24.0); // max penalty of 24 points
        }

        score.max(0.0)
    }

    fn clone_for_testing(&self) -> MirrorManagerTestHelper {
        MirrorManagerTestHelper {
            config: self.config.clone(),
        }
    }

    async fn fetch_mirror_list(&mut self) -> PackerResult<()> {
        info!("Fetching mirror list from: {}", self.config.mirror_list_url);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("packer/0.2.1")
            .build()?;

        let response = client.get(&self.config.mirror_list_url).send().await?;

        if !response.status().is_success() {
            return Err(PackerError::NetworkError(format!(
                "Failed to fetch mirror list: HTTP {}",
                response.status()
            )));
        }

        let mirror_data = response.text().await?;
        self.parse_mirror_list(&mirror_data)?;
        self.last_mirror_update = Some(Utc::now());

        Ok(())
    }

    fn parse_mirror_list(&mut self, data: &str) -> PackerResult<()> {
        // parse the archlinux mirror list format
        let mut current_mirror: Option<Mirror> = None;

        for line in data.lines() {
            let line = line.trim();

            if line.starts_with("## ") {
                // save previous mirror if exists
                if let Some(mirror) = current_mirror.take() {
                    if self.is_mirror_suitable(&mirror) {
                        self.mirrors.push(mirror);
                    }
                }

                // parse mirror info from comment
                let info = &line[3..];
                current_mirror = self.parse_mirror_info(info);
            } else if line.starts_with("Server = ") {
                // extract server URL
                let url = &line[9..];
                if let Some(ref mut mirror) = current_mirror {
                    mirror.url = url.replace("$repo/os/$arch", "").to_string();
                }
            }
        }

        // don't forget the last mirror
        if let Some(mirror) = current_mirror {
            if self.is_mirror_suitable(&mirror) {
                self.mirrors.push(mirror);
            }
        }

        info!("Parsed {} mirrors from mirror list", self.mirrors.len());
        Ok(())
    }

    fn parse_mirror_info(&self, info: &str) -> Option<Mirror> {
        // example: "United States - http://mirror.example.com/archlinux/"
        let parts: Vec<&str> = info.split(" - ").collect();
        if parts.len() < 2 {
            return None;
        }

        let country = parts[0].trim().to_string();
        let url_part = parts[1].trim();

        // extract protocol
        let protocol = if url_part.starts_with("https://") {
            "https"
        } else if url_part.starts_with("http://") {
            "http"
        } else if url_part.starts_with("ftp://") {
            "ftp"
        } else {
            "unknown"
        }
        .to_string();

        // country code mapping (simplified)
        let country_code = self.get_country_code(&country);

        Some(Mirror {
            url: String::new(), // will be filled when parsing Server line
            country,
            country_code,
            protocol,
            completion_pct: 100.0, // assume 100% until we know better
            delay: None,
            duration_avg: None,
            duration_stddev: None,
            score: None,
            active: true,
            isos: false,
            ipv4: true,
            ipv6: false,
            details: String::new(),
            last_sync: None,
            last_tested: None,
            response_time: None,
            success_rate: 1.0,
            bandwidth_score: 1.0,
        })
    }

    fn get_country_code(&self, country: &str) -> String {
        // simplified country code mapping
        match country {
            "United States" => "US",
            "United Kingdom" => "GB",
            "Germany" => "DE",
            "France" => "FR",
            "Canada" => "CA",
            "Australia" => "AU",
            "Japan" => "JP",
            "China" => "CN",
            "Netherlands" => "NL",
            "Sweden" => "SE",
            "Norway" => "NO",
            "Denmark" => "DK",
            "Finland" => "FI",
            _ => "XX", // unknown
        }
        .to_string()
    }

    fn load_builtin_mirrors(&mut self) {
        // hardcoded reliable mirrors as fallback
        let builtin_mirrors = vec![
            ("https://geo.mirror.pkgbuild.com", "Global", "XX"),
            (
                "https://mirror.rackspace.com/archlinux",
                "United States",
                "US",
            ),
            ("https://america.mirror.pkgbuild.com", "United States", "US"),
            ("https://europe.mirror.pkgbuild.com", "Germany", "DE"),
            ("https://asia.mirror.pkgbuild.com", "Singapore", "SG"),
            (
                "https://mirrors.kernel.org/archlinux",
                "United States",
                "US",
            ),
            ("https://mirror.leaseweb.net/archlinux", "Netherlands", "NL"),
        ];

        for (url, country, country_code) in builtin_mirrors {
            let mirror = Mirror {
                url: url.to_string(),
                country: country.to_string(),
                country_code: country_code.to_string(),
                protocol: "https".to_string(),
                completion_pct: 100.0,
                delay: Some(Duration::from_secs(0)),
                duration_avg: None,
                duration_stddev: None,
                score: Some(80.0), // good default score
                active: true,
                isos: true,
                ipv4: true,
                ipv6: false,
                details: "Built-in reliable mirror".to_string(),
                last_sync: Some(Utc::now()),
                last_tested: None,
                response_time: None,
                success_rate: 1.0,
                bandwidth_score: 1.0,
            };
            self.mirrors.push(mirror);
        }
    }

    fn add_custom_mirrors(&mut self) {
        for custom_url in &self.config.custom_mirrors {
            let mirror = Mirror {
                url: custom_url.clone(),
                country: "Custom".to_string(),
                country_code: "XX".to_string(),
                protocol: if custom_url.starts_with("https") {
                    "https"
                } else {
                    "http"
                }
                .to_string(),
                completion_pct: 100.0,
                delay: Some(Duration::from_secs(0)),
                duration_avg: None,
                duration_stddev: None,
                score: Some(90.0), // custom mirrors get high priority
                active: true,
                isos: false,
                ipv4: true,
                ipv6: false,
                details: "User-configured custom mirror".to_string(),
                last_sync: Some(Utc::now()),
                last_tested: None,
                response_time: None,
                success_rate: 1.0,
                bandwidth_score: 1.0,
            };
            self.mirrors.push(mirror);
        }
    }

    async fn quick_test_mirrors(&mut self) -> PackerResult<()> {
        // test a few mirrors quickly to get initial scores
        let test_count = 10.min(self.mirrors.len());
        let mirrors_to_test: Vec<_> = self.mirrors.iter().take(test_count).cloned().collect();

        for mirror in mirrors_to_test {
            if let Ok(result) = self.test_mirror_speed(&mirror.url).await {
                if let Some(m) = self.mirrors.iter_mut().find(|m| m.url == mirror.url) {
                    let score = Self::calculate_mirror_score(&self.config, &mirror, &result);
                    m.score = Some(score);
                    m.response_time = Some(result.response_time);
                    m.last_tested = Some(result.tested_at);
                }
            }
        }

        Ok(())
    }

    fn is_mirror_suitable(&self, mirror: &Mirror) -> bool {
        mirror.active
            && mirror.completion_pct >= self.config.min_completion_pct
            && self.config.preferred_protocols.contains(&mirror.protocol)
            && (self.config.enable_ipv6 || mirror.ipv4)
    }

    fn should_update_mirrors(&self) -> bool {
        match self.last_mirror_update {
            Some(last_update) => {
                Utc::now().signed_duration_since(last_update).num_seconds()
                    > self.config.update_interval.as_secs() as i64
            }
            None => true,
        }
    }

    pub fn get_mirror_stats(&self) -> MirrorStats {
        let total_mirrors = self.mirrors.len();
        let active_mirrors = self.mirrors.iter().filter(|m| m.active).count();
        let tested_mirrors = self
            .mirrors
            .iter()
            .filter(|m| m.last_tested.is_some())
            .count();

        let avg_response_time = {
            let times: Vec<_> = self
                .mirrors
                .iter()
                .filter_map(|m| m.response_time)
                .collect();
            if times.is_empty() {
                Duration::from_secs(0)
            } else {
                times.iter().sum::<Duration>() / times.len() as u32
            }
        };

        MirrorStats {
            total_mirrors,
            active_mirrors,
            tested_mirrors,
            avg_response_time,
            last_update: self.last_mirror_update,
        }
    }
}

// helper struct for testing (to avoid full clone)
#[derive(Clone)]
struct MirrorManagerTestHelper {
    config: MirrorConfig,
}

impl MirrorManagerTestHelper {
    async fn test_mirror_speed(&self, mirror_url: &str) -> PackerResult<MirrorTestResult> {
        let test_url = format!(
            "{}/{}",
            mirror_url.trim_end_matches('/'),
            self.config.test_file_path
        );

        let start_time = Instant::now();

        let client = reqwest::Client::builder()
            .timeout(self.config.test_timeout)
            .user_agent("packer/0.2.1")
            .build()?;

        match timeout(self.config.test_timeout, client.head(&test_url).send()).await {
            Ok(Ok(response)) => {
                let response_time = start_time.elapsed();
                let success = response.status().is_success();

                Ok(MirrorTestResult {
                    mirror_url: mirror_url.to_string(),
                    response_time,
                    download_speed: 0.0,
                    success,
                    error_message: if success {
                        None
                    } else {
                        Some(format!("HTTP {}", response.status()))
                    },
                    tested_at: Utc::now(),
                    package_available: success,
                    ssl_valid: test_url.starts_with("https://"),
                })
            }
            Ok(Err(e)) => Ok(MirrorTestResult {
                mirror_url: mirror_url.to_string(),
                response_time: start_time.elapsed(),
                download_speed: 0.0,
                success: false,
                error_message: Some(e.to_string()),
                tested_at: Utc::now(),
                package_available: false,
                ssl_valid: false,
            }),
            Err(_) => Ok(MirrorTestResult {
                mirror_url: mirror_url.to_string(),
                response_time: self.config.test_timeout,
                download_speed: 0.0,
                success: false,
                error_message: Some("Request timeout".to_string()),
                tested_at: Utc::now(),
                package_available: false,
                ssl_valid: false,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorStats {
    pub total_mirrors: usize,
    pub active_mirrors: usize,
    pub tested_mirrors: usize,
    pub avg_response_time: Duration,
    pub last_update: Option<DateTime<Utc>>,
}
