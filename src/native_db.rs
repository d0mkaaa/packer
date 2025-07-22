use crate::{
    core::{CorePackage, SourceType},
    error::PackerResult,
};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;

#[derive(Debug)]
pub struct SearchCache {
    cache: HashMap<String, Vec<CorePackage>>,
    cache_ttl: Duration,
    last_updated: HashMap<String, DateTime<Utc>>,
}

impl SearchCache {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(300), // 5 min cache
            last_updated: HashMap::new(),
        }
    }

    fn get(&self, query: &str) -> Option<&Vec<CorePackage>> {
        if let Some(last_update) = self.last_updated.get(query) {
            let now = Utc::now();
            if now.signed_duration_since(*last_update).num_seconds()
                < self.cache_ttl.as_secs() as i64
            {
                return self.cache.get(query);
            }
        }
        None
    }

    fn insert(&mut self, query: String, results: Vec<CorePackage>) {
        self.cache.insert(query.clone(), results);
        self.last_updated.insert(query, Utc::now());
    }

    fn clear(&mut self) {
        self.cache.clear();
        self.last_updated.clear();
    }
}

#[derive(Debug)]
pub struct NativePackageDatabase {
    cache_dir: PathBuf,
    db_path: PathBuf,
    official_db: PackageRepository,
    aur_db: PackageRepository,
    last_sync: Option<DateTime<Utc>>,
    sync_interval: chrono::Duration,
    search_cache: SearchCache,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRepository {
    pub name: String,
    pub packages: HashMap<String, CorePackage>,
    pub last_updated: DateTime<Utc>,
    pub package_count: usize,
    pub metadata: RepositoryMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryMetadata {
    pub total_size: u64,
    pub architecture: String,
    pub source_url: String,
    pub sync_status: SyncStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    Fresh,
    Stale,
    Failed(String),
    Syncing,
}

#[derive(Debug, Serialize, Deserialize)]
struct DatabaseFile {
    version: String,
    created: DateTime<Utc>,
    last_updated: DateTime<Utc>,
    official_repo: PackageRepository,
    aur_repo: PackageRepository,
}

impl NativePackageDatabase {
    pub fn new(cache_dir: PathBuf) -> Self {
        let db_path = cache_dir.join("native_packages.json");

        Self {
            cache_dir: cache_dir.clone(),
            db_path,
            official_db: PackageRepository::new("official".to_string()),
            aur_db: PackageRepository::new("aur".to_string()),
            last_sync: None,
            sync_interval: chrono::Duration::hours(6),
            search_cache: SearchCache::new(),
        }
    }

    pub async fn initialize(&mut self) -> PackerResult<()> {
        fs::create_dir_all(&self.cache_dir).await?;

        if self.db_path.exists() {
            self.load_from_disk().await?;
        } else {
            info!("No existing database found, will create new one");
        }

        if self.should_sync() {
            info!("Database is stale, performing initial sync");
            self.sync_repositories().await?;
        }

        Ok(())
    }

    pub fn search(&mut self, query: &str) -> Vec<CorePackage> {
        let query_lower = query.to_lowercase();

        // check cache first - way faster for repeated searches
        if let Some(cached_results) = self.search_cache.get(&query_lower) {
            debug!("Cache hit for search query: {}", query);
            return cached_results.clone();
        }

        debug!(
            "Cache miss for search query: {}, performing full search",
            query
        );
        let mut results = Vec::new();

        for package in self.official_db.packages.values() {
            if package.name.to_lowercase().contains(&query_lower)
                || package.description.to_lowercase().contains(&query_lower)
            {
                results.push(package.clone());
            }
        }

        for package in self.aur_db.packages.values() {
            if package.name.to_lowercase().contains(&query_lower)
                || package.description.to_lowercase().contains(&query_lower)
            {
                results.push(package.clone());
            }
        }

        results.sort_by(|a, b| {
            let a_exact = a.name.to_lowercase() == query_lower;
            let b_exact = b.name.to_lowercase() == query_lower;

            match (a_exact, b_exact) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => {
                    match (
                        a.source_type == SourceType::Official,
                        b.source_type == SourceType::Official,
                    ) {
                        (true, false) => std::cmp::Ordering::Less,
                        (false, true) => std::cmp::Ordering::Greater,
                        _ => a.name.cmp(&b.name),
                    }
                }
            }
        });

        // cache the results for next time
        self.search_cache.insert(query_lower, results.clone());

        results
    }

    pub fn get_package(&self, name: &str) -> Option<&CorePackage> {
        self.official_db
            .packages
            .get(name)
            .or_else(|| self.aur_db.packages.get(name))
    }

    pub fn get_official_package(&self, name: &str) -> Option<&CorePackage> {
        self.official_db.packages.get(name)
    }

    pub fn get_aur_package(&self, name: &str) -> Option<&CorePackage> {
        self.aur_db.packages.get(name)
    }

    pub async fn add_package(&mut self, package: CorePackage) -> PackerResult<()> {
        match package.source_type {
            SourceType::Official => {
                self.official_db
                    .packages
                    .insert(package.name.clone(), package);
                self.official_db.package_count = self.official_db.packages.len();
            }
            SourceType::AUR => {
                self.aur_db.packages.insert(package.name.clone(), package);
                self.aur_db.package_count = self.aur_db.packages.len();
            }
            _ => {
                self.aur_db.packages.insert(package.name.clone(), package);
                self.aur_db.package_count = self.aur_db.packages.len();
            }
        }

        // clear search cache since we added new packages
        self.search_cache.clear();
        self.save_to_disk().await?;
        Ok(())
    }

    pub fn add_package_no_save(&mut self, package: CorePackage) {
        match package.source_type {
            SourceType::Official => {
                self.official_db
                    .packages
                    .insert(package.name.clone(), package);
                self.official_db.package_count = self.official_db.packages.len();
            }
            SourceType::AUR => {
                self.aur_db.packages.insert(package.name.clone(), package);
                self.aur_db.package_count = self.aur_db.packages.len();
            }
            _ => {
                self.aur_db.packages.insert(package.name.clone(), package);
                self.aur_db.package_count = self.aur_db.packages.len();
            }
        }
    }

    pub async fn bulk_add_packages(&mut self, packages: Vec<CorePackage>) -> PackerResult<()> {
        for package in packages {
            self.add_package_no_save(package);
        }
        // clear search cache since we added new packages
        self.search_cache.clear();
        // save once at the end instead of for each package
        self.save_to_disk().await?;
        Ok(())
    }

    pub fn get_stats(&self) -> DatabaseStats {
        DatabaseStats {
            official_packages: self.official_db.package_count,
            aur_packages: self.aur_db.package_count,
            total_packages: self.official_db.package_count + self.aur_db.package_count,
            last_updated: self.last_sync,
            official_status: self.official_db.metadata.sync_status.clone(),
            aur_status: self.aur_db.metadata.sync_status.clone(),
        }
    }

    pub fn search_packages(&self, query: &str) -> Vec<CorePackage> {
        let mut results = Vec::new();
        let query_lower = query.to_lowercase();

        for package in self.official_db.packages.values() {
            if package.name.to_lowercase().contains(&query_lower)
                || package.description.to_lowercase().contains(&query_lower)
            {
                results.push(package.clone());
            }
        }

        for package in self.aur_db.packages.values() {
            if package.name.to_lowercase().contains(&query_lower)
                || package.description.to_lowercase().contains(&query_lower)
            {
                results.push(package.clone());
            }
        }

        results
    }

    pub async fn sync_repositories(&mut self) -> PackerResult<()> {
        info!("Syncing package repositories...");

        self.official_db.metadata.sync_status = SyncStatus::Syncing;
        self.aur_db.metadata.sync_status = SyncStatus::Syncing;

        match self.sync_official_packages().await {
            Ok(count) => {
                info!("Synced {} official packages", count);
                self.official_db.metadata.sync_status = SyncStatus::Fresh;
                self.official_db.last_updated = Utc::now();
            }
            Err(e) => {
                warn!("Failed to sync official packages: {}", e);
                self.official_db.metadata.sync_status = SyncStatus::Failed(e.to_string());
            }
        }

        match self.sync_aur_packages().await {
            Ok(count) => {
                info!("Synced {} AUR packages", count);
                self.aur_db.metadata.sync_status = SyncStatus::Fresh;
                self.aur_db.last_updated = Utc::now();
            }
            Err(e) => {
                warn!("Failed to sync AUR packages: {}", e);
                self.aur_db.metadata.sync_status = SyncStatus::Failed(e.to_string());
            }
        }

        self.last_sync = Some(Utc::now());

        self.save_to_disk().await?;

        info!("Repository sync completed");
        Ok(())
    }

    async fn sync_official_packages(&mut self) -> PackerResult<usize> {
        info!("Syncing official packages from Arch repository APIs");

        // sync from actual arch repo database files
        let client = reqwest::Client::new();
        let mut packages_added = 0;

        // arch repositories we want to sync
        let repos = vec!["core", "extra", "multilib"];

        for repo in repos {
            match self.sync_repo_database(&client, repo).await {
                Ok(count) => {
                    packages_added += count;
                    info!("synced {} packages from {} repo", count, repo);
                }
                Err(e) => {
                    warn!("failed to sync {} repo: {}", repo, e);
                    // fallback to essential packages if sync fails
                    if self.official_db.packages.is_empty() {
                        self.add_essential_packages();
                        packages_added += self.official_db.packages.len();
                    }
                }
            }
        }

        self.official_db.package_count = self.official_db.packages.len();
        Ok(packages_added)
    }

    async fn sync_aur_packages(&mut self) -> PackerResult<usize> {
        info!("syncing popular AUR packages from official stats");

        let client = reqwest::Client::new();
        let mut packages_added = 0;

        // get popular packages from aur statistics
        match self.fetch_popular_aur_packages(&client).await {
            Ok(packages) => {
                for package in packages {
                    if !self.aur_db.packages.contains_key(&package.name) {
                        self.aur_db.packages.insert(package.name.clone(), package);
                        packages_added += 1;
                    }
                }
            }
            Err(e) => {
                warn!("failed to fetch popular packages: {}", e);
                // fallback to category-based search
                packages_added = self.sync_aur_by_categories(&client).await?;
            }
        }

        self.aur_db.package_count = self.aur_db.packages.len();
        info!("aur sync completed: {} packages added", packages_added);
        Ok(packages_added)
    }

    // fetch most popular packages from aur using proper metrics
    async fn fetch_popular_aur_packages(
        &self,
        client: &reqwest::Client,
    ) -> PackerResult<Vec<CorePackage>> {
        let mut packages = Vec::new();

        // search for packages sorted by popularity (votes)
        let search_url = "https://aur.archlinux.org/rpc/?v=5&type=search&by=popularity&arg=";

        // search for broad categories to get popular packages
        let broad_searches = vec![
            "app", "dev", "tool", "lib", "bin", "cli", "gui", "system", "utility",
        ];

        for search_term in broad_searches {
            let url = format!("{}{}", search_url, search_term);

            match client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(results) = json["results"].as_array() {
                                    for result in results.iter().take(20) {
                                        // top 20 from each search term should be enough
                                        if let Some(package) = self.parse_aur_result(result) {
                                            packages.push(package);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("failed to parse json for search '{}': {}", search_term, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to search aur for '{}': {}", search_term, e);
                }
            }

            // be nice to the aur api - dont spam requests
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }

        // remove duplicates and sort by popularity - no point having dupes
        let mut unique_packages = std::collections::HashMap::new();
        for package in packages {
            unique_packages
                .entry(package.name.clone())
                .or_insert(package);
        }

        Ok(unique_packages.into_values().collect())
    }

    // fallback category-based search - more targeted and efficient
    async fn sync_aur_by_categories(&mut self, client: &reqwest::Client) -> PackerResult<usize> {
        let mut packages_added = 0;

        // curated list of actually useful software categories
        let categories = vec![
            "browser",
            "editor",
            "terminal",
            "media",
            "development",
            "security",
            "network",
            "system",
            "graphics",
            "office",
            "science",
            "game",
        ];

        for category in categories {
            let url = format!(
                "https://aur.archlinux.org/rpc/?v=5&type=search&by=popularity&arg={}",
                category
            );

            match client.get(&url).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<serde_json::Value>().await {
                            Ok(json) => {
                                if let Some(results) = json["results"].as_array() {
                                    // only take top 5 from each category to avoid spam - quality over quantity
                                    for result in results.iter().take(5) {
                                        if let Some(package) = self.parse_aur_result(result) {
                                            if !self.aur_db.packages.contains_key(&package.name) {
                                                self.aur_db
                                                    .packages
                                                    .insert(package.name.clone(), package);
                                                packages_added += 1;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("failed to parse category '{}': {}", category, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to search category '{}': {}", category, e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
        }

        Ok(packages_added)
    }

    // sync from actual arch repo database - fetches real package data
    async fn sync_repo_database(
        &mut self,
        client: &reqwest::Client,
        repo: &str,
    ) -> PackerResult<usize> {
        let mirror_url = "https://mirror.rackspace.com/archlinux";
        let db_url = format!("{}/{}/os/x86_64/{}.db", mirror_url, repo, repo);

        info!("fetching database from: {}", db_url);

        let response = client.get(&db_url).send().await?;
        if !response.status().is_success() {
            return Err(crate::error::PackerError::NetworkError(format!(
                "failed to fetch {}.db: {}",
                repo,
                response.status()
            )));
        }

        // download and extract the database
        let db_data = response.bytes().await?;
        let temp_dir = std::env::temp_dir().join(format!("packer_db_{}", repo));
        tokio::fs::create_dir_all(&temp_dir).await?;

        let db_file = temp_dir.join(format!("{}.db", repo));
        tokio::fs::write(&db_file, db_data).await?;

        // extract the database (it's a tar file)
        self.extract_and_parse_db(&db_file, repo).await
    }

    async fn extract_and_parse_db(
        &mut self,
        db_file: &std::path::Path,
        repo: &str,
    ) -> PackerResult<usize> {
        use std::process::Command;

        let extract_dir = db_file
            .parent()
            .unwrap()
            .join(format!("{}_extracted", repo));
        tokio::fs::create_dir_all(&extract_dir).await?;

        // extract the database using tar
        let output = Command::new("tar")
            .arg("-xf")
            .arg(db_file)
            .arg("-C")
            .arg(&extract_dir)
            .output()?;

        if !output.status.success() {
            warn!(
                "failed to extract database: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(0);
        }

        // parse the extracted files
        let mut packages_added = 0;
        let mut entries = tokio::fs::read_dir(&extract_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                if let Some(mut package) = self.parse_package_dir(&entry.path()).await? {
                    package.repository = repo.to_string();
                    self.official_db
                        .packages
                        .insert(package.name.clone(), package);
                    packages_added += 1;
                }
            }
        }

        // cleanup
        let _ = tokio::fs::remove_dir_all(&extract_dir).await;
        let _ = tokio::fs::remove_file(db_file).await;

        Ok(packages_added)
    }

    async fn parse_package_dir(
        &self,
        package_dir: &std::path::Path,
    ) -> PackerResult<Option<CorePackage>> {
        let desc_file = package_dir.join("desc");

        if !desc_file.exists() {
            return Ok(None);
        }

        let desc_content = tokio::fs::read_to_string(&desc_file).await?;
        let mut package = CorePackage {
            name: String::new(),
            version: String::new(),
            description: String::new(),
            repository: String::new(),
            arch: "x86_64".to_string(),
            download_size: 0,
            installed_size: 0,
            dependencies: Vec::new(),
            conflicts: Vec::new(),
            maintainer: "Arch Linux Team".to_string(),
            url: String::new(),
            checksum: None,
            source_type: crate::core::SourceType::Official,
            install_date: None,
        };

        // parse the desc file format
        let lines: Vec<&str> = desc_content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            if line.starts_with('%') && line.ends_with('%') {
                let field = &line[1..line.len() - 1];
                i += 1;

                match field {
                    "NAME" => {
                        if i < lines.len() {
                            package.name = lines[i].trim().to_string();
                        }
                    }
                    "VERSION" => {
                        if i < lines.len() {
                            package.version = lines[i].trim().to_string();
                        }
                    }
                    "DESC" => {
                        if i < lines.len() {
                            package.description = lines[i].trim().to_string();
                        }
                    }
                    "CSIZE" => {
                        if i < lines.len() {
                            package.download_size = lines[i]
                                .trim()
                                .parse()
                                .map_err(|e| {
                                    warn!("Failed to parse CSIZE for {}: {}", package.name, e)
                                })
                                .unwrap_or(0);
                        }
                    }
                    "ISIZE" => {
                        if i < lines.len() {
                            package.installed_size = lines[i]
                                .trim()
                                .parse()
                                .map_err(|e| {
                                    warn!("Failed to parse ISIZE for {}: {}", package.name, e)
                                })
                                .unwrap_or(0);
                        }
                    }
                    "URL" => {
                        if i < lines.len() {
                            package.url = lines[i].trim().to_string();
                        }
                    }
                    "DEPENDS" => {
                        // read dependencies until empty line or next field
                        while i < lines.len()
                            && !lines[i].trim().is_empty()
                            && !lines[i].starts_with('%')
                        {
                            package.dependencies.push(lines[i].trim().to_string());
                            i += 1;
                        }
                        i -= 1; // adjust for the increment at the end of the loop
                    }
                    "CONFLICTS" => {
                        // read conflicts until empty line or next field
                        while i < lines.len()
                            && !lines[i].trim().is_empty()
                            && !lines[i].starts_with('%')
                        {
                            package.conflicts.push(lines[i].trim().to_string());
                            i += 1;
                        }
                        i -= 1; // adjust for the increment at the end of the loop
                    }
                    _ => {}
                }
            }
            i += 1;
        }

        // skip empty packages
        if package.name.is_empty() {
            return Ok(None);
        }

        Ok(Some(package))
    }

    // fallback function for when real sync fails
    fn add_essential_packages(&mut self) {
        warn!("using fallback essential packages - real sync failed");

        // minimal essential packages as fallback
        let essential_packages = vec![
            ("bash", "The GNU Bourne Again Shell"),
            (
                "coreutils",
                "The basic file, shell and text manipulation utilities",
            ),
            ("wget", "Network utility to retrieve files from the Web"),
            ("curl", "An URL retrieval utility and library"),
            ("git", "Fast distributed version control system"),
            ("nano", "Small and friendly text editor"),
            ("vim", "Vi Improved, a highly configurable text editor"),
            ("htop", "Interactive process viewer for Unix"),
            (
                "tree",
                "Directory listing program displaying tree-like structure",
            ),
            ("firefox", "Fast, Private & Safe Web Browser"),
        ];

        for (name, description) in essential_packages {
            let package = CorePackage {
                name: name.to_string(),
                version: "latest".to_string(),
                description: description.to_string(),
                repository: "fallback".to_string(),
                arch: "x86_64".to_string(),
                download_size: 0,
                installed_size: 0,
                dependencies: Vec::new(),
                conflicts: Vec::new(),
                maintainer: "Arch Linux Team".to_string(),
                url: String::new(),
                checksum: None,
                source_type: crate::core::SourceType::Official,
                install_date: None,
            };
            self.official_db.packages.insert(name.to_string(), package);
        }
    }

    fn _parse_pacman_list_line(&self, line: &str) -> Option<CorePackage> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let repository = parts[0].to_string();
        let name = parts[1].to_string();
        let version = parts[2].to_string();

        Some(CorePackage {
            name,
            version,
            description: String::new(),
            repository,
            arch: "x86_64".to_string(),
            download_size: 0,
            installed_size: 0,
            dependencies: Vec::new(),
            conflicts: Vec::new(),
            maintainer: "Arch Linux Team".to_string(),
            url: String::new(),
            checksum: None,
            source_type: SourceType::Official,
            install_date: None,
        })
    }

    fn parse_aur_result(&self, result: &serde_json::Value) -> Option<CorePackage> {
        let name = result["Name"].as_str()?.to_string();
        let version = result["Version"].as_str().unwrap_or("unknown").to_string();
        let description = result["Description"].as_str().unwrap_or("").to_string();
        let maintainer = result["Maintainer"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let url = result["URL"].as_str().unwrap_or("").to_string();

        Some(CorePackage {
            name,
            version,
            description,
            repository: "aur".to_string(),
            arch: "x86_64".to_string(),
            download_size: 0,
            installed_size: 0,
            dependencies: Vec::new(),
            conflicts: Vec::new(),
            maintainer,
            url,
            checksum: None,
            source_type: SourceType::AUR,
            install_date: None,
        })
    }

    fn should_sync(&self) -> bool {
        match self.last_sync {
            Some(last_sync) => {
                let now = Utc::now();
                now.signed_duration_since(last_sync) > self.sync_interval
            }
            None => true,
        }
    }

    async fn load_from_disk(&mut self) -> PackerResult<()> {
        debug!("Loading database from disk: {}", self.db_path.display());

        let content = fs::read_to_string(&self.db_path).await?;
        let db_file: DatabaseFile = serde_json::from_str(&content)?;

        self.official_db = db_file.official_repo;
        self.aur_db = db_file.aur_repo;
        self.last_sync = Some(db_file.last_updated);

        info!(
            "Loaded database: {} official packages, {} AUR packages",
            self.official_db.package_count, self.aur_db.package_count
        );

        Ok(())
    }

    pub async fn save_to_disk(&self) -> PackerResult<()> {
        debug!("Saving database to disk: {}", self.db_path.display());

        let db_file = DatabaseFile {
            version: "1.0".to_string(),
            created: Utc::now(),
            last_updated: self.last_sync.unwrap_or_else(Utc::now),
            official_repo: self.official_db.clone(),
            aur_repo: self.aur_db.clone(),
        };

        let content = serde_json::to_string_pretty(&db_file)?;
        fs::write(&self.db_path, content).await?;

        debug!("Database saved successfully");
        Ok(())
    }

    pub async fn force_sync(&mut self) -> PackerResult<()> {
        self.last_sync = None;
        self.sync_repositories().await
    }

    pub fn is_stale(&self) -> bool {
        self.should_sync()
    }

    pub fn get_age(&self) -> Option<chrono::Duration> {
        match self.last_sync {
            Some(last_sync) => {
                let now = Utc::now();
                Some(now.signed_duration_since(last_sync))
            }
            None => None,
        }
    }

    pub async fn clear_cache(&mut self) -> PackerResult<()> {
        info!("Clearing package database cache");

        self.official_db.packages.clear();
        self.aur_db.packages.clear();
        self.official_db.package_count = 0;
        self.aur_db.package_count = 0;
        self.last_sync = None;

        if self.db_path.exists() {
            fs::remove_file(&self.db_path).await?;
        }

        Ok(())
    }
}

impl PackageRepository {
    fn new(name: String) -> Self {
        Self {
            name: name.clone(),
            packages: HashMap::new(),
            last_updated: Utc::now(),
            package_count: 0,
            metadata: RepositoryMetadata {
                total_size: 0,
                architecture: "x86_64".to_string(),
                source_url: format!("native://{}", name),
                sync_status: SyncStatus::Stale,
            },
        }
    }
}

#[derive(Debug)]
pub struct DatabaseStats {
    pub official_packages: usize,
    pub aur_packages: usize,
    pub total_packages: usize,
    pub last_updated: Option<DateTime<Utc>>,
    pub official_status: SyncStatus,
    pub aur_status: SyncStatus,
}
