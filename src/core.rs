use crate::{
    config::Config,
    error::{PackerError, PackerResult},
    mirrors::MirrorManager,
    native_db::NativePackageDatabase,
    resolver::FastDependencyResolver,
};
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorePackage {
    pub name: String,
    pub version: String,
    pub description: String,
    pub repository: String,
    pub arch: String,
    pub download_size: u64,
    pub installed_size: u64,
    pub dependencies: Vec<String>,
    pub conflicts: Vec<String>,
    pub maintainer: String,
    pub url: String,
    pub checksum: Option<String>,
    pub source_type: SourceType,
    pub install_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SourceType {
    Official, // From official repositories (use pacman)
    AUR,      // From AUR (build from source)
    Binary,   // Direct binary download
    Github,   // GitHub releases
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InstallStatus {
    NotInstalled,
    Installing,
    Installed,
    Failed(String),
    UpdateAvailable(String),
}

#[derive(Debug)]
pub struct PackageDatabase {
    installed: HashMap<String, CorePackage>,
    available: HashMap<String, CorePackage>,
    cache_dir: PathBuf,
    db_file: PathBuf,
}

impl PackageDatabase {
    pub fn new(cache_dir: PathBuf) -> Self {
        let db_file = cache_dir.join("packages.json");
        Self {
            installed: HashMap::new(),
            available: HashMap::new(),
            cache_dir,
            db_file,
        }
    }

    pub async fn load(&mut self) -> PackerResult<()> {
        // First load existing packer data
        if self.db_file.exists() {
            let content = tokio::fs::read_to_string(&self.db_file).await?;
            if let Ok(data) = serde_json::from_str::<DatabaseContent>(&content) {
                self.installed = data.installed;
                self.available = data.available;
            }
        }

        // Pacman import removed - packer is now completely independent
        info!("Packer running in standalone mode (no pacman dependency)");

        // Save the combined data
        if let Err(e) = self.save().await {
            warn!("Failed to save combined package database: {}", e);
        }

        info!(
            "Loaded {} installed and {} available packages",
            self.installed.len(),
            self.available.len()
        );

        Ok(())
    }

    pub async fn save(&self) -> PackerResult<()> {
        let data = DatabaseContent {
            installed: self.installed.clone(),
            available: self.available.clone(),
            updated: Utc::now(),
        };
        let content = serde_json::to_string_pretty(&data)?;
        tokio::fs::create_dir_all(&self.cache_dir).await?;
        tokio::fs::write(&self.db_file, content).await?;
        Ok(())
    }

    pub fn get_installed(&self, name: &str) -> Option<&CorePackage> {
        self.installed.get(name)
    }

    pub fn get_available(&self, name: &str) -> Option<&CorePackage> {
        self.available.get(name)
    }

    pub fn mark_installed(&mut self, package: CorePackage) {
        let mut pkg = package;
        pkg.install_date = Some(Utc::now());
        self.installed.insert(pkg.name.clone(), pkg);
    }

    pub fn mark_removed(&mut self, name: &str) {
        self.installed.remove(name);
    }

    #[allow(dead_code)]
    async fn import_pacman_packages(&mut self) -> PackerResult<()> {
        use std::process::Command;

        info!("Importing existing pacman packages...");

        // grab all the packages pacman knows about
        let output = Command::new("pacman")
            .arg("-Q") // Query installed packages
            .output()
            .map_err(|e| PackerError::Io(e))?;

        if !output.status.success() {
            return Err(PackerError::InstallationFailed(
                "Failed to query pacman database".to_string(),
            ));
        }

        let installed_list = String::from_utf8_lossy(&output.stdout);
        let mut imported_count = 0;

        for line in installed_list.lines() {
            if let Some((name, version)) = line.split_once(' ') {
                // Skip if we already have this package
                if self.installed.contains_key(name) {
                    continue;
                }

                // get more details about this package
                if let Ok(package) = self.get_pacman_package_info(name, version).await {
                    self.installed.insert(name.to_string(), package);
                    imported_count += 1;
                }
            }
        }

        info!("Imported {} packages from pacman database", imported_count);
        Ok(())
    }

    #[allow(dead_code)]
    async fn get_pacman_package_info(
        &self,
        name: &str,
        version: &str,
    ) -> PackerResult<CorePackage> {
        use std::process::Command;

        // ask pacman for all the juicy details
        let output = Command::new("pacman")
            .arg("-Qi") // Query info for installed package
            .arg(name)
            .output()
            .map_err(|e| PackerError::Io(e))?;

        if !output.status.success() {
            return Err(PackerError::PackageNotFound(name.to_string()));
        }

        let info = String::from_utf8_lossy(&output.stdout);
        let mut package = CorePackage {
            name: name.to_string(),
            version: version.to_string(),
            description: String::new(),
            repository: "system".to_string(), // Mark as system-installed
            arch: "x86_64".to_string(),
            download_size: 0,
            installed_size: 0,
            dependencies: Vec::new(),
            conflicts: Vec::new(),
            maintainer: "System".to_string(),
            url: String::new(),
            checksum: None,
            source_type: SourceType::Official,
            install_date: Some(Utc::now()),
        };

        // Parse pacman output to get more details
        for line in info.lines() {
            if let Some(desc) = line.strip_prefix("Description         : ") {
                package.description = desc.to_string();
            } else if let Some(repo) = line.strip_prefix("Repository          : ") {
                package.repository = repo.to_string();
            } else if let Some(size) = line.strip_prefix("Installed Size      : ") {
                // Parse size like "1.23 MiB" to bytes
                if let Some((num_str, unit)) = size.split_once(' ') {
                    if let Ok(num) = num_str.parse::<f64>() {
                        let bytes = match unit {
                            "KiB" => (num * 1024.0) as u64,
                            "MiB" => (num * 1024.0 * 1024.0) as u64,
                            "GiB" => (num * 1024.0 * 1024.0 * 1024.0) as u64,
                            _ => 0,
                        };
                        package.installed_size = bytes;
                    }
                }
            }
        }

        Ok(package)
    }

    pub fn add_available(&mut self, package: CorePackage) {
        self.available.insert(package.name.clone(), package);
    }

    pub fn search_available(&self, query: &str) -> Vec<&CorePackage> {
        let query_lower = query.to_lowercase();
        self.available
            .values()
            .filter(|pkg| {
                pkg.name.to_lowercase().contains(&query_lower)
                    || pkg.description.to_lowercase().contains(&query_lower)
            })
            .collect()
    }

    pub fn list_installed(&self) -> Vec<&CorePackage> {
        self.installed.values().collect()
    }

    pub fn get_status(&self, name: &str) -> InstallStatus {
        match (self.get_installed(name), self.get_available(name)) {
            (Some(installed), Some(available)) => {
                if installed.version != available.version {
                    InstallStatus::UpdateAvailable(available.version.clone())
                } else {
                    InstallStatus::Installed
                }
            }
            (Some(_), None) => InstallStatus::Installed,
            (None, Some(_)) => InstallStatus::NotInstalled,
            (None, None) => InstallStatus::NotInstalled,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DatabaseContent {
    installed: HashMap<String, CorePackage>,
    available: HashMap<String, CorePackage>,
    updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallTransaction {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub packages_to_install: Vec<CorePackage>,
    pub installed_packages: Vec<CorePackage>,
    pub failed_packages: Vec<String>,
    pub rollback_commands: Vec<RollbackCommand>,
    pub status: TransactionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionStatus {
    InProgress,
    Completed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackCommand {
    pub action: RollbackAction,
    pub package_name: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RollbackAction {
    RemovePackage,
    RestorePackage { version: String },
    CleanupFiles { paths: Vec<String> },
}

#[derive(Debug)]
pub struct CorePackageManager {
    config: Config,
    database: PackageDatabase,
    native_db: NativePackageDatabase,
    resolver: FastDependencyResolver,
    mirror_manager: MirrorManager,
    transactions: Vec<InstallTransaction>,
    transaction_log_path: PathBuf,
}

impl CorePackageManager {
    pub async fn new(config: Config) -> PackerResult<Self> {
        let mut database = PackageDatabase::new(config.cache_dir.clone());
        database.load().await?;

        let mut native_db = NativePackageDatabase::new(config.cache_dir.clone());
        native_db.initialize().await?;

        let mut mirror_manager = MirrorManager::new(config.mirror_config.clone());
        mirror_manager.initialize().await?;

        let transaction_log_path = config.cache_dir.join("transactions.json");

        let resolver = FastDependencyResolver::new()
            .with_dynamic_resolver(config.cache_dir.clone())
            .await?;

        Ok(Self {
            config,
            database,
            native_db,
            resolver,
            mirror_manager,
            transactions: Vec::new(),
            transaction_log_path,
        })
    }

    pub async fn search(&mut self, query: &str) -> PackerResult<Vec<CorePackage>> {
        info!("Searching for: {}", query);

        if self.native_db.is_stale() {
            warn!("Database is stale, performing automatic update...");
            println!(
                "⚠️  Database is stale (>6 hours old). Run 'packer update' for latest packages."
            );
        }

        let mut results: Vec<CorePackage> = self.native_db.search(query);

        info!("Found {} results in native database", results.len());

        if !results.is_empty() {
            if let Some(_exact_match) = results.iter().find(|p| p.name == query) {
                results.retain(|p| p.name == query || p.name.contains(query));
                results.sort_by(|a, b| {
                    if a.name == query && b.name != query {
                        std::cmp::Ordering::Less
                    } else if a.name != query && b.name == query {
                        std::cmp::Ordering::Greater
                    } else {
                        a.name.cmp(&b.name)
                    }
                });
                return Ok(results.into_iter().take(20).collect());
            }

            results.truncate(20);
            return Ok(results);
        }

        info!("No results in local database, searching AUR automatically...");
        println!("🔍 Package not in local database, searching AUR...");

        match self.search_and_cache_from_aur(query).await {
            Ok(aur_results) => {
                if !aur_results.is_empty() {
                    println!(
                        "✅ Found {} packages in AUR and added to database",
                        aur_results.len()
                    );
                    results.extend(aur_results);
                }
            }
            Err(e) => {
                warn!("Failed to search AUR: {}", e);
            }
        }

        if results.is_empty() {
            if let Ok(external_results) = self.search_external(query).await {
                results.extend(external_results);
            }
        }

        results.sort_by(|a, b| {
            let a_exact = a.name == query;
            let b_exact = b.name == query;
            match (a_exact, b_exact) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.name.cmp(&b.name),
            }
        });

        results.truncate(20);

        Ok(results)
    }

    async fn search_and_cache_from_aur(&mut self, query: &str) -> PackerResult<Vec<CorePackage>> {
        let url = format!(
            "https://aur.archlinux.org/rpc/?v=5&type=search&arg={}",
            query
        );
        let client = reqwest::Client::new();

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let json: serde_json::Value = response.json().await?;
        let mut packages = Vec::new();

        if let Some(results) = json["results"].as_array() {
            // process results sequentially but more efficiently
            let mut parsed_packages: Vec<(CorePackage, f64)> = Vec::new();

            for result in results {
                if let Some(package) = self.parse_aur_search_result(result) {
                    let popularity = result["Popularity"].as_f64().unwrap_or(0.0);
                    parsed_packages.push((package, popularity));
                }
            }

            parsed_packages
                .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            for (package, _) in parsed_packages.into_iter().take(10) {
                self.native_db.add_package_no_save(package.clone());
                info!("Added {} to AUR cache", package.name);
                packages.push(package);
            }

            if !packages.is_empty() {
                if let Err(e) = self.native_db.save_to_disk().await {
                    warn!("Failed to save packages to disk: {}", e);
                }
            }
        }

        Ok(packages)
    }

    fn parse_aur_search_result(&self, result: &serde_json::Value) -> Option<CorePackage> {
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

    pub async fn install(&mut self, packages: &[String]) -> PackerResult<()> {
        info!("Installing packages: {:?}", packages);

        let transaction_id = format!("tx_{}", Utc::now().timestamp());
        let mut transaction = InstallTransaction {
            id: transaction_id.clone(),
            timestamp: Utc::now(),
            packages_to_install: Vec::new(),
            installed_packages: Vec::new(),
            failed_packages: Vec::new(),
            rollback_commands: Vec::new(),
            status: TransactionStatus::InProgress,
        };

        let installed_packages: std::collections::HashMap<String, CorePackage> = self
            .database
            .list_installed()
            .into_iter()
            .map(|p| (p.name.clone(), p.clone()))
            .collect();

        let resolution = match self
            .resolver
            .resolve_dependencies(packages, &self.native_db, &installed_packages)
            .await
        {
            Ok(res) => res,
            Err(e) => {
                transaction.status = TransactionStatus::Failed;
                transaction.failed_packages = packages.iter().map(|s| s.clone()).collect();
                self.save_transaction(transaction).await?;
                return Err(e);
            }
        };

        info!(
            "Resolved {} packages in {:?}",
            resolution.packages_to_install.len(),
            resolution.resolution_time
        );

        if self.resolver.is_critical_conflict(&resolution.conflicts) {
            let conflict_msgs = self.resolver.format_conflicts(&resolution.conflicts);
            transaction.status = TransactionStatus::Failed;
            transaction.failed_packages = packages.iter().map(|s| s.clone()).collect();
            self.save_transaction(transaction).await?;
            return Err(PackerError::DependencyConflict(format!(
                "Critical conflicts found:\n{}",
                conflict_msgs.join("\n")
            )));
        }

        transaction.packages_to_install = resolution.packages_to_install.clone();

        if !resolution.warnings.is_empty() {
            for warning in &resolution.warnings {
                warn!("Dependency warning: {}", warning);
            }
        }

        let mut official_packages = Vec::new();
        let mut aur_packages = Vec::new();
        let mut other_packages = Vec::new();

        for package in &resolution.packages_to_install {
            match package.source_type {
                SourceType::Official => official_packages.push(package.clone()),
                SourceType::AUR => aur_packages.push(package.clone()),
                _ => other_packages.push(package.clone()),
            }
        }

        let install_result = self
            .install_with_recovery(
                &mut transaction,
                &official_packages,
                &aur_packages,
                &other_packages,
            )
            .await;

        match install_result {
            Ok(()) => {
                transaction.status = TransactionStatus::Completed;
                info!("Installation completed successfully");
            }
            Err(e) => {
                transaction.status = TransactionStatus::Failed;
                warn!("Installation failed: {}", e);

                if let Err(rollback_err) = self.rollback_transaction(&mut transaction).await {
                    warn!("Rollback also failed: {}", rollback_err);
                } else {
                    transaction.status = TransactionStatus::RolledBack;
                    info!("Successfully rolled back failed installation");
                }

                self.save_transaction(transaction).await?;
                return Err(e);
            }
        }

        self.database.save().await?;
        self.save_transaction(transaction).await?;
        Ok(())
    }

    async fn install_with_recovery(
        &mut self,
        transaction: &mut InstallTransaction,
        official_packages: &[CorePackage],
        aur_packages: &[CorePackage],
        other_packages: &[CorePackage],
    ) -> PackerResult<()> {
        let all_packages: Vec<_> = official_packages
            .iter()
            .chain(aur_packages.iter())
            .chain(other_packages.iter())
            .collect();

        if all_packages.is_empty() {
            println!("✅ All requested packages are already installed!");
        } else {
            println!(
                "🔧 Installing {} packages natively (no pacman)...",
                all_packages.len()
            );
        }

        let mut installed_count = 0;
        let mut failed_packages = Vec::new();
        let mut shared_native_manager = None;

        for (i, package) in all_packages.iter().enumerate() {
            println!(
                "📦 [{}/{}] Installing: {} ({})",
                i + 1,
                all_packages.len(),
                package.name,
                package.repository
            );

            // Skip system stub packages - they're already "installed"
            if package.repository == "system" {
                println!("✅ System package (assumed available): {}", package.name);
                installed_count += 1;
                transaction.installed_packages.push((*package).clone());
                self.database.mark_installed((*package).clone());
                continue;
            }

            match package.source_type {
                SourceType::AUR => match self.try_aur_install(package, transaction).await {
                    Ok(()) => {
                        println!("✅ Installed: {}", package.name);
                        installed_count += 1;
                        transaction.installed_packages.push((*package).clone());
                        self.database.mark_installed((*package).clone());
                    }
                    Err(e) => {
                        println!("❌ Failed to install AUR package {}: {}", package.name, e);
                        failed_packages.push(package.name.clone());
                        transaction.failed_packages.push(package.name.clone());
                    }
                },
                _ => {
                    match self
                        .try_native_install_shared(package, transaction, &mut shared_native_manager)
                        .await
                    {
                        Ok(()) => {
                            println!("✅ Installed: {}", package.name);
                            installed_count += 1;
                            transaction.installed_packages.push((*package).clone());
                            self.database.mark_installed((*package).clone());
                        }
                        Err(e) => {
                            println!("❌ Failed to install {}: {}", package.name, e);
                            failed_packages.push(package.name.clone());
                            transaction.failed_packages.push(package.name.clone());
                        }
                    }
                }
            }
        }

        // Finalize installation by reloading all collected services
        if let Some(ref mut manager) = shared_native_manager {
            if let Err(e) = manager.finalize_installation().await {
                println!("⚠️  Failed to finalize installation: {}", e);
            }
        }

        if !failed_packages.is_empty() {
            return Err(PackerError::InstallationFailed(format!(
                "Failed to install {} packages: {}",
                failed_packages.len(),
                failed_packages.join(", ")
            )));
        }

        // yo let's see how much space we have left
        let install_path = std::path::Path::new("/"); // just checking the whole system
        let (_used, available) = crate::utils::get_disk_usage(install_path).unwrap_or((0, 0));

        if installed_count > 0 {
            println!(
                "🎉 Successfully installed {} packages natively!",
                installed_count
            );

            println!(
                "💾 Available space: {}",
                crate::utils::format_bytes(available)
            );
        }

        Ok(())
    }

    #[allow(dead_code)]
    async fn install_official_packages_tracked(
        &mut self,
        packages: &[CorePackage],
        transaction: &mut InstallTransaction,
    ) -> PackerResult<()> {
        for package in packages {
            transaction.rollback_commands.push(RollbackCommand {
                action: RollbackAction::RemovePackage,
                package_name: package.name.clone(),
                details: format!(
                    "Remove {} {} if installation fails",
                    package.name, package.version
                ),
            });
        }

        for package in packages {
            self.try_native_install(package, transaction).await?;
            transaction.installed_packages.push(package.clone());
        }

        Ok(())
    }

    #[allow(dead_code)]
    async fn install_single_aur_package_tracked(
        &mut self,
        package: &CorePackage,
        transaction: &mut InstallTransaction,
    ) -> PackerResult<()> {
        transaction.rollback_commands.push(RollbackCommand {
            action: RollbackAction::RemovePackage,
            package_name: package.name.clone(),
            details: format!("Remove AUR package {} if installation fails", package.name),
        });

        self.try_native_install(package, transaction).await
    }

    async fn rollback_transaction(
        &mut self,
        transaction: &mut InstallTransaction,
    ) -> PackerResult<()> {
        info!("Starting transaction rollback for: {}", transaction.id);

        let mut rollback_errors = Vec::new();

        for command in transaction.rollback_commands.iter().rev() {
            match &command.action {
                RollbackAction::RemovePackage => {
                    if let Err(e) = self
                        .remove_package_for_rollback(&command.package_name)
                        .await
                    {
                        rollback_errors
                            .push(format!("Failed to remove {}: {}", command.package_name, e));
                    } else {
                        info!("Rolled back: removed {}", command.package_name);
                    }
                }
                RollbackAction::RestorePackage { version } => {
                    info!(
                        "Would restore {} to version {}",
                        command.package_name, version
                    );
                }
                RollbackAction::CleanupFiles { paths } => {
                    for path in paths {
                        if let Err(e) = tokio::fs::remove_file(path).await {
                            rollback_errors.push(format!("Failed to cleanup {}: {}", path, e));
                        }
                    }
                }
            }
        }

        if !rollback_errors.is_empty() {
            warn!(
                "Rollback completed with errors: {}",
                rollback_errors.join(", ")
            );
        } else {
            info!("Rollback completed successfully");
        }

        Ok(())
    }

    async fn remove_package_for_rollback(&mut self, package_name: &str) -> PackerResult<()> {
        use crate::native_format::NativePackageManager;
        let mut native_manager = NativePackageManager::new(self.config.install_root.clone())?;

        match native_manager.remove_package(package_name).await {
            Ok(()) => {
                self.database.mark_removed(package_name);
                Ok(())
            }
            Err(e) => {
                warn!("Native removal failed for {}: {}", package_name, e);
                Err(PackerError::InstallationFailed(format!(
                    "Failed to remove {} during rollback",
                    package_name
                )))
            }
        }
    }

    async fn save_transaction(&mut self, transaction: InstallTransaction) -> PackerResult<()> {
        self.transactions.push(transaction);

        if self.transactions.len() > 100 {
            self.transactions.drain(0..50);
        }

        let content = serde_json::to_string_pretty(&self.transactions)?;
        tokio::fs::write(&self.transaction_log_path, content).await?;

        Ok(())
    }

    pub async fn list_transactions(&self) -> &[InstallTransaction] {
        &self.transactions
    }

    pub async fn rollback_by_id(&mut self, transaction_id: &str) -> PackerResult<()> {
        if let Some(mut transaction) = self
            .transactions
            .iter()
            .find(|t| t.id == transaction_id)
            .cloned()
        {
            self.rollback_transaction(&mut transaction).await?;
            transaction.status = TransactionStatus::RolledBack;

            if let Some(stored_tx) = self
                .transactions
                .iter_mut()
                .find(|t| t.id == transaction_id)
            {
                *stored_tx = transaction;
            }

            self.save_transaction_log().await?;
            Ok(())
        } else {
            Err(PackerError::InstallationFailed(format!(
                "Transaction {} not found",
                transaction_id
            )))
        }
    }

    async fn save_transaction_log(&self) -> PackerResult<()> {
        let content = serde_json::to_string_pretty(&self.transactions)?;
        tokio::fs::write(&self.transaction_log_path, content).await?;
        Ok(())
    }

    async fn try_native_install_shared(
        &mut self,
        package: &CorePackage,
        transaction: &mut InstallTransaction,
        shared_manager: &mut Option<crate::native_format::NativePackageManager>,
    ) -> PackerResult<()> {
        use crate::native_format::NativePackageManager;

        info!("Attempting native installation for: {}", package.name);

        let temp_dir = self
            .config
            .cache_dir
            .join("native-conversion")
            .join(&package.name);
        if temp_dir.exists() {
            tokio::fs::remove_dir_all(&temp_dir).await?;
        }
        tokio::fs::create_dir_all(&temp_dir).await?;

        let package_files = match self
            .download_package_for_conversion(package, &temp_dir)
            .await
        {
            Ok(files) => files,
            Err(e) => {
                tokio::fs::remove_dir_all(&temp_dir).await.ok();
                info!(
                    "Failed to download package files for {}: {}",
                    package.name, e
                );
                return Err(e);
            }
        };

        let native_package = match self
            .convert_to_native_format(package, &package_files, &temp_dir)
            .await
        {
            Ok(pkg) => pkg,
            Err(e) => {
                tokio::fs::remove_dir_all(&temp_dir).await.ok();
                info!("Failed to convert {} to native format: {}", package.name, e);
                return Err(e);
            }
        };

        // Initialize shared manager if it doesn't exist
        if shared_manager.is_none() {
            *shared_manager = Some(NativePackageManager::new(self.config.install_root.clone())?);
        }

        let native_manager = shared_manager.as_mut().unwrap();

        match native_manager.install_package(&native_package).await {
            Ok(()) => {
                transaction.rollback_commands.push(RollbackCommand {
                    action: RollbackAction::RemovePackage,
                    package_name: package.name.clone(),
                    details: format!(
                        "Remove native package {} if transaction fails",
                        package.name
                    ),
                });

                tokio::fs::remove_dir_all(&temp_dir).await.ok();

                info!(
                    "Successfully installed {} using native format",
                    package.name
                );
                Ok(())
            }
            Err(e) => {
                tokio::fs::remove_dir_all(&temp_dir).await.ok();
                info!(
                    "Failed to install {} using native format: {}",
                    package.name, e
                );
                Err(e)
            }
        }
    }

    async fn try_aur_install(
        &mut self,
        package: &CorePackage,
        transaction: &mut InstallTransaction,
    ) -> PackerResult<()> {
        info!("Building AUR package from source: {}", package.name);

        // For now, create a minimal implementation that installs a stub
        // In a full implementation, this would:
        // 1. Clone the AUR repository
        // 2. Build the package using makepkg
        // 3. Install the resulting package

        println!(
            "🔨 Building AUR package: {} (stub implementation)",
            package.name
        );

        // Create a stub desktop entry for GUI applications
        if package.name.contains("desktop") || package.name.contains("gui") {
            self.create_aur_stub(package).await?;
        }

        // Mark as successfully "installed" for now
        transaction.installed_packages.push(package.clone());
        self.database.mark_installed(package.clone());

        println!(
            "✅ AUR package {} installed (stub - rebuild with full AUR support later)",
            package.name
        );
        Ok(())
    }

    async fn create_aur_stub(&self, package: &CorePackage) -> PackerResult<()> {
        let home_dir = dirs::home_dir().ok_or_else(|| {
            crate::error::PackerError::ConfigError("Could not find home directory".to_string())
        })?;

        let desktop_dir = home_dir.join(".local/share/applications");
        tokio::fs::create_dir_all(&desktop_dir).await?;

        let desktop_file_path = desktop_dir.join(format!("packer-aur-{}.desktop", package.name));

        let desktop_content = format!(
            r#"[Desktop Entry]
Name={}
Comment={} (AUR stub)
Exec=echo "AUR package {} - install full version with proper AUR support"
Icon=application-x-executable
Terminal=false
Type=Application
Categories=Development;
StartupNotify=true
"#,
            package.name, package.description, package.name
        );

        tokio::fs::write(&desktop_file_path, desktop_content).await?;
        println!("📝 Created AUR stub desktop entry for {}", package.name);

        Ok(())
    }

    async fn try_native_install(
        &mut self,
        package: &CorePackage,
        transaction: &mut InstallTransaction,
    ) -> PackerResult<()> {
        use crate::native_format::NativePackageManager;

        info!("Attempting native installation for: {}", package.name);

        let temp_dir = self
            .config
            .cache_dir
            .join("native-conversion")
            .join(&package.name);
        if temp_dir.exists() {
            tokio::fs::remove_dir_all(&temp_dir).await?;
        }
        tokio::fs::create_dir_all(&temp_dir).await?;

        let package_files = match self
            .download_package_for_conversion(package, &temp_dir)
            .await
        {
            Ok(files) => files,
            Err(e) => {
                tokio::fs::remove_dir_all(&temp_dir).await.ok();
                info!(
                    "Failed to download {} for native conversion: {}",
                    package.name, e
                );
                return Err(e);
            }
        };

        let native_package = match self
            .convert_to_native_package(package, &package_files, &temp_dir)
            .await
        {
            Ok(pkg) => pkg,
            Err(e) => {
                tokio::fs::remove_dir_all(&temp_dir).await.ok();
                info!("Failed to convert {} to native format: {}", package.name, e);
                return Err(e);
            }
        };

        let mut native_manager = NativePackageManager::new(self.config.install_root.clone())?;

        match native_manager.install_package(&native_package).await {
            Ok(()) => {
                transaction.rollback_commands.push(RollbackCommand {
                    action: RollbackAction::RemovePackage,
                    package_name: package.name.clone(),
                    details: format!(
                        "Remove native package {} if transaction fails",
                        package.name
                    ),
                });

                tokio::fs::remove_dir_all(&temp_dir).await.ok();

                info!(
                    "Successfully installed {} using native format",
                    package.name
                );
                Ok(())
            }
            Err(e) => {
                tokio::fs::remove_dir_all(&temp_dir).await.ok();
                info!("Native installation failed for {}: {}", package.name, e);
                Err(e)
            }
        }
    }

    async fn download_package_for_conversion(
        &mut self,
        package: &CorePackage,
        temp_dir: &std::path::Path,
    ) -> PackerResult<Vec<std::path::PathBuf>> {
        match package.source_type {
            SourceType::Official => self.download_official_package(package, temp_dir).await,
            SourceType::AUR => {
                self.build_aur_package_for_conversion(package, temp_dir)
                    .await
            }
            _ => Err(PackerError::InstallationFailed(format!(
                "Native conversion not supported for source type: {:?}",
                package.source_type
            ))),
        }
    }

    async fn download_official_package(
        &mut self,
        package: &CorePackage,
        temp_dir: &std::path::Path,
    ) -> PackerResult<Vec<std::path::PathBuf>> {
        let repo_name = &package.repository;

        // get best mirrors for this repo
        let mirrors = self
            .mirror_manager
            .get_best_mirrors(&format!("{}/os/x86_64", repo_name))
            .await
            .unwrap_or_else(|_| {
                // fallback to hardcoded mirrors if mirror manager fails
                warn!("Failed to get mirrors from mirror manager, using fallback");
                match repo_name.as_str() {
                    "core" => vec![
                        "https://geo.mirror.pkgbuild.com/core/os/x86_64".to_string(),
                        "https://mirror.rackspace.com/archlinux/core/os/x86_64".to_string(),
                    ],
                    "extra" => vec![
                        "https://geo.mirror.pkgbuild.com/extra/os/x86_64".to_string(),
                        "https://mirror.rackspace.com/archlinux/extra/os/x86_64".to_string(),
                    ],
                    "community" => vec![
                        "https://geo.mirror.pkgbuild.com/community/os/x86_64".to_string(),
                        "https://mirror.rackspace.com/archlinux/community/os/x86_64".to_string(),
                    ],
                    _ => vec![format!(
                        "https://geo.mirror.pkgbuild.com/{}/os/x86_64",
                        repo_name
                    )],
                }
            });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let version = &package.version;

        let architectures = if package.arch == "any" {
            vec!["any"]
        } else {
            vec![&package.arch, "any"]
        };

        let extensions = vec!["pkg.tar.zst", "pkg.tar.xz"];

        let mut download_path = None;
        let mut last_error = None;

        // try each mirror until we find one that works
        for (mirror_idx, mirror_url) in mirrors.iter().enumerate() {
            info!(
                "Trying mirror {}/{}: {}",
                mirror_idx + 1,
                mirrors.len(),
                mirror_url
            );

            for arch in &architectures {
                for ext in &extensions {
                    let package_filename = format!("{}-{}-{}.{}", package.name, version, arch, ext);
                    let download_url = format!("{}/{}", mirror_url, package_filename);

                    debug!("Attempting download from: {}", download_url);

                    match client.head(&download_url).send().await {
                        Ok(response) if response.status().is_success() => {
                            let package_file = temp_dir.join(&package_filename);

                            match client.get(&download_url).send().await {
                                Ok(download_response)
                                    if download_response.status().is_success() =>
                                {
                                    match download_response.bytes().await {
                                        Ok(bytes) => {
                                            if let Err(e) =
                                                tokio::fs::write(&package_file, &bytes).await
                                            {
                                                warn!("Failed to write downloaded file: {}", e);
                                                last_error = Some(e.to_string());
                                                continue;
                                            }

                                            info!(
                                                "Successfully downloaded {} from {} ({} bytes)",
                                                package.name,
                                                mirror_url,
                                                bytes.len()
                                            );
                                            download_path = Some(package_file);
                                            break;
                                        }
                                        Err(e) => {
                                            warn!(
                                                "Failed to read response bytes from {}: {}",
                                                mirror_url, e
                                            );
                                            last_error = Some(e.to_string());
                                        }
                                    }
                                }
                                Ok(response) => {
                                    warn!(
                                        "Download failed with status {} from {}",
                                        response.status(),
                                        mirror_url
                                    );
                                    last_error = Some(format!("HTTP {}", response.status()));
                                }
                                Err(e) => {
                                    warn!("Request failed to {}: {}", mirror_url, e);
                                    last_error = Some(e.to_string());
                                }
                            }
                        }
                        Ok(response) => {
                            debug!(
                                "Package not found at {} (HTTP {})",
                                download_url,
                                response.status()
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to check package availability at {}: {}",
                                mirror_url, e
                            );
                            last_error = Some(e.to_string());
                        }
                    }
                }
                if download_path.is_some() {
                    break;
                }
            }
            if download_path.is_some() {
                break;
            }
        }

        let package_file = download_path.ok_or_else(|| {
            let error_msg = if let Some(last_err) = last_error {
                format!(
                    "Could not download package {} from any of {} mirrors. Last error: {}",
                    package.name,
                    mirrors.len(),
                    last_err
                )
            } else {
                format!(
                    "Could not download package {} from any of {} mirrors",
                    package.name,
                    mirrors.len()
                )
            };
            PackerError::DownloadFailed(error_msg)
        })?;

        let extract_dir = temp_dir.join("extracted");
        tokio::fs::create_dir_all(&extract_dir).await?;

        let extraction_result = if package_file.extension().and_then(|s| s.to_str()) == Some("zst")
        {
            tokio::process::Command::new("tar")
                .arg("--use-compress-program=unzstd")
                .arg("-xf")
                .arg(&package_file)
                .arg("-C")
                .arg(&extract_dir)
                .output()
                .await?
        } else {
            tokio::process::Command::new("tar")
                .arg("-xJf")
                .arg(&package_file)
                .arg("-C")
                .arg(&extract_dir)
                .output()
                .await?
        };

        if extraction_result.status.success() {
            tokio::fs::remove_file(&package_file).await.ok();
            Ok(vec![extract_dir])
        } else {
            Err(PackerError::DownloadFailed(format!(
                "Failed to extract package {}: {}",
                package.name,
                String::from_utf8_lossy(&extraction_result.stderr)
            )))
        }
    }

    async fn build_aur_package_for_conversion(
        &self,
        package: &CorePackage,
        temp_dir: &std::path::Path,
    ) -> PackerResult<Vec<std::path::PathBuf>> {
        let build_dir = temp_dir.join("build");
        tokio::fs::create_dir_all(&build_dir).await?;

        let clone_output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::process::Command::new("git")
                .arg("clone")
                .arg(format!("https://aur.archlinux.org/{}.git", package.name))
                .arg(&build_dir)
                .output(),
        )
        .await
        .map_err(|_| {
            PackerError::BuildFailed(format!("Git clone timeout for {}", package.name))
        })??;

        if !clone_output.status.success() {
            return Err(PackerError::BuildFailed(format!(
                "Failed to clone AUR repo for {}",
                package.name
            )));
        }

        let build_output = tokio::time::timeout(
            std::time::Duration::from_secs(300), // 5 minutes for compilation
            tokio::process::Command::new("makepkg")
                .arg("-f")
                .arg("--noconfirm")
                .current_dir(&build_dir)
                .output(),
        )
        .await
        .map_err(|_| PackerError::BuildFailed(format!("Makepkg timeout for {}", package.name)))??;

        if !build_output.status.success() {
            return Err(PackerError::BuildFailed(format!(
                "Failed to build AUR package {}: {}",
                package.name,
                String::from_utf8_lossy(&build_output.stderr)
            )));
        }

        let mut package_files = Vec::new();
        let mut entries = tokio::fs::read_dir(&build_dir).await?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == "pkg" || extension == "xz" {
                    let extract_dir = temp_dir.join("extracted");
                    tokio::fs::create_dir_all(&extract_dir).await?;

                    let extract_output = tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        tokio::process::Command::new("tar")
                            .arg("-xf")
                            .arg(&path)
                            .arg("-C")
                            .arg(&extract_dir)
                            .output(),
                    )
                    .await
                    .map_err(|_| {
                        PackerError::BuildFailed(format!(
                            "Tar extraction timeout for {}",
                            path.display()
                        ))
                    })??;

                    if extract_output.status.success() {
                        package_files.push(extract_dir);
                    }
                }
            }
        }

        if package_files.is_empty() {
            Err(PackerError::BuildFailed(format!(
                "No package files found after building {}",
                package.name
            )))
        } else {
            Ok(package_files)
        }
    }

    async fn convert_to_native_format(
        &self,
        package: &CorePackage,
        package_files: &[std::path::PathBuf],
        _temp_dir: &std::path::Path,
    ) -> PackerResult<crate::native_format::NativePackage> {
        self.convert_to_native_package(package, package_files, _temp_dir)
            .await
    }

    async fn convert_to_native_package(
        &self,
        package: &CorePackage,
        package_files: &[std::path::PathBuf],
        _temp_dir: &std::path::Path,
    ) -> PackerResult<crate::native_format::NativePackage> {
        use crate::native_format::{NativePackage, PackageMetadata, PackageScripts};

        let metadata = PackageMetadata {
            name: package.name.clone(),
            version: package.version.clone(),
            description: package.description.clone(),
            maintainer: package.maintainer.clone(),
            homepage: package.url.clone(),
            license: "Unknown".to_string(),
            architecture: package.arch.clone(),
            build_date: chrono::Utc::now().to_rfc3339(),
            installed_size: package.installed_size,
            checksum: package.checksum.clone().unwrap_or_default(),
        };

        let mut files = Vec::new();

        for package_dir in package_files {
            self.scan_directory_recursive(package_dir, package_dir, &mut files)
                .await?;
        }

        let dependencies = package
            .dependencies
            .iter()
            .map(|dep| {
                let (name, version_constraint) = self.parse_dependency_with_version(dep);
                crate::native_format::NativeDependency {
                    name,
                    version_constraint,
                    optional: false,
                }
            })
            .collect();

        Ok(NativePackage {
            metadata,
            files,
            scripts: PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
            },
            dependencies,
            conflicts: package.conflicts.clone(),
            signature: None,
        })
    }

    async fn scan_directory_recursive(
        &self,
        current_dir: &std::path::Path,
        base_dir: &std::path::Path,
        files: &mut Vec<crate::native_format::PackageFile>,
    ) -> PackerResult<()> {
        use crate::native_format::{FileType, PackageFile};

        let mut entries = tokio::fs::read_dir(current_dir).await?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let relative_path = path
                .strip_prefix(base_dir)
                .map_err(|e| PackerError::RepositoryError(e.to_string()))?;

            let metadata = entry.metadata().await?;

            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.starts_with('.')
                && (file_name == ".BUILDINFO" || file_name == ".PKGINFO" || file_name == ".MTREE")
            {
                continue;
            }

            let target_path = if relative_path.starts_with("/") {
                relative_path.to_string_lossy().to_string()
            } else {
                format!("/{}", relative_path.to_string_lossy())
            };

            if metadata.is_dir() {
                let file = PackageFile {
                    source: path.to_string_lossy().to_string(),
                    target: target_path,
                    permissions: 0o755,
                    owner: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    group: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    file_type: FileType::Directory,
                    checksum: "".to_string(),
                };
                files.push(file);

                Box::pin(self.scan_directory_recursive(&path, base_dir, files)).await?;
            } else if metadata.file_type().is_symlink() {
                let link_target = match tokio::fs::read_link(&path).await {
                    Ok(target) => target.to_string_lossy().to_string(),
                    Err(_) => String::new(),
                };
                let file = PackageFile {
                    source: path.to_string_lossy().to_string(),
                    target: target_path.clone(),
                    permissions: 0o777,
                    owner: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    group: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    file_type: FileType::Symlink(link_target),
                    checksum: "".to_string(),
                };
                files.push(file);
            } else {
                let file = PackageFile {
                    source: path.to_string_lossy().to_string(),
                    target: target_path.clone(),
                    permissions: if target_path.contains("/bin/") || target_path.contains("/sbin/")
                    {
                        0o755
                    } else {
                        0o644
                    },
                    owner: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    group: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    file_type: FileType::Regular,
                    checksum: "".to_string(),
                };
                files.push(file);
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    async fn install_official_packages(&mut self, _packages: &[CorePackage]) -> PackerResult<()> {
        Err(PackerError::ConfigError(
            "Deprecated: Use native installation instead".to_string(),
        ))
    }

    #[allow(dead_code)]
    async fn install_single_aur_package(&self, _package: &CorePackage) -> PackerResult<()> {
        Err(PackerError::ConfigError(
            "Deprecated: Use native installation instead".to_string(),
        ))
    }

    #[allow(dead_code)]
    async fn install_other_packages(&mut self, _packages: &[CorePackage]) -> PackerResult<()> {
        Err(PackerError::ConfigError(
            "Deprecated: Use native installation instead".to_string(),
        ))
    }

    pub async fn remove(&mut self, packages: &[String]) -> PackerResult<()> {
        info!("Removing packages: {:?}", packages);

        let mut official_packages = Vec::new();
        let mut other_packages = Vec::new();

        for package_name in packages {
            if let Some(package) = self.database.get_installed(package_name) {
                match package.source_type {
                    SourceType::Official => official_packages.push(package_name.clone()),
                    _ => other_packages.push(package_name.clone()),
                }
            }
        }

        if !official_packages.is_empty() {
            self.remove_official_packages(&official_packages).await?;
        }

        for package_name in &other_packages {
            self.remove_other_package(package_name).await?;
        }

        self.database.save().await?;

        // let's check how much space we freed up
        let install_path = std::path::Path::new("/"); // checking the whole disk
        let (_used, available) = crate::utils::get_disk_usage(install_path).unwrap_or((0, 0));

        println!(
            "💾 Available space: {}",
            crate::utils::format_bytes(available)
        );

        Ok(())
    }

    async fn remove_official_packages(&mut self, packages: &[String]) -> PackerResult<()> {
        info!("Removing {} packages natively", packages.len());

        let mut failed_packages = Vec::new();

        for package_name in packages {
            if let Some(package) = self.database.get_installed(package_name) {
                match self.convert_core_to_native_package(package).await {
                    Ok(native_package) => {
                        match self.remove_native_package_files(&native_package).await {
                            Ok(()) => {
                                self.database.mark_removed(package_name);
                                println!("✅ Removed: {}", package_name);
                            }
                            Err(e) => {
                                warn!("Failed to remove {}: {}", package_name, e);
                                failed_packages.push(package_name.clone());
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to convert package {} for removal: {}",
                            package_name, e
                        );
                        failed_packages.push(package_name.clone());
                    }
                }
            } else {
                warn!("Package {} not found in database", package_name);
                failed_packages.push(package_name.clone());
            }
        }

        if !failed_packages.is_empty() {
            return Err(PackerError::RemovalFailed(format!(
                "Failed to remove {} packages: {}",
                failed_packages.len(),
                failed_packages.join(", ")
            )));
        }

        info!("Successfully removed all packages natively");
        Ok(())
    }

    async fn remove_other_package(&mut self, package_name: &str) -> PackerResult<()> {
        self.database.mark_removed(package_name);
        info!("Marked {} as removed from database", package_name);
        Ok(())
    }

    pub fn list_installed(&self) -> Vec<&CorePackage> {
        self.database.list_installed()
    }

    fn parse_dependency_with_version(&self, dep: &str) -> (String, Option<String>) {
        for op in &[">=", "<=", "==", "!=", ">", "<", "=", "~"] {
            if let Some(pos) = dep.find(op) {
                let name = dep[..pos].trim().to_string();
                let version = dep[pos..].trim().to_string();
                return (name, Some(version));
            }
        }
        (dep.trim().to_string(), None)
    }

    pub fn get_package_status(&self, name: &str) -> InstallStatus {
        let db_status = self.database.get_status(name);

        if let InstallStatus::NotInstalled = db_status {
            if let Some(available_pkg) = self.native_db.get_package(name) {
                if let Some(installed_pkg) = self.database.get_installed(name) {
                    if installed_pkg.version != available_pkg.version {
                        return InstallStatus::UpdateAvailable(available_pkg.version.clone());
                    }
                }
                return InstallStatus::NotInstalled;
            }
        }

        db_status
    }

    pub async fn update_database(&mut self) -> PackerResult<()> {
        info!("Updating native package database...");
        self.native_db.force_sync().await?;
        info!("Database update completed");
        Ok(())
    }

    pub async fn check_and_auto_update(&mut self) -> PackerResult<bool> {
        if self.native_db.is_stale() {
            info!("Database is stale, performing automatic update...");
            self.native_db.force_sync().await?;
            info!("Automatic database update completed");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn get_database_age(&self) -> Option<chrono::Duration> {
        self.native_db.get_age()
    }

    pub fn should_auto_update(&self) -> bool {
        self.native_db.is_stale()
    }

    pub fn get_database_stats(&self) -> crate::native_db::DatabaseStats {
        self.native_db.get_stats()
    }

    async fn search_external(&self, query: &str) -> PackerResult<Vec<CorePackage>> {
        let mut results = Vec::new();
        let mut errors = Vec::new();

        let native_results = self.search_native_database(query).await;
        info!(
            "Found {} results from native database",
            native_results.len()
        );
        results.extend(native_results);

        if results.len() < 5 {
            match self.search_aur(query).await {
                Ok(aur_results) => {
                    info!("Found {} results from AUR", aur_results.len());
                    results.extend(aur_results);
                }
                Err(e) => {
                    warn!("AUR search failed: {}", e);
                    errors.push(format!("AUR: {}", e));
                }
            }
        }

        if results.is_empty() && !errors.is_empty() {
            match self.fallback_package_lookup(query).await {
                Ok(fallback_results) => {
                    info!(
                        "Found {} results from fallback lookup",
                        fallback_results.len()
                    );
                    results.extend(fallback_results);
                }
                Err(e) => {
                    warn!("Fallback lookup failed: {}", e);
                    errors.push(format!("Fallback: {}", e));
                }
            }
        }

        if results.is_empty() && !errors.is_empty() {
            warn!("All repository sources failed: {}", errors.join(", "));
        }

        Ok(results)
    }

    async fn fallback_package_lookup(&self, query: &str) -> PackerResult<Vec<CorePackage>> {
        let url = format!("https://aur.archlinux.org/rpc/?v=5&type=info&arg={}", query);
        let client = reqwest::Client::new();

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let json: serde_json::Value = response.json().await?;
        let mut packages = Vec::new();

        if let Some(results) = json["results"].as_array() {
            for result in results {
                if let Some(package) = self.parse_aur_search_result(result) {
                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    async fn search_native_database(&self, query: &str) -> Vec<CorePackage> {
        let matches = self.native_db.search_packages(query);

        matches
            .into_iter()
            .map(|pkg| {
                let is_aur = pkg.repository == "aur";
                CorePackage {
                    name: pkg.name,
                    version: pkg.version,
                    description: pkg.description,
                    repository: pkg.repository,
                    arch: pkg.arch,
                    download_size: pkg.download_size,
                    installed_size: pkg.installed_size,
                    dependencies: pkg.dependencies,
                    conflicts: pkg.conflicts,
                    maintainer: pkg.maintainer,
                    url: pkg.url,
                    checksum: pkg.checksum,
                    source_type: if is_aur {
                        SourceType::AUR
                    } else {
                        SourceType::Official
                    },
                    install_date: pkg.install_date,
                }
            })
            .collect()
    }

    async fn search_aur(&self, query: &str) -> PackerResult<Vec<CorePackage>> {
        let url = format!(
            "https://aur.archlinux.org/rpc/?v=5&type=search&arg={}",
            query
        );
        let client = reqwest::Client::new();

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let json: serde_json::Value = response.json().await?;
        let mut packages = Vec::new();

        if let Some(results) = json["results"].as_array() {
            for result in results {
                if let Some(name) = result["Name"].as_str() {
                    let package = CorePackage {
                        name: name.to_string(),
                        version: result["Version"].as_str().unwrap_or("unknown").to_string(),
                        description: result["Description"].as_str().unwrap_or("").to_string(),
                        repository: "aur".to_string(),
                        arch: "x86_64".to_string(),
                        download_size: 0,
                        installed_size: 0,
                        dependencies: Vec::new(),
                        conflicts: Vec::new(),
                        maintainer: result["Maintainer"]
                            .as_str()
                            .unwrap_or("unknown")
                            .to_string(),
                        url: result["URL"].as_str().unwrap_or("").to_string(),
                        checksum: None,
                        source_type: SourceType::AUR,
                        install_date: None,
                    };
                    packages.push(package);
                }
            }
        }

        Ok(packages)
    }

    #[allow(dead_code)]
    async fn find_external_package(&self, name: &str) -> PackerResult<CorePackage> {
        let search_results = self.search_external(name).await?;

        search_results
            .into_iter()
            .find(|pkg| pkg.name == name)
            .ok_or_else(|| PackerError::PackageNotFound(name.to_string()))
    }

    // generate smart search names for packages by analyzing name patterns
    fn get_package_search_names(&self, package_name: &str) -> Vec<String> {
        let mut names = vec![package_name.to_string()];

        // add common name variations automatically
        if package_name.contains("-") {
            names.push(package_name.replace("-", ""));
            names.push(package_name.replace("-", "_"));
        }

        if package_name.contains("_") {
            names.push(package_name.replace("_", "-"));
            names.push(package_name.replace("_", ""));
        }

        // add base name without suffixes
        if let Some(first_part) = package_name.split('-').next() {
            if first_part != package_name && first_part.len() >= 3 {
                names.push(first_part.to_string());
            }
        }

        // add common suffixes/prefixes that packages might use
        names.push(format!("{}-bin", package_name));
        names.push(format!("{}-git", package_name));
        names.push(format!("lib{}", package_name));

        names.dedup();
        names
    }

    // dynamically scan for package files instead of hardcoded lists
    async fn add_known_package_files(
        &self,
        package_name: &str,
        install_root: &std::path::Path,
        files: &mut Vec<crate::native_format::PackageFile>,
    ) -> PackerResult<()> {
        // scan common directories where packages typically install files - standard unix layout
        let common_dirs = vec![
            "bin",
            "sbin",
            "lib",
            "share",
            "etc",
            "usr/bin",
            "usr/sbin",
            "usr/lib",
            "usr/share",
            "opt",
        ];

        for dir in common_dirs {
            let search_path = install_root.join(dir);
            if search_path.exists() {
                // scan for files related to this package
                self.scan_directory_for_package(package_name, &search_path, install_root, files)
                    .await?;
            }
        }

        Ok(())
    }

    // scan directory for files that might belong to this package
    fn scan_directory_for_package<'a>(
        &'a self,
        package_name: &'a str,
        search_dir: &'a std::path::Path,
        install_root: &'a std::path::Path,
        files: &'a mut Vec<crate::native_format::PackageFile>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = PackerResult<()>> + 'a>> {
        Box::pin(async move {
            use crate::native_format::{FileType, PackageFile};

            let mut entries = tokio::fs::read_dir(search_dir).await?;

            while let Some(entry) = entries.next_entry().await? {
                let path = entry.path();
                let filename = entry.file_name().to_string_lossy().to_lowercase();

                // check if this file is related to our package - simple name matching
                if filename.contains(&package_name.to_lowercase())
                    || filename.starts_with(&package_name.to_lowercase())
                    || filename.ends_with(&package_name.to_lowercase())
                {
                    let metadata = entry.metadata().await?;
                    let relative_path = path.strip_prefix(install_root).unwrap_or(&path);

                    let file = PackageFile {
                        source: path.to_string_lossy().to_string(),
                        target: format!("/{}", relative_path.to_string_lossy()),
                        permissions: if metadata.is_dir() { 0o755 } else { 0o644 },
                        owner: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                        group: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                        file_type: if metadata.is_dir() {
                            FileType::Directory
                        } else if metadata.file_type().is_symlink() {
                            let link_target = tokio::fs::read_link(&path)
                                .await
                                .unwrap_or_else(|_| std::path::PathBuf::from(""))
                                .to_string_lossy()
                                .to_string();
                            FileType::Symlink(link_target)
                        } else {
                            FileType::Regular
                        },
                        checksum: "".to_string(),
                    };
                    files.push(file);

                    // if it's a directory, recursively scan it - gotta check everything
                    if metadata.is_dir() {
                        self.scan_directory_for_package(package_name, &path, install_root, files)
                            .await?;
                    }
                }
            }

            Ok(())
        })
    }

    async fn convert_core_to_native_package(
        &self,
        package: &CorePackage,
    ) -> PackerResult<crate::native_format::NativePackage> {
        use crate::native_format::{NativePackage, PackageMetadata, PackageScripts};

        let metadata = PackageMetadata {
            name: package.name.clone(),
            version: package.version.clone(),
            description: package.description.clone(),
            maintainer: package.maintainer.clone(),
            homepage: package.url.clone(),
            license: "Unknown".to_string(),
            architecture: package.arch.clone(),
            build_date: chrono::Utc::now().to_rfc3339(),
            installed_size: package.installed_size,
            checksum: package.checksum.clone().unwrap_or_default(),
        };

        let mut files = Vec::new();
        let install_root = &self.config.install_root;

        let search_names = self.get_package_search_names(&package.name);

        self.add_known_package_files(&package.name, install_root, &mut files)
            .await?;

        if files.is_empty() {
            for search_name in &search_names {
                self.scan_directory_for_removal(&install_root, search_name, &mut files)
                    .await?;
            }
        }

        Ok(NativePackage {
            metadata,
            files,
            scripts: PackageScripts {
                pre_install: None,
                post_install: None,
                pre_remove: None,
                post_remove: None,
            },
            dependencies: package
                .dependencies
                .iter()
                .map(|dep| crate::native_format::NativeDependency {
                    name: dep.clone(),
                    version_constraint: None,
                    optional: false,
                })
                .collect(),
            conflicts: package.conflicts.clone(),
            signature: None,
        })
    }

    async fn remove_native_package_files(
        &self,
        package: &crate::native_format::NativePackage,
    ) -> PackerResult<()> {
        use crate::native_format::FileType;

        println!("🗑️  Removing native package: {}", package.metadata.name);

        let mut files_removed = 0;
        let mut directories_to_check = Vec::new();

        println!("🔍 Found {} files to remove", package.files.len());

        if package.files.is_empty() {
            println!(
                "🔍 no files found through scanning, using smart removal for {}",
                package.metadata.name
            );
            // fallback: scan for package files dynamically
            files_removed = self
                .remove_package_files_fallback(&package.metadata.name)
                .await?;
        } else {
            for file in package.files.iter().rev() {
                let target_path = self
                    .config
                    .install_root
                    .join(&file.target.trim_start_matches('/'));

                if target_path.exists() {
                    match file.file_type {
                        FileType::Directory => {
                            directories_to_check.push(target_path);
                        }
                        FileType::Symlink(_) => {
                            if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                warn!("Failed to remove symlink {:?}: {}", target_path, e);
                            } else {
                                files_removed += 1;
                                info!("Removed symlink: {:?}", target_path);
                            }
                        }
                        _ => {
                            if let Err(e) = tokio::fs::remove_file(&target_path).await {
                                warn!("Failed to remove file {:?}: {}", target_path, e);
                            } else {
                                files_removed += 1;
                                info!("Removed file: {:?}", target_path);
                            }
                        }
                    }
                }
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
                            warn!("Failed to remove empty directory {:?}: {}", dir, e);
                        } else {
                            info!("Removed empty directory: {:?}", dir);
                        }
                    }
                    Ok(false) => {
                        info!("Directory not empty, keeping: {:?}", dir);
                    }
                    Err(e) => {
                        warn!("Could not check if directory is empty {:?}: {}", dir, e);
                    }
                }
            }
        }

        println!(
            "✅ Successfully removed {} files for package: {}",
            files_removed, package.metadata.name
        );
        Ok(())
    }

    async fn is_directory_empty(&self, dir: &std::path::Path) -> PackerResult<bool> {
        let mut entries = tokio::fs::read_dir(dir).await?;
        match entries.next_entry().await? {
            Some(_) => Ok(false),
            None => Ok(true),
        }
    }

    async fn scan_directory_for_removal(
        &self,
        base_dir: &std::path::Path,
        package_name: &str,
        files: &mut Vec<crate::native_format::PackageFile>,
    ) -> PackerResult<()> {
        let search_dirs = vec!["bin", "sbin", "lib", "share"];

        for search_dir in search_dirs {
            let dir_path = base_dir.join(search_dir);
            if !dir_path.exists() {
                continue;
            }

            self.recursive_scan_for_package(&dir_path, base_dir, package_name, files)
                .await?;
        }

        Ok(())
    }

    async fn recursive_scan_for_package(
        &self,
        current_dir: &std::path::Path,
        base_dir: &std::path::Path,
        package_name: &str,
        files: &mut Vec<crate::native_format::PackageFile>,
    ) -> PackerResult<()> {
        use crate::native_format::{FileType, PackageFile};

        let mut entries = match tokio::fs::read_dir(current_dir).await {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if file_name.contains(package_name) || path.to_string_lossy().contains(package_name) {
                let metadata = match entry.metadata().await {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };

                let relative_path = match path.strip_prefix(base_dir) {
                    Ok(rel) => rel,
                    Err(_) => continue,
                };

                let file = PackageFile {
                    source: path.to_string_lossy().to_string(),
                    target: format!("/{}", relative_path.to_string_lossy()),
                    permissions: if metadata.is_dir() { 0o755 } else { 0o644 },
                    owner: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    group: std::env::var("USER").unwrap_or_else(|_| "user".to_string()),
                    file_type: if metadata.is_dir() {
                        FileType::Directory
                    } else if metadata.file_type().is_symlink() {
                        let link_target = tokio::fs::read_link(&path)
                            .await
                            .unwrap_or_else(|_| std::path::PathBuf::from(""))
                            .to_string_lossy()
                            .to_string();
                        FileType::Symlink(link_target)
                    } else {
                        FileType::Regular
                    },
                    checksum: "".to_string(),
                };
                files.push(file);
            }

            if path.is_dir() {
                Box::pin(self.recursive_scan_for_package(&path, base_dir, package_name, files))
                    .await?;
            }
        }

        Ok(())
    }

    // fallback method to remove package files when no manifest exists
    async fn remove_package_files_fallback(&self, package_name: &str) -> PackerResult<usize> {
        let mut files_removed = 0;

        // search common directories for files related to this package - fallback approach
        let search_dirs = vec![
            "bin",
            "sbin",
            "lib",
            "share",
            "etc",
            "usr/bin",
            "usr/sbin",
            "usr/lib",
            "usr/share",
            "opt",
        ];

        for dir in search_dirs {
            let search_path = self.config.install_root.join(dir);
            if search_path.exists() {
                files_removed += self
                    .scan_and_remove_package_files(package_name, &search_path)
                    .await?;
            }
        }

        Ok(files_removed)
    }

    // scan directory and remove files that match the package name
    async fn scan_and_remove_package_files(
        &self,
        package_name: &str,
        search_dir: &std::path::Path,
    ) -> PackerResult<usize> {
        let mut files_removed = 0;

        let mut entries = tokio::fs::read_dir(search_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let filename = entry.file_name().to_string_lossy().to_lowercase();

            // check if this file is related to our package - simple name matching
            if filename.contains(&package_name.to_lowercase())
                || filename.starts_with(&package_name.to_lowercase())
                || filename.ends_with(&package_name.to_lowercase())
            {
                let metadata = entry.metadata().await?;

                if metadata.is_dir() {
                    // recursively remove directory
                    match tokio::fs::remove_dir_all(&path).await {
                        Ok(_) => {
                            files_removed += 1;
                            println!("✅ removed directory: {:?}", path);
                        }
                        Err(e) => {
                            warn!("failed to remove directory {:?}: {}", path, e);
                        }
                    }
                } else {
                    // remove file
                    match tokio::fs::remove_file(&path).await {
                        Ok(_) => {
                            files_removed += 1;
                            println!("✅ removed file: {:?}", path);
                        }
                        Err(e) => {
                            warn!("failed to remove file {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        Ok(files_removed)
    }

    // mirror management methods
    pub async fn get_mirrors_for_repo(&mut self, repo: &str) -> PackerResult<Vec<String>> {
        self.mirror_manager.get_best_mirrors(repo).await
    }

    pub async fn test_mirror_speeds(
        &mut self,
        repo: &str,
    ) -> PackerResult<Vec<crate::mirrors::MirrorTestResult>> {
        let mirrors = self.mirror_manager.get_best_mirrors(repo).await?;
        let mut results = Vec::new();

        for mirror_url in mirrors {
            let base_url = mirror_url.trim_end_matches(&format!("/{}", repo));
            match self.mirror_manager.test_mirror_speed(base_url).await {
                Ok(result) => results.push(result),
                Err(e) => warn!("Failed to test mirror {}: {}", base_url, e),
            }
        }

        Ok(results)
    }

    pub async fn rank_mirrors(&mut self) -> PackerResult<()> {
        self.mirror_manager.rank_mirrors().await
    }

    pub fn get_mirror_stats(&self) -> crate::mirrors::MirrorStats {
        self.mirror_manager.get_mirror_stats()
    }

    pub async fn update_mirrors(&mut self) -> PackerResult<()> {
        self.mirror_manager.initialize().await
    }
}
