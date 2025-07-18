use crate::{
    core::{CorePackage, SourceType},
    error::PackerResult,
    native_db::NativePackageDatabase,
};
use log::{info, warn};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug)]
pub struct FastDependencyResolver {
    max_depth: usize,
    max_resolution_time: std::time::Duration,
    prefer_official: bool,
}

#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub packages_to_install: Vec<CorePackage>,
    pub install_order: Vec<String>,
    pub conflicts: Vec<Conflict>,
    pub warnings: Vec<String>,
    pub resolution_time: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct Conflict {
    pub package1: String,
    pub package2: String,
    pub reason: ConflictReason,
    pub severity: ConflictSeverity,
}

#[derive(Debug, Clone)]
pub enum ConflictReason {
    VersionConflict { required: String, available: String },
    PackageConflict { conflicts_with: String },
    CircularDependency { cycle: Vec<String> },
    NotFound { package: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictSeverity {
    Critical, // Cannot proceed
    Warning,  // Can proceed with caution
    Info,     // Just informational
}

impl FastDependencyResolver {
    pub fn new() -> Self {
        Self {
            max_depth: 10,
            max_resolution_time: std::time::Duration::from_secs(30),
            prefer_official: true,
        }
    }

    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.max_resolution_time = timeout;
        self
    }

    pub async fn resolve_dependencies(
        &self,
        packages: &[String],
        native_db: &NativePackageDatabase,
        installed_packages: &HashMap<String, CorePackage>,
    ) -> PackerResult<ResolutionResult> {
        let start_time = std::time::Instant::now();
        info!("Resolving dependencies for: {:?}", packages);

        let mut resolution = ResolutionResult {
            packages_to_install: Vec::new(),
            install_order: Vec::new(),
            conflicts: Vec::new(),
            warnings: Vec::new(),
            resolution_time: std::time::Duration::default(),
        };

        let mut to_resolve = VecDeque::new();
        let mut resolved_packages = HashMap::new();
        let mut visited = HashSet::new();

        for package_name in packages {
            if !installed_packages.contains_key(package_name) {
                to_resolve.push_back((package_name.clone(), 0));
            } else {
                info!("Package {} is already installed, skipping", package_name);
            }
        }

        while let Some((package_name, depth)) = to_resolve.pop_front() {
            if start_time.elapsed() > self.max_resolution_time {
                resolution.warnings.push(format!(
                    "Dependency resolution timed out after {:?}",
                    self.max_resolution_time
                ));
                break;
            }

            if depth > self.max_depth {
                resolution.warnings.push(format!(
                    "Max dependency depth ({}) reached for package {}",
                    self.max_depth, package_name
                ));
                continue;
            }

            if visited.contains(&package_name) {
                continue;
            }
            visited.insert(package_name.clone());

            match self.find_best_package(&package_name, native_db) {
                Some(package) => {
                    if let Some(conflict) = self.check_conflicts(&package, &resolved_packages, installed_packages) {
                        let is_critical = matches!(conflict.severity, ConflictSeverity::Critical);
                        resolution.conflicts.push(conflict);
                        if is_critical {
                            continue;
                        }
                    }

                    for dep in &package.dependencies {
                        let dep_name = self.parse_dependency_name(dep);
                        if !installed_packages.contains_key(&dep_name) 
                           && !resolved_packages.contains_key(&dep_name) 
                           && !visited.contains(&dep_name) {
                            to_resolve.push_back((dep_name, depth + 1));
                        }
                    }

                    resolved_packages.insert(package_name.clone(), package);
                }
                None => {
                    resolution.conflicts.push(Conflict {
                        package1: package_name.clone(),
                        package2: String::new(),
                        reason: ConflictReason::NotFound { package: package_name.clone() },
                        severity: ConflictSeverity::Critical,
                    });
                }
            }
        }

        resolution.install_order = self.calculate_install_order(&resolved_packages);
        resolution.packages_to_install = resolution.install_order
            .iter()
            .filter_map(|name| resolved_packages.get(name).cloned())
            .collect();

        self.validate_resolution(&mut resolution, installed_packages);

        resolution.resolution_time = start_time.elapsed();
        info!("Dependency resolution completed in {:?}", resolution.resolution_time);
        
        Ok(resolution)
    }

    fn find_best_package(&self, name: &str, native_db: &NativePackageDatabase) -> Option<CorePackage> {
        if self.prefer_official {
            if let Some(official_pkg) = native_db.get_official_package(name) {
                return Some(official_pkg.clone());
            }
        }

        native_db.get_package(name).cloned()
    }

    fn check_conflicts(
        &self,
        package: &CorePackage,
        resolved_packages: &HashMap<String, CorePackage>,
        installed_packages: &HashMap<String, CorePackage>,
    ) -> Option<Conflict> {
        for dep in &package.dependencies {
            let (dep_name, version_req) = self.parse_dependency_with_version(dep);
            
            if let Some(resolved_pkg) = resolved_packages.get(&dep_name) {
                if let Some(ref version_req) = version_req {
                    if !self.version_satisfies(&resolved_pkg.version, version_req) {
                        return Some(Conflict {
                            package1: package.name.clone(),
                            package2: resolved_pkg.name.clone(),
                            reason: ConflictReason::VersionConflict {
                                required: version_req.clone(),
                                available: resolved_pkg.version.clone(),
                            },
                            severity: ConflictSeverity::Warning,
                        });
                    }
                }
            }

            if let Some(installed_pkg) = installed_packages.get(&dep_name) {
                if let Some(ref version_req) = version_req {
                    if !self.version_satisfies(&installed_pkg.version, version_req) {
                        return Some(Conflict {
                            package1: package.name.clone(),
                            package2: installed_pkg.name.clone(),
                            reason: ConflictReason::VersionConflict {
                                required: version_req.clone(),
                                available: installed_pkg.version.clone(),
                            },
                            severity: ConflictSeverity::Warning,
                        });
                    }
                }
            }
        }

        for conflict_pkg in &package.conflicts {
            if resolved_packages.contains_key(conflict_pkg) || installed_packages.contains_key(conflict_pkg) {
                return Some(Conflict {
                    package1: package.name.clone(),
                    package2: conflict_pkg.clone(),
                    reason: ConflictReason::PackageConflict {
                        conflicts_with: conflict_pkg.clone(),
                    },
                    severity: ConflictSeverity::Critical,
                });
            }
        }

        None
    }

    fn calculate_install_order(&self, packages: &HashMap<String, CorePackage>) -> Vec<String> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut temp_visited = HashSet::new();

        for package_name in packages.keys() {
            if !visited.contains(package_name) {
                self.topological_sort(
                    package_name,
                    packages,
                    &mut visited,
                    &mut temp_visited,
                    &mut order,
                );
            }
        }

        order.reverse();
        order
    }

    fn topological_sort(
        &self,
        package_name: &str,
        packages: &HashMap<String, CorePackage>,
        visited: &mut HashSet<String>,
        temp_visited: &mut HashSet<String>,
        order: &mut Vec<String>,
    ) {
        if temp_visited.contains(package_name) {
            warn!("Circular dependency detected involving package: {}", package_name);
            return;
        }

        if visited.contains(package_name) {
            return;
        }

        temp_visited.insert(package_name.to_string());

        if let Some(package) = packages.get(package_name) {
            for dep in &package.dependencies {
                let dep_name = self.parse_dependency_name(dep);
                if packages.contains_key(&dep_name) {
                    self.topological_sort(&dep_name, packages, visited, temp_visited, order);
                }
            }
        }

        temp_visited.remove(package_name);
        visited.insert(package_name.to_string());
        order.push(package_name.to_string());
    }

    fn validate_resolution(
        &self,
        resolution: &mut ResolutionResult,
        installed_packages: &HashMap<String, CorePackage>,
    ) {
        let package_names: HashSet<String> = resolution.packages_to_install
            .iter()
            .map(|p| p.name.clone())
            .collect();

        for package in &resolution.packages_to_install {
            for dep in &package.dependencies {
                let dep_name = self.parse_dependency_name(dep);
                if !package_names.contains(&dep_name) && !installed_packages.contains_key(&dep_name) {
                    resolution.warnings.push(format!(
                        "Package {} requires {} which is not in the resolution set",
                        package.name, dep_name
                    ));
                }
            }
        }

        let mut official_count = 0;
        let mut aur_count = 0;
        let mut other_count = 0;

        for package in &resolution.packages_to_install {
            match package.source_type {
                SourceType::Official => official_count += 1,
                SourceType::AUR => aur_count += 1,
                _ => other_count += 1,
            }
        }

        if aur_count > 10 {
            resolution.warnings.push(format!(
                "Large number of AUR packages ({}) may take significant time to build",
                aur_count
            ));
        }

        info!("Resolution summary: {} official, {} AUR, {} other packages", 
              official_count, aur_count, other_count);
    }

    fn parse_dependency_name(&self, dep: &str) -> String {
        dep.split(&['=', '>', '<', '~'][..])
           .next()
           .unwrap_or(dep)
           .trim()
           .to_string()
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

    fn version_satisfies(&self, available: &str, requirement: &str) -> bool {
        if requirement.starts_with(">=") {
            let req_version = &requirement[2..];
            available >= req_version
        } else if requirement.starts_with("<=") {
            let req_version = &requirement[2..];
            available <= req_version
        } else if requirement.starts_with("==") || requirement.starts_with("=") {
            let req_version = if requirement.starts_with("==") {
                &requirement[2..]
            } else {
                &requirement[1..]
            };
            available == req_version
        } else if requirement.starts_with("!=") {
            let req_version = &requirement[2..];
            available != req_version
        } else if requirement.starts_with(">") {
            let req_version = &requirement[1..];
            available > req_version
        } else if requirement.starts_with("<") {
            let req_version = &requirement[1..];
            available < req_version
        } else {
            available == requirement
        }
    }

    pub fn is_critical_conflict(&self, conflicts: &[Conflict]) -> bool {
        conflicts.iter().any(|c| c.severity == ConflictSeverity::Critical)
    }

    pub fn format_conflicts(&self, conflicts: &[Conflict]) -> Vec<String> {
        conflicts.iter().map(|conflict| {
            match &conflict.reason {
                ConflictReason::VersionConflict { required, available } => {
                    format!("Version conflict: {} requires {}, but {} is available",
                           conflict.package1, required, available)
                }
                ConflictReason::PackageConflict { conflicts_with } => {
                    format!("Package conflict: {} conflicts with {}",
                           conflict.package1, conflicts_with)
                }
                ConflictReason::CircularDependency { cycle } => {
                    format!("Circular dependency: {}", cycle.join(" -> "))
                }
                ConflictReason::NotFound { package } => {
                    format!("Package not found: {}", package)
                }
            }
        }).collect()
    }
}

impl Default for FastDependencyResolver {
    fn default() -> Self {
        Self::new()
    }
} 