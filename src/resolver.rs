use crate::{
    core::{CorePackage, SourceType},
    dependency::{Dependency, DependencyGraph, DependencyResolution},
    error::{PackerError, PackerResult},
    native_db::NativePackageDatabase,
    package::Package,
    repository::RepositoryManager,
};
use log::{debug, info, warn};
use parking_lot::RwLock;
use semver::{Version, VersionReq};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DependencyResolver {
    graph: DependencyGraph,
    package_cache: Arc<RwLock<HashMap<String, Vec<Package>>>>,
    resolution_cache: Arc<RwLock<HashMap<String, ResolutionResult>>>,
    solver: SATSolver,
    constraints: Vec<Constraint>,
    preferences: ResolutionPreferences,
    conflict_resolver: ConflictResolver,
    optimizer: MultiObjectiveOptimizer,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConflictResolver {
    resolution_strategies: Vec<ResolutionStrategy>,
    backtrack_limit: usize,
    heuristics: ConflictHeuristics,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MultiObjectiveOptimizer {
    objectives: Vec<OptimizationObjective>,
    weights: HashMap<OptimizationGoal, f64>,
    pareto_frontier: Vec<Solution>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Solution {
    packages: Vec<Package>,
    score: f64,
    objectives: HashMap<OptimizationGoal, f64>,
    trade_offs: Vec<TradeOff>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TradeOff {
    objective1: OptimizationGoal,
    objective2: OptimizationGoal,
    impact: f64,
    description: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct OptimizationObjective {
    goal: OptimizationGoal,
    weight: f64,
    constraint: Option<f64>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ResolutionStrategy {
    BacktrackSearch,
    ConstraintPropagation,
    LocalSearch,
    GeneticAlgorithm,
    SimulatedAnnealing,
    HybridApproach,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ConflictHeuristics {
    use_version_ranges: bool,
    prefer_optional_dependencies: bool,
    allow_downgrade: bool,
    auto_resolve_conflicts: bool,
    conflict_timeout: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub additional_packages: Vec<Package>,
    pub conflicts: Vec<String>,
    pub install_order: Vec<String>,
    pub removed_packages: Vec<String>,
    pub upgraded_packages: Vec<(Package, Package)>,
    pub resolution_time: std::time::Duration,
    pub optimization_score: f64,
}

#[derive(Debug, Clone)]
pub struct FastResolutionResult {
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
    Critical,
    Warning,
    Info,
}
#[derive(Debug, Clone)]
pub struct ConflictCheckResult {
    pub conflicts: Vec<String>,
    pub circular_dependencies: Vec<Vec<String>>,
    pub version_conflicts: Vec<VersionConflict>,
    pub architecture_conflicts: Vec<ArchConflict>,
    pub suggestions: Vec<ConflictSuggestion>,
}
#[derive(Debug, Clone)]
pub struct VersionConflict {
    pub package: String,
    pub required_versions: Vec<String>,
    pub conflicting_packages: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct ArchConflict {
    pub package: String,
    pub required_archs: Vec<String>,
    pub conflicting_packages: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct ConflictSuggestion {
    pub suggestion_type: SuggestionType,
    pub description: String,
    pub packages_to_remove: Vec<String>,
    pub packages_to_add: Vec<String>,
    pub packages_to_upgrade: Vec<String>,
}
#[derive(Debug, Clone)]
pub enum SuggestionType {
    RemoveConflicting,
    UpgradeToCompatible,
    UseAlternative,
    RelaxConstraints,
}
#[derive(Debug, Clone)]
pub struct SATSolver {
    variables: HashMap<String, usize>,
    clauses: Vec<Vec<i32>>,
    assignments: Vec<Option<bool>>,
    implications: Vec<Vec<usize>>,
}
#[derive(Debug, Clone)]
pub struct Constraint {
    pub constraint_type: ConstraintType,
    pub packages: Vec<String>,
    pub versions: Vec<VersionReq>,
    pub priority: i32,
}
#[derive(Debug, Clone)]
pub enum ConstraintType {
    Requires,
    Conflicts,
    AtMostOne,
    AtLeastOne,
    Implies,
    Equivalent,
}
#[derive(Debug, Clone)]
pub struct ResolutionPreferences {
    pub prefer_newer_versions: bool,
    pub prefer_fewer_packages: bool,
    pub prefer_trusted_repositories: bool,
    pub prefer_stable_versions: bool,
    pub max_resolution_time: std::time::Duration,
    pub optimization_goals: Vec<OptimizationGoal>,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum OptimizationGoal {
    MinimizeDownloadSize,
    MinimizeInstallSize,
    MinimizeDependencies,
    MaximizeStability,
    MaximizeSecurity,
    MinimizeConflicts,
}
impl Default for ResolutionPreferences {
    fn default() -> Self {
        Self {
            prefer_newer_versions: true,
            prefer_fewer_packages: false,
            prefer_trusted_repositories: true,
            prefer_stable_versions: true,
            max_resolution_time: std::time::Duration::from_secs(30),
            optimization_goals: vec![
                OptimizationGoal::MinimizeConflicts,
                OptimizationGoal::MaximizeSecurity,
                OptimizationGoal::MaximizeStability,
            ],
        }
    }
}
impl SATSolver {
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            clauses: Vec::new(),
            assignments: Vec::new(),
            implications: Vec::new(),
        }
    }
    pub fn add_variable(&mut self, name: String) -> usize {
        if let Some(&var_id) = self.variables.get(&name) {
            return var_id;
        }
        let var_id = self.variables.len();
        self.variables.insert(name, var_id);
        self.assignments.push(None);
        self.implications.push(Vec::new());
        var_id
    }
    pub fn add_clause(&mut self, literals: Vec<i32>) {
        if !literals.is_empty() {
            self.clauses.push(literals);
        }
    }
    pub fn add_implication(&mut self, from: usize, to: usize) {
        if from < self.implications.len() {
            self.implications[from].push(to);
        }
    }
    pub fn solve(&mut self) -> bool {
        self.dpll(0)
    }
    fn dpll(&mut self, level: usize) -> bool {
        if level >= self.assignments.len() {
            return self.check_all_clauses();
        }
        if self.assignments[level].is_some() {
            return self.dpll(level + 1);
        }
        for &value in &[true, false] {
            self.assignments[level] = Some(value);
            if self.propagate_implications(level) && self.dpll(level + 1) {
                return true;
            }
            self.backtrack(level);
        }
        self.assignments[level] = None;
        false
    }
    fn propagate_implications(&mut self, var: usize) -> bool {
        if let Some(true) = self.assignments[var] {
            for &implied_var in &self.implications[var].clone() {
                if self.assignments[implied_var].is_none() {
                    self.assignments[implied_var] = Some(true);
                    if !self.propagate_implications(implied_var) {
                        return false;
                    }
                } else if self.assignments[implied_var] == Some(false) {
                    return false;
                }
            }
        }
        true
    }
    fn backtrack(&mut self, level: usize) {
        for i in level..self.assignments.len() {
            if i != level {
                self.assignments[i] = None;
            }
        }
    }
    fn check_all_clauses(&self) -> bool {
        for clause in &self.clauses {
            if !self.check_clause(clause) {
                return false;
            }
        }
        true
    }
    fn check_clause(&self, clause: &[i32]) -> bool {
        for &literal in clause {
            let var_id = (literal.abs() - 1) as usize;
            let expected = literal > 0;
            if let Some(value) = self.assignments.get(var_id).and_then(|&x| x) {
                if value == expected {
                    return true;
                }
            }
        }
        false
    }
    pub fn get_solution(&self) -> HashMap<String, bool> {
        let mut solution = HashMap::new();
        for (name, &var_id) in &self.variables {
            if let Some(value) = self.assignments.get(var_id).and_then(|&x| x) {
                solution.insert(name.clone(), value);
            }
        }
        solution
    }
}
impl DependencyResolver {
    pub fn new() -> Self {
        Self {
            graph: DependencyGraph::new(),
            package_cache: Arc::new(RwLock::new(HashMap::new())),
            resolution_cache: Arc::new(RwLock::new(HashMap::new())),
            solver: SATSolver::new(),
            constraints: Vec::new(),
            preferences: ResolutionPreferences::default(),
            conflict_resolver: ConflictResolver {
                resolution_strategies: vec![ResolutionStrategy::BacktrackSearch],
                backtrack_limit: 1000,
                heuristics: ConflictHeuristics {
                    use_version_ranges: true,
                    prefer_optional_dependencies: true,
                    allow_downgrade: false,
                    auto_resolve_conflicts: true,
                    conflict_timeout: std::time::Duration::from_secs(10),
                },
            },
            optimizer: MultiObjectiveOptimizer {
                objectives: vec![
                    OptimizationObjective {
                        goal: OptimizationGoal::MinimizeConflicts,
                        weight: 1.0,
                        constraint: None,
                    },
                    OptimizationObjective {
                        goal: OptimizationGoal::MaximizeStability,
                        weight: 0.8,
                        constraint: None,
                    },
                    OptimizationObjective {
                        goal: OptimizationGoal::MinimizeDownloadSize,
                        weight: 0.5,
                        constraint: None,
                    },
                ],
                weights: HashMap::new(),
                pareto_frontier: Vec::new(),
            },
        }
    }
    pub fn with_preferences(mut self, preferences: ResolutionPreferences) -> Self {
        self.preferences = preferences;
        self
    }
    pub async fn resolve_dependencies_advanced(
        &mut self,
        packages: &[Package],
        repository_manager: &RepositoryManager,
        installed_packages: &[Package],
    ) -> PackerResult<ResolutionResult> {
        let start_time = std::time::Instant::now();
        info!(
            "Starting advanced dependency resolution for {} packages",
            packages.len()
        );
        let cache_key = self.generate_cache_key(packages);
        if let Some(cached_result) = self.resolution_cache.read().get(&cache_key) {
            debug!("Using cached resolution result");
            return Ok(cached_result.clone());
        }
        self.clear_solver_state();
        let candidate_packages = self
            .discover_all_candidates(packages, repository_manager)
            .await?;
        self.build_constraint_system(&candidate_packages, installed_packages)?;
        let solution = self.solve_constraints()?;
        let selected_packages = self.extract_selected_packages(solution, &candidate_packages)?;
        let optimized_packages = self
            .optimize_selection(selected_packages, repository_manager)
            .await?;
        let conflicts = self.detect_advanced_conflicts(&optimized_packages).await?;
        let install_order = self.calculate_optimal_install_order(&optimized_packages)?;
        let (removed, upgraded) =
            self.calculate_package_changes(&optimized_packages, installed_packages)?;
        let resolution_time = start_time.elapsed();
        let optimization_score = self.calculate_optimization_score(&optimized_packages);
        let result = ResolutionResult {
            additional_packages: optimized_packages,
            conflicts: conflicts.conflicts,
            install_order,
            removed_packages: removed,
            upgraded_packages: upgraded,
            resolution_time,
            optimization_score,
        };
        self.resolution_cache
            .write()
            .insert(cache_key, result.clone());
        info!(
            "Advanced dependency resolution completed in {:?} with score {:.2}",
            resolution_time, optimization_score
        );
        Ok(result)
    }
    async fn discover_all_candidates(
        &mut self,
        packages: &[Package],
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<Package>> {
        let mut candidates = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        for package in packages {
            queue.push_back(package.clone());
        }
        while let Some(package) = queue.pop_front() {
            if visited.contains(&package.name) {
                continue;
            }
            visited.insert(package.name.clone());
            candidates.push(package.clone());
            for dependency in &package.dependencies {
                if dependency.optional && !self.should_include_optional(&dependency) {
                    continue;
                }
                let dep_candidates = self
                    .find_dependency_candidates(dependency, repository_manager)
                    .await?;
                for candidate in dep_candidates {
                    if !visited.contains(&candidate.name) {
                        queue.push_back(candidate);
                    }
                }
            }
        }
        Ok(candidates)
    }
    async fn find_dependency_candidates(
        &self,
        dependency: &Dependency,
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<Package>> {
        let mut candidates = Vec::new();
        if let Some(package) = repository_manager.get_package(&dependency.name).await? {
            if self.dependency_matches(&package, dependency) {
                candidates.push(package);
            }
        }
        let search_results = repository_manager
            .search_packages(&dependency.name, false, Some(5))
            .await?;
        for package in search_results {
            if self.dependency_matches(&package, dependency)
                && !candidates
                    .iter()
                    .any(|p| p.name == package.name && p.version == package.version)
            {
                candidates.push(package);
            }
        }
        candidates.sort_by(|a, b| self.compare_package_preference(a, b));
        candidates.truncate(5);
        Ok(candidates)
    }
    fn dependency_matches(&self, package: &Package, dependency: &Dependency) -> bool {
        if package.name != dependency.name {
            return false;
        }
        if let Some(ref version_req_str) = dependency.version_req {
            if let Ok(version_req) = VersionReq::parse(version_req_str) {
                if let Ok(version) = Version::parse(&package.version) {
                    if !version_req.matches(&version) {
                        return false;
                    }
                }
            }
        }
        if let Some(ref dep_arch) = dependency.arch {
            if dep_arch != &package.arch {
                return false;
            }
        }
        if let Some(ref dep_os) = dependency.os {
            if !package.arch.contains(dep_os) {
                return false;
            }
        }
        true
    }
    fn should_include_optional(&self, dependency: &Dependency) -> bool {
        match dependency.name.as_str() {
            name if name.contains("dev") || name.contains("debug") => false,
            name if name.contains("doc") || name.contains("man") => false,
            _ => true,
        }
    }
    fn compare_package_preference(&self, a: &Package, b: &Package) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        if self.preferences.prefer_newer_versions {
            if let (Ok(ver_a), Ok(ver_b)) = (Version::parse(&a.version), Version::parse(&b.version))
            {
                let version_cmp = ver_b.cmp(&ver_a);
                if version_cmp != Ordering::Equal {
                    return version_cmp;
                }
            }
        }
        if self.preferences.prefer_trusted_repositories {
            let trust_a = self.get_repository_trust_score(&a.repository);
            let trust_b = self.get_repository_trust_score(&b.repository);
            let trust_cmp = trust_b.partial_cmp(&trust_a).unwrap_or(Ordering::Equal);
            if trust_cmp != Ordering::Equal {
                return trust_cmp;
            }
        }
        if self.preferences.prefer_stable_versions {
            let stable_a = self.is_stable_version(&a.version);
            let stable_b = self.is_stable_version(&b.version);
            match (stable_a, stable_b) {
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                _ => {}
            }
        }
        Ordering::Equal
    }
    fn get_repository_trust_score(&self, repository: &str) -> f64 {
        match repository {
            "packer-core" => 1.0,
            "github-releases" => 0.8,
            "auto-discovered" => 0.5,
            _ => 0.6,
        }
    }
    fn is_stable_version(&self, version: &str) -> bool {
        !version.contains("alpha")
            && !version.contains("beta")
            && !version.contains("rc")
            && !version.contains("dev")
            && !version.contains("pre")
    }
    fn build_constraint_system(
        &mut self,
        packages: &[Package],
        installed: &[Package],
    ) -> PackerResult<()> {
        self.constraints.clear();
        for package in packages {
            let _var_id = self
                .solver
                .add_variable(format!("{}:{}", package.name, package.version));
            for dependency in &package.dependencies {
                self.add_dependency_constraint(package, dependency, packages)?;
            }
            for conflict in &package.conflicts {
                self.add_conflict_constraint(package, conflict, packages)?;
            }
        }
        for package in installed {
            if !packages.iter().any(|p| p.name == package.name) {
                let var_id = self
                    .solver
                    .add_variable(format!("{}:{}", package.name, package.version));
                self.solver.add_clause(vec![var_id as i32 + 1]);
            }
        }
        self.add_global_constraints(packages)?;
        Ok(())
    }
    fn add_dependency_constraint(
        &mut self,
        package: &Package,
        dependency: &Dependency,
        packages: &[Package],
    ) -> PackerResult<()> {
        let package_var = format!("{}:{}", package.name, package.version);
        let package_id = self.solver.add_variable(package_var);
        let mut dependency_vars = Vec::new();
        for candidate in packages {
            if self.dependency_matches(candidate, dependency) {
                let dep_var = format!("{}:{}", candidate.name, candidate.version);
                let dep_id = self.solver.add_variable(dep_var);
                dependency_vars.push(dep_id as i32 + 1);
            }
        }
        if !dependency_vars.is_empty() {
            let mut clause = vec![-(package_id as i32 + 1)];
            clause.extend(dependency_vars);
            self.solver.add_clause(clause);
        }
        Ok(())
    }
    fn add_conflict_constraint(
        &mut self,
        package: &Package,
        conflict: &str,
        packages: &[Package],
    ) -> PackerResult<()> {
        let package_var = format!("{}:{}", package.name, package.version);
        let package_id = self.solver.add_variable(package_var);
        for candidate in packages {
            if candidate.name == conflict || candidate.provides.contains(&conflict.to_string()) {
                let conflict_var = format!("{}:{}", candidate.name, candidate.version);
                let conflict_id = self.solver.add_variable(conflict_var);
                self.solver
                    .add_clause(vec![-(package_id as i32 + 1), -(conflict_id as i32 + 1)]);
            }
        }
        Ok(())
    }
    fn add_global_constraints(&mut self, packages: &[Package]) -> PackerResult<()> {
        let mut package_versions: HashMap<String, Vec<usize>> = HashMap::new();
        for package in packages {
            let var_name = format!("{}:{}", package.name, package.version);
            let var_id = self.solver.add_variable(var_name);
            package_versions
                .entry(package.name.clone())
                .or_default()
                .push(var_id);
        }
        for (_package_name, var_ids) in package_versions {
            if var_ids.len() > 1 {
                for i in 0..var_ids.len() {
                    for j in i + 1..var_ids.len() {
                        self.solver
                            .add_clause(vec![-(var_ids[i] as i32 + 1), -(var_ids[j] as i32 + 1)]);
                    }
                }
            }
        }
        Ok(())
    }
    fn solve_constraints(&mut self) -> PackerResult<HashMap<String, bool>> {
        let start_time = std::time::Instant::now();
        if !self.solver.solve() {
            return Err(PackerError::DependencyConflict(
                "No satisfying assignment found for dependency constraints".to_string(),
            ));
        }
        let solution = self.solver.get_solution();
        let solve_time = start_time.elapsed();
        debug!("SAT solver found solution in {:?}", solve_time);
        Ok(solution)
    }
    fn extract_selected_packages(
        &self,
        solution: HashMap<String, bool>,
        candidates: &[Package],
    ) -> PackerResult<Vec<Package>> {
        let mut selected = Vec::new();
        for package in candidates {
            let var_name = format!("{}:{}", package.name, package.version);
            if solution.get(&var_name) == Some(&true) {
                selected.push(package.clone());
            }
        }
        Ok(selected)
    }
    async fn optimize_selection(
        &self,
        packages: Vec<Package>,
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<Package>> {
        let mut optimized = packages;
        for goal in &self.preferences.optimization_goals {
            optimized = self
                .apply_optimization_goal(optimized, goal, repository_manager)
                .await?;
        }
        Ok(optimized)
    }
    async fn apply_optimization_goal(
        &self,
        mut packages: Vec<Package>,
        goal: &OptimizationGoal,
        _repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<Package>> {
        match goal {
            OptimizationGoal::MinimizeDownloadSize => {
                packages.sort_by_key(|p| p.size);
            }
            OptimizationGoal::MinimizeInstallSize => {
                packages.sort_by_key(|p| p.installed_size);
            }
            OptimizationGoal::MinimizeDependencies => {
                packages.sort_by_key(|p| p.dependencies.len());
            }
            OptimizationGoal::MaximizeStability => {
                packages.sort_by(|a, b| {
                    let stable_a = self.is_stable_version(&a.version);
                    let stable_b = self.is_stable_version(&b.version);
                    stable_b.cmp(&stable_a)
                });
            }
            OptimizationGoal::MaximizeSecurity => {
                packages.sort_by(|a, b| {
                    let trust_a = self.get_repository_trust_score(&a.repository);
                    let trust_b = self.get_repository_trust_score(&b.repository);
                    trust_b
                        .partial_cmp(&trust_a)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            OptimizationGoal::MinimizeConflicts => {
                packages.sort_by_key(|p| p.conflicts.len());
            }
        }
        Ok(packages)
    }
    async fn detect_advanced_conflicts(
        &self,
        packages: &[Package],
    ) -> PackerResult<ConflictCheckResult> {
        let mut conflicts = Vec::new();
        for (i, pkg1) in packages.iter().enumerate() {
            for pkg2 in packages.iter().skip(i + 1) {
                if pkg1.conflicts.contains(&pkg2.name) || pkg2.conflicts.contains(&pkg1.name) {
                    conflicts.push(format!("{} conflicts with {}", pkg1.name, pkg2.name));
                }
                for provides in &pkg1.provides {
                    if pkg2.replaces.contains(provides) {
                        conflicts.push(format!(
                            "{} provides {}, but {} replaces it",
                            pkg1.name, provides, pkg2.name
                        ));
                    }
                }
            }
        }
        Ok(ConflictCheckResult {
            conflicts,
            circular_dependencies: Vec::new(),
            version_conflicts: Vec::new(),
            architecture_conflicts: Vec::new(),
            suggestions: Vec::new(),
        })
    }
    fn calculate_optimal_install_order(&self, packages: &[Package]) -> PackerResult<Vec<String>> {
        let mut graph = petgraph::Graph::new();
        let mut node_map = HashMap::new();
        for package in packages {
            let node = graph.add_node(package.name.clone());
            node_map.insert(package.name.clone(), node);
        }
        for package in packages {
            if let Some(&from_node) = node_map.get(&package.name) {
                for dependency in &package.dependencies {
                    if let Some(&to_node) = node_map.get(&dependency.name) {
                        graph.add_edge(from_node, to_node, ());
                    }
                }
            }
        }
        match petgraph::algo::toposort(&graph, None) {
            Ok(order) => {
                let mut install_order = Vec::new();
                for node in order.into_iter().rev() {
                    install_order.push(graph[node].clone());
                }
                Ok(install_order)
            }
            Err(_) => {
                warn!("Circular dependency detected, using heuristic ordering");
                Ok(packages.iter().map(|p| p.name.clone()).collect())
            }
        }
    }
    fn calculate_package_changes(
        &self,
        selected: &[Package],
        installed: &[Package],
    ) -> PackerResult<(Vec<String>, Vec<(Package, Package)>)> {
        let mut to_remove = Vec::new();
        let mut to_upgrade = Vec::new();
        let selected_names: HashSet<String> = selected.iter().map(|p| p.name.clone()).collect();
        for installed_pkg in installed {
            if !selected_names.contains(&installed_pkg.name) {
                to_remove.push(installed_pkg.name.clone());
            } else if let Some(selected_pkg) =
                selected.iter().find(|p| p.name == installed_pkg.name)
            {
                if let (Ok(installed_ver), Ok(selected_ver)) = (
                    Version::parse(&installed_pkg.version),
                    Version::parse(&selected_pkg.version),
                ) {
                    if selected_ver > installed_ver {
                        to_upgrade.push((installed_pkg.clone(), selected_pkg.clone()));
                    }
                }
            }
        }
        Ok((to_remove, to_upgrade))
    }
    fn calculate_optimization_score(&self, packages: &[Package]) -> f64 {
        let mut score = 0.0;
        let total_size: u64 = packages.iter().map(|p| p.size).sum();
        let total_deps: usize = packages.iter().map(|p| p.dependencies.len()).sum();
        let total_conflicts: usize = packages.iter().map(|p| p.conflicts.len()).sum();
        score += 1000.0 / (total_size as f64 / 1024.0 / 1024.0 + 1.0);
        score += 100.0 / (total_deps as f64 + 1.0);
        score += 200.0 / (total_conflicts as f64 + 1.0);
        for package in packages {
            if self.is_stable_version(&package.version) {
                score += 10.0;
            }
            score += self.get_repository_trust_score(&package.repository) * 5.0;
        }
        score / packages.len() as f64
    }
    pub async fn check_conflicts(&self, packages: &[String]) -> PackerResult<ConflictCheckResult> {
        info!(
            "Performing advanced conflict checking for {} packages",
            packages.len()
        );
        let mut conflicts = Vec::new();
        let circular_dependencies = self.graph.find_circular_dependencies();
        let version_conflicts = self.check_version_conflicts_advanced(packages).await?;
        let architecture_conflicts = self.check_architecture_conflicts_advanced(packages).await?;
        let suggestions = self
            .generate_conflict_suggestions(&version_conflicts, &architecture_conflicts)
            .await?;
        let conflict_info = self.graph.find_conflicts(packages);
        for conflict in conflict_info {
            conflicts.push(format!(
                "{} conflicts with {}: {}",
                conflict.package1, conflict.package2, conflict.reason
            ));
        }
        Ok(ConflictCheckResult {
            conflicts,
            circular_dependencies,
            version_conflicts,
            architecture_conflicts,
            suggestions,
        })
    }
    async fn check_version_conflicts_advanced(
        &self,
        packages: &[String],
    ) -> PackerResult<Vec<VersionConflict>> {
        let mut conflicts = Vec::new();
        let mut version_requirements: HashMap<String, Vec<(String, VersionReq)>> = HashMap::new();
        for package_name in packages {
            if let Some(node) = self.graph.nodes.get(package_name) {
                for dependency in &node.dependencies {
                    if let Some(ref version_req_str) = dependency.version_req {
                        if let Ok(version_req) = VersionReq::parse(version_req_str) {
                            version_requirements
                                .entry(dependency.name.clone())
                                .or_default()
                                .push((package_name.clone(), version_req));
                        }
                    }
                }
            }
        }
        for (dep_package, requirements) in version_requirements {
            if requirements.len() > 1 {
                let mut compatible_versions = None;
                let mut conflicting_packages = Vec::new();
                for (requiring_package, version_req) in &requirements {
                    if compatible_versions.is_none() {
                        compatible_versions = Some(version_req.clone());
                    } else if let Some(ref mut compat) = compatible_versions {
                        if !self.are_version_requirements_compatible(compat, version_req) {
                            conflicting_packages.push(requiring_package.clone());
                        }
                    }
                }
                if !conflicting_packages.is_empty() {
                    conflicts.push(VersionConflict {
                        package: dep_package,
                        required_versions: requirements
                            .iter()
                            .map(|(_, req)| req.to_string())
                            .collect(),
                        conflicting_packages,
                    });
                }
            }
        }
        Ok(conflicts)
    }
    fn are_version_requirements_compatible(&self, req1: &VersionReq, req2: &VersionReq) -> bool {
        let test_versions = ["1.0.0", "1.1.0", "1.2.0", "2.0.0", "2.1.0"];
        for version_str in &test_versions {
            if let Ok(version) = Version::parse(version_str) {
                if req1.matches(&version) && req2.matches(&version) {
                    return true;
                }
            }
        }
        false
    }
    async fn check_architecture_conflicts_advanced(
        &self,
        packages: &[String],
    ) -> PackerResult<Vec<ArchConflict>> {
        let mut conflicts = Vec::new();
        let mut arch_requirements: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for package_name in packages {
            if let Some(node) = self.graph.nodes.get(package_name) {
                for dependency in &node.dependencies {
                    if let Some(ref arch) = dependency.arch {
                        arch_requirements
                            .entry(dependency.name.clone())
                            .or_default()
                            .push((package_name.clone(), arch.clone()));
                    }
                }
            }
        }
        for (dep_package, requirements) in arch_requirements {
            let unique_archs: HashSet<String> =
                requirements.iter().map(|(_, arch)| arch.clone()).collect();
            if unique_archs.len() > 1 {
                conflicts.push(ArchConflict {
                    package: dep_package,
                    required_archs: unique_archs.into_iter().collect(),
                    conflicting_packages: requirements.into_iter().map(|(pkg, _)| pkg).collect(),
                });
            }
        }
        Ok(conflicts)
    }
    async fn generate_conflict_suggestions(
        &self,
        version_conflicts: &[VersionConflict],
        arch_conflicts: &[ArchConflict],
    ) -> PackerResult<Vec<ConflictSuggestion>> {
        let mut suggestions = Vec::new();
        for conflict in version_conflicts {
            suggestions.push(ConflictSuggestion {
                suggestion_type: SuggestionType::UpgradeToCompatible,
                description: format!(
                    "Upgrade conflicting packages to versions compatible with {}",
                    conflict.package
                ),
                packages_to_remove: Vec::new(),
                packages_to_add: Vec::new(),
                packages_to_upgrade: conflict.conflicting_packages.clone(),
            });
        }
        for conflict in arch_conflicts {
            suggestions.push(ConflictSuggestion {
                suggestion_type: SuggestionType::UseAlternative,
                description: format!("Use architecture-specific version of {}", conflict.package),
                packages_to_remove: conflict.conflicting_packages.clone(),
                packages_to_add: vec![format!(
                    "{}-{}",
                    conflict.package, conflict.required_archs[0]
                )],
                packages_to_upgrade: Vec::new(),
            });
        }
        Ok(suggestions)
    }
    fn clear_solver_state(&mut self) {
        self.solver = SATSolver::new();
        self.constraints.clear();
    }
    fn generate_cache_key(&self, packages: &[Package]) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        for package in packages {
            package.name.hash(&mut hasher);
            package.version.hash(&mut hasher);
        }
        format!("{:x}", hasher.finish())
    }
    pub async fn resolve_dependencies(
        &mut self,
        packages: &[Package],
    ) -> PackerResult<ResolutionResult> {
        let start_time = std::time::Instant::now();
        let mut additional_packages = Vec::new();
        let mut resolved_packages = HashSet::new();
        let mut to_resolve = packages.to_vec();
        for package in packages {
            self.add_package_to_graph(package).await?;
            resolved_packages.insert(package.name.clone());
        }
        while let Some(package) = to_resolve.pop() {
            debug!("Resolving dependencies for package: {}", package.name);
            for dependency in &package.dependencies {
                if dependency.optional {
                    continue;
                }
                if resolved_packages.contains(&dependency.name) {
                    continue;
                }
                let candidate = self.find_best_candidate(dependency).await?;
                if let Some(candidate_package) = candidate {
                    debug!(
                        "Found candidate for {}: {} {}",
                        dependency.name, candidate_package.name, candidate_package.version
                    );
                    additional_packages.push(candidate_package.clone());
                    self.add_package_to_graph(&candidate_package).await?;
                    resolved_packages.insert(candidate_package.name.clone());
                    to_resolve.push(candidate_package);
                } else {
                    warn!("No suitable package found for dependency: {}", dependency);
                }
            }
        }
        let all_packages: Vec<String> = packages.iter().map(|p| p.name.clone()).collect();
        let conflict_check = self.check_conflicts(&all_packages).await?;
        let install_order = self.graph.get_install_order(&all_packages)?;
        let resolution_time = start_time.elapsed();
        Ok(ResolutionResult {
            additional_packages,
            conflicts: conflict_check.conflicts,
            install_order,
            removed_packages: Vec::new(),
            upgraded_packages: Vec::new(),
            resolution_time,
            optimization_score: 0.0,
        })
    }
    async fn add_package_to_graph(&mut self, package: &Package) -> PackerResult<()> {
        let resolution = DependencyResolution {
            package: package.name.clone(),
            version: package.version.clone(),
            repository: package.repository.clone(),
            dependencies: package.dependencies.clone(),
            conflicts: package.conflicts.clone(),
            provides: package.provides.clone(),
            replaces: package.replaces.clone(),
        };
        self.graph.add_package(resolution, false);
        for dep in &package.dependencies {
            self.graph.add_dependency_edge(&package.name, &dep.name);
        }
        for conflict in &package.conflicts {
            self.graph.add_conflict_edge(&package.name, conflict);
        }
        for provides in &package.provides {
            self.graph.add_provides_edge(&package.name, provides);
        }
        for replaces in &package.replaces {
            self.graph.add_replaces_edge(&package.name, replaces);
        }
        Ok(())
    }
    async fn find_best_candidate(&self, dependency: &Dependency) -> PackerResult<Option<Package>> {
        debug!("Finding candidate for dependency: {}", dependency);
        if let Some(cached_packages) = self.get_packages_from_cache(&dependency.name) {
            debug!(
                "Found {} cached packages for {}",
                cached_packages.len(),
                dependency.name
            );
            for package in cached_packages {
                if self.dependency_matches(&package, dependency) {
                    debug!(
                        "Found matching cached package: {} {}",
                        package.name, package.version
                    );
                    return Ok(Some(package));
                }
            }
        }
        debug!(
            "No suitable candidate found for dependency: {}",
            dependency.name
        );
        Ok(None)
    }
    pub fn add_package_to_cache(&mut self, name: String, packages: Vec<Package>) {
        self.package_cache.write().insert(name, packages);
    }
    pub fn get_packages_from_cache(&self, name: &str) -> Option<Vec<Package>> {
        self.package_cache.read().get(name).cloned()
    }
    pub fn clear_cache(&mut self) {
        self.package_cache.write().clear();
        self.resolution_cache.write().clear();
    }
    pub fn get_dependency_tree(&self, package: &str) -> PackerResult<Vec<String>> {
        let mut tree = Vec::new();
        let mut visited = HashSet::new();
        self.build_dependency_tree(package, &mut tree, &mut visited)?;
        Ok(tree)
    }
    fn build_dependency_tree(
        &self,
        package: &str,
        tree: &mut Vec<String>,
        visited: &mut HashSet<String>,
    ) -> PackerResult<()> {
        if visited.contains(package) {
            return Ok(());
        }
        visited.insert(package.to_string());
        tree.push(package.to_string());
        Ok(())
    }
    pub fn find_orphaned_packages(
        &self,
        installed_packages: &[String],
    ) -> PackerResult<Vec<String>> {
        let mut orphaned = Vec::new();
        for package in installed_packages {
            let mut is_orphaned = true;
            for other_package in installed_packages {
                if other_package != package {
                    if let Some(node) = self.graph.nodes.get(other_package) {
                        for dep in &node.dependencies {
                            if dep.name == *package {
                                is_orphaned = false;
                                break;
                            }
                        }
                    }
                    if !is_orphaned {
                        break;
                    }
                }
            }
            if is_orphaned {
                orphaned.push(package.clone());
            }
        }
        Ok(orphaned)
    }
    pub fn find_broken_dependencies(
        &self,
        installed_packages: &[String],
    ) -> PackerResult<Vec<String>> {
        let mut broken = Vec::new();
        for package in installed_packages {
            if let Some(node) = self.graph.nodes.get(package) {
                for dep in &node.dependencies {
                    if !installed_packages.contains(&dep.name) {
                        broken.push(format!("{} -> {}", package, dep.name));
                    }
                }
            }
        }
        Ok(broken)
    }
    pub fn suggest_packages(&self, query: &str) -> PackerResult<Vec<String>> {
        let mut suggestions = Vec::new();
        for package_name in self.graph.nodes.keys() {
            if package_name.contains(query) {
                suggestions.push(package_name.clone());
            }
        }
        suggestions.sort_by(|a, b| {
            if a == query {
                std::cmp::Ordering::Less
            } else if b == query {
                std::cmp::Ordering::Greater
            } else {
                a.cmp(b)
            }
        });
        Ok(suggestions)
    }
    pub fn get_package_stats(&self) -> (usize, usize) {
        let total_packages = self.graph.nodes.len();
        let total_edges = self.graph.edges.len();
        (total_packages, total_edges)
    }

    pub async fn resolve_conflicts_intelligently(
        &mut self,
        packages: &[Package],
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<ConflictSuggestion>> {
        let start_time = Instant::now();
        info!(
            "Starting intelligent conflict resolution for {} packages",
            packages.len()
        );

        let conflicts = self.detect_advanced_conflicts(packages).await?;
        if conflicts.conflicts.is_empty() && conflicts.circular_dependencies.is_empty() {
            return Ok(vec![]);
        }

        let mut suggestions = Vec::new();

        for strategy in &self.conflict_resolver.resolution_strategies {
            match strategy {
                ResolutionStrategy::BacktrackSearch => {
                    suggestions.extend(
                        self.backtrack_conflict_resolution(&conflicts, repository_manager)
                            .await?,
                    );
                }
                ResolutionStrategy::ConstraintPropagation => {
                    suggestions.extend(
                        self.constraint_propagation_resolution(&conflicts, repository_manager)
                            .await?,
                    );
                }
                ResolutionStrategy::LocalSearch => {
                    suggestions.extend(
                        self.local_search_resolution(&conflicts, packages, repository_manager)
                            .await?,
                    );
                }
                ResolutionStrategy::HybridApproach => {
                    suggestions.extend(
                        self.hybrid_resolution(&conflicts, packages, repository_manager)
                            .await?,
                    );
                }
                _ => {
                    debug!("Resolution strategy {:?} not yet implemented", strategy);
                }
            }

            if start_time.elapsed() > self.conflict_resolver.heuristics.conflict_timeout {
                warn!("Conflict resolution timeout reached");
                break;
            }
        }

        suggestions.sort_by(|a, b| {
            let score_a = self.calculate_suggestion_score(a);
            let score_b = self.calculate_suggestion_score(b);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(suggestions)
    }

    async fn backtrack_conflict_resolution(
        &self,
        conflicts: &ConflictCheckResult,
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<ConflictSuggestion>> {
        let mut suggestions = Vec::new();

        for conflict in &conflicts.version_conflicts {
            let alternative_versions = self
                .find_compatible_versions(
                    &conflict.package,
                    &conflict.required_versions,
                    repository_manager,
                )
                .await?;

            for version in alternative_versions {
                suggestions.push(ConflictSuggestion {
                    suggestion_type: SuggestionType::UpgradeToCompatible,
                    description: format!(
                        "Upgrade {} to version {} to resolve version conflict",
                        conflict.package, version
                    ),
                    packages_to_remove: vec![],
                    packages_to_add: vec![format!("{}={}", conflict.package, version)],
                    packages_to_upgrade: vec![conflict.package.clone()],
                });
            }
        }

        for circular_dep in &conflicts.circular_dependencies {
            if circular_dep.len() > 1 {
                let optional_deps = self
                    .find_optional_dependencies_in_cycle(circular_dep, repository_manager)
                    .await?;

                for optional_dep in optional_deps {
                    suggestions.push(ConflictSuggestion {
                        suggestion_type: SuggestionType::RelaxConstraints,
                        description: format!(
                            "Make dependency {} optional to break circular dependency",
                            optional_dep
                        ),
                        packages_to_remove: vec![],
                        packages_to_add: vec![],
                        packages_to_upgrade: vec![optional_dep],
                    });
                }
            }
        }

        Ok(suggestions)
    }

    async fn find_compatible_versions(
        &self,
        package_name: &str,
        required_versions: &[String],
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<String>> {
        let mut compatible_versions = Vec::new();

        if let Ok(Some(package)) = repository_manager.get_package(package_name).await {
            let current_version = package.version.clone();

            let available_versions =
                if let Ok(versions) = repository_manager.get_package_versions(package_name).await {
                    versions
                } else {
                    vec![current_version.clone()]
                };

            for version in &available_versions {
                let mut is_compatible = true;

                for required_version in required_versions {
                    if let Ok(version_req) = semver::VersionReq::parse(required_version) {
                        if let Ok(parsed_version) = semver::Version::parse(version) {
                            if !version_req.matches(&parsed_version) {
                                is_compatible = false;
                                break;
                            }
                        }
                    }
                }

                if is_compatible && !compatible_versions.contains(version) {
                    compatible_versions.push(version.clone());
                }
            }

            if compatible_versions.is_empty() {
                compatible_versions.push(current_version);
            }
        }

        Ok(compatible_versions)
    }

    async fn constraint_propagation_resolution(
        &self,
        conflicts: &ConflictCheckResult,
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<ConflictSuggestion>> {
        let mut suggestions = Vec::new();

        for conflict in &conflicts.conflicts {
            let alternatives = repository_manager.find_alternatives(conflict).await?;

            for alternative in alternatives {
                if let Ok(Some(alt_package)) =
                    repository_manager.find_package(&alternative, true).await
                {
                    suggestions.push(ConflictSuggestion {
                        suggestion_type: SuggestionType::UseAlternative,
                        description: format!(
                            "Use {} as alternative to conflicting {}",
                            alternative, conflict
                        ),
                        packages_to_remove: vec![conflict.clone()],
                        packages_to_add: vec![alt_package.name],
                        packages_to_upgrade: vec![],
                    });
                }
            }
        }

        Ok(suggestions)
    }

    async fn local_search_resolution(
        &self,
        conflicts: &ConflictCheckResult,
        packages: &[Package],
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<ConflictSuggestion>> {
        let mut suggestions = Vec::new();
        let mut current_solution = packages.to_vec();

        for _ in 0..10 {
            let improved_solution = self
                .local_search_step(&current_solution, conflicts, repository_manager)
                .await?;

            if self.evaluate_solution_quality(&improved_solution)
                > self.evaluate_solution_quality(&current_solution)
            {
                current_solution = improved_solution;
            }
        }

        let changes = self.compare_solutions(packages, &current_solution);
        if !changes.packages_to_remove.is_empty() || !changes.packages_to_add.is_empty() {
            suggestions.push(changes);
        }

        Ok(suggestions)
    }

    async fn hybrid_resolution(
        &self,
        conflicts: &ConflictCheckResult,
        packages: &[Package],
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<ConflictSuggestion>> {
        let mut suggestions = Vec::new();

        suggestions.extend(
            self.backtrack_conflict_resolution(conflicts, repository_manager)
                .await?,
        );
        suggestions.extend(
            self.constraint_propagation_resolution(conflicts, repository_manager)
                .await?,
        );
        suggestions.extend(
            self.local_search_resolution(conflicts, packages, repository_manager)
                .await?,
        );

        suggestions.dedup_by(|a, b| {
            a.description == b.description
                && a.packages_to_remove == b.packages_to_remove
                && a.packages_to_add == b.packages_to_add
        });

        Ok(suggestions)
    }

    pub async fn optimize_multi_objective(
        &mut self,
        packages: &[Package],
        objectives: &[OptimizationGoal],
    ) -> PackerResult<Vec<Solution>> {
        info!(
            "Starting multi-objective optimization with {} objectives",
            objectives.len()
        );

        let mut solutions = Vec::new();

        for combination in self.generate_solution_combinations(packages) {
            let mut solution = Solution {
                packages: combination.clone(),
                score: 0.0,
                objectives: HashMap::new(),
                trade_offs: Vec::new(),
            };

            for objective in objectives {
                let objective_score = self.evaluate_objective(&combination, objective);
                solution
                    .objectives
                    .insert(objective.clone(), objective_score);
            }

            solution.score = self.calculate_weighted_score(&solution.objectives);
            solution.trade_offs = self.analyze_trade_offs(&solution.objectives);

            solutions.push(solution);
        }

        solutions.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let pareto_optimal = self.extract_pareto_frontier(&solutions);
        self.optimizer.pareto_frontier = pareto_optimal.clone();

        Ok(pareto_optimal)
    }

    fn generate_solution_combinations(&self, packages: &[Package]) -> Vec<Vec<Package>> {
        let mut combinations = Vec::new();

        combinations.push(packages.to_vec());

        for i in 0..packages.len() {
            let mut variant = packages.to_vec();
            variant.remove(i);
            if !variant.is_empty() {
                combinations.push(variant);
            }
        }

        combinations
    }

    fn evaluate_objective(&self, packages: &[Package], objective: &OptimizationGoal) -> f64 {
        match objective {
            OptimizationGoal::MinimizeDownloadSize => {
                let total_size: u64 = packages.iter().map(|p| p.size).sum();
                1.0 / (total_size as f64 + 1.0)
            }
            OptimizationGoal::MinimizeInstallSize => {
                let total_installed_size: u64 = packages.iter().map(|p| p.installed_size).sum();
                1.0 / (total_installed_size as f64 + 1.0)
            }
            OptimizationGoal::MinimizeDependencies => {
                let total_deps: usize = packages.iter().map(|p| p.dependencies.len()).sum();
                1.0 / (total_deps as f64 + 1.0)
            }
            OptimizationGoal::MaximizeStability => {
                packages
                    .iter()
                    .map(|p| {
                        if p.version.contains("stable") {
                            1.0
                        } else {
                            0.5
                        }
                    })
                    .sum::<f64>()
                    / packages.len() as f64
            }
            OptimizationGoal::MaximizeSecurity => {
                packages
                    .iter()
                    .map(|p| self.calculate_security_score(p))
                    .sum::<f64>()
                    / packages.len() as f64
            }
            OptimizationGoal::MinimizeConflicts => {
                let conflict_count = self.count_potential_conflicts(packages);
                1.0 / (conflict_count as f64 + 1.0)
            }
        }
    }

    fn calculate_security_score(&self, package: &Package) -> f64 {
        let mut score: f64 = 1.0;

        if package.signature.is_some() {
            score += 0.3;
        }

        if !package.checksum.is_empty() {
            score += 0.2;
        }

        if package.repository.contains("trusted") {
            score += 0.5;
        }

        score.min(1.0)
    }

    fn count_potential_conflicts(&self, packages: &[Package]) -> usize {
        let mut conflicts = 0;

        for i in 0..packages.len() {
            for j in (i + 1)..packages.len() {
                if packages[i].conflicts.contains(&packages[j].name)
                    || packages[j].conflicts.contains(&packages[i].name)
                {
                    conflicts += 1;
                }
            }
        }

        conflicts
    }

    fn extract_pareto_frontier(&self, solutions: &[Solution]) -> Vec<Solution> {
        let mut frontier = Vec::new();

        for solution in solutions {
            let is_dominated = solutions.iter().any(|other| {
                if std::ptr::eq(solution, other) {
                    return false;
                }

                let dominates = solution.objectives.iter().all(|(objective, &score)| {
                    other
                        .objectives
                        .get(objective)
                        .map_or(false, |&other_score| other_score >= score)
                }) && solution.objectives.iter().any(|(objective, &score)| {
                    other
                        .objectives
                        .get(objective)
                        .map_or(false, |&other_score| other_score > score)
                });

                dominates
            });

            if !is_dominated {
                frontier.push(solution.clone());
            }
        }

        frontier
    }

    fn analyze_trade_offs(&self, objectives: &HashMap<OptimizationGoal, f64>) -> Vec<TradeOff> {
        let mut trade_offs = Vec::new();

        let objectives_vec: Vec<_> = objectives.iter().collect();
        for i in 0..objectives_vec.len() {
            for j in (i + 1)..objectives_vec.len() {
                let (obj1, &score1) = objectives_vec[i];
                let (obj2, &score2) = objectives_vec[j];

                let correlation = self.calculate_objective_correlation(obj1, obj2);
                if correlation < -0.5 {
                    trade_offs.push(TradeOff {
                        objective1: obj1.clone(),
                        objective2: obj2.clone(),
                        impact: (score1 - score2).abs(),
                        description: format!("Trade-off between {:?} and {:?}", obj1, obj2),
                    });
                }
            }
        }

        trade_offs
    }

    fn calculate_objective_correlation(
        &self,
        _obj1: &OptimizationGoal,
        _obj2: &OptimizationGoal,
    ) -> f64 {
        -0.6
    }

    fn calculate_weighted_score(&self, objectives: &HashMap<OptimizationGoal, f64>) -> f64 {
        objectives
            .iter()
            .map(|(objective, &score)| {
                let weight = self.optimizer.weights.get(objective).unwrap_or(&1.0);
                score * weight
            })
            .sum()
    }

    fn calculate_suggestion_score(&self, suggestion: &ConflictSuggestion) -> f64 {
        let mut score: f64 = 1.0;

        match suggestion.suggestion_type {
            SuggestionType::UseAlternative => score += 0.8,
            SuggestionType::UpgradeToCompatible => score += 0.6,
            SuggestionType::RelaxConstraints => score += 0.4,
            SuggestionType::RemoveConflicting => score += 0.2,
        }

        score -= suggestion.packages_to_remove.len() as f64 * 0.1;
        score += suggestion.packages_to_add.len() as f64 * 0.05;

        score
    }

    async fn find_optional_dependencies_in_cycle(
        &self,
        cycle: &[String],
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<String>> {
        let mut optional_deps = Vec::new();

        for package_name in cycle {
            if let Ok(Some(package)) = repository_manager.find_package(package_name, true).await {
                for dep in &package.dependencies {
                    if dep.optional && cycle.contains(&dep.name) {
                        optional_deps.push(dep.name.clone());
                    }
                }
            }
        }

        Ok(optional_deps)
    }

    async fn local_search_step(
        &self,
        current_solution: &[Package],
        conflicts: &ConflictCheckResult,
        repository_manager: &RepositoryManager,
    ) -> PackerResult<Vec<Package>> {
        let mut improved = current_solution.to_vec();

        for conflict in &conflicts.conflicts {
            if let Some(pos) = improved.iter().position(|p| &p.name == conflict) {
                if let Ok(alternatives) = repository_manager.find_alternatives(conflict).await {
                    for alt_name in alternatives {
                        if let Ok(Some(alt_package)) =
                            repository_manager.find_package(&alt_name, true).await
                        {
                            improved[pos] = alt_package;
                            break;
                        }
                    }
                }
            }
        }

        Ok(improved)
    }

    fn evaluate_solution_quality(&self, solution: &[Package]) -> f64 {
        let conflict_penalty = self.count_potential_conflicts(solution) as f64 * -10.0;
        let size_penalty = solution.iter().map(|p| p.size as f64).sum::<f64>() * -0.001;
        let stability_bonus = solution
            .iter()
            .map(|p| {
                if p.version.contains("stable") {
                    5.0
                } else {
                    0.0
                }
            })
            .sum::<f64>();

        100.0 + conflict_penalty + size_penalty + stability_bonus
    }

    fn compare_solutions(&self, original: &[Package], improved: &[Package]) -> ConflictSuggestion {
        let original_names: HashSet<_> = original.iter().map(|p| &p.name).collect();
        let improved_names: HashSet<_> = improved.iter().map(|p| &p.name).collect();

        let to_remove: Vec<String> = original_names
            .difference(&improved_names)
            .map(|&name| name.clone())
            .collect();

        let to_add: Vec<String> = improved_names
            .difference(&original_names)
            .map(|&name| name.clone())
            .collect();

        ConflictSuggestion {
            suggestion_type: SuggestionType::UseAlternative,
            description: "Local search optimization suggestion".to_string(),
            packages_to_remove: to_remove,
            packages_to_add: to_add,
            packages_to_upgrade: vec![],
        }
    }
}
impl Default for DependencyResolver {
    fn default() -> Self {
        Self::new()
    }
}

// Fast Dependency Resolver (from fast_resolver.rs)
#[derive(Debug)]
pub struct FastDependencyResolver {
    max_depth: usize,
    max_resolution_time: std::time::Duration,
    prefer_official: bool,
    dynamic_resolver: Option<DynamicPackageResolver>,
}

impl FastDependencyResolver {
    pub fn new() -> Self {
        Self {
            max_depth: 10,
            max_resolution_time: std::time::Duration::from_secs(10), // Reduced to 10 seconds for faster feedback
            prefer_official: true,
            dynamic_resolver: None,
        }
    }

    pub async fn with_dynamic_resolver(mut self, cache_dir: std::path::PathBuf) -> PackerResult<Self> {
        let mut resolver = DynamicPackageResolver::new(cache_dir);
        resolver.initialize().await?;
        self.dynamic_resolver = Some(resolver);
        info!("Dynamic package resolver initialized");
        Ok(self)
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
        &mut self,
        packages: &[String],
        native_db: &NativePackageDatabase,
        installed_packages: &HashMap<String, CorePackage>,
    ) -> PackerResult<FastResolutionResult> {
        let start_time = std::time::Instant::now();
        info!("Resolving dependencies for: {:?}", packages);
        println!("🔍 Starting dependency resolution for {} package(s)...", packages.len());

        let mut resolution = FastResolutionResult {
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
                println!("📦 Queued package for resolution: {}", package_name);
            } else {
                info!("Package {} is already installed, skipping", package_name);
                println!("✅ Package {} is already installed", package_name);
            }
        }

        let mut progress_counter = 0;
        const MAX_PACKAGES_TO_PROCESS: usize = 1000; // Safety limit to prevent infinite loops
        
        while let Some((package_name, depth)) = to_resolve.pop_front() {
            progress_counter += 1;
            
            if progress_counter > MAX_PACKAGES_TO_PROCESS {
                println!("🛑 Reached maximum package processing limit ({}), stopping to prevent infinite loops", MAX_PACKAGES_TO_PROCESS);
                resolution.warnings.push(format!(
                    "Stopped processing after {} packages to prevent infinite loops",
                    MAX_PACKAGES_TO_PROCESS
                ));
                break;
            }
            
            if progress_counter % 5 == 0 {
                println!("🔄 Processing dependency #{}: {} (depth: {})", progress_counter, package_name, depth);
            }
            
            if start_time.elapsed() > self.max_resolution_time {
                println!("⏰ Dependency resolution timed out after {:?}", self.max_resolution_time);
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

            match self.find_best_package(&package_name, native_db).await {
                Some(package) => {
                    if progress_counter <= 10 || progress_counter % 10 == 0 {
                        println!("✓ Found package: {} v{}", package.name, package.version);
                    }
                    if let Some(conflict) =
                        self.check_conflicts(&package, &resolved_packages, installed_packages)
                    {
                        let is_critical = matches!(conflict.severity, ConflictSeverity::Critical);
                        resolution.conflicts.push(conflict);
                        if is_critical {
                            continue;
                        }
                    }

                    for dep in &package.dependencies {
                        let dep_name = self.parse_dependency_name(dep);
                        if progress_counter <= 10 || progress_counter % 10 == 0 {
                            if dep != &dep_name {
                                println!("  📎 Dependency: {} -> parsed as: {}", dep, dep_name);
                            } else {
                                println!("  📎 Dependency: {}", dep_name);
                            }
                        }
                        
                        if !installed_packages.contains_key(&dep_name)
                            && !resolved_packages.contains_key(&dep_name)
                            && !visited.contains(&dep_name)
                        {
                            to_resolve.push_back((dep_name.clone(), depth + 1));
                            if progress_counter <= 10 || progress_counter % 10 == 0 {
                                println!("    ➕ Added to resolution queue: {}", dep_name);
                            }
                        } else {
                            if progress_counter <= 10 || progress_counter % 10 == 0 {
                                if installed_packages.contains_key(&dep_name) {
                                    println!("    ✅ Already installed: {}", dep_name);
                                } else if resolved_packages.contains_key(&dep_name) {
                                    println!("    ✅ Already resolved: {}", dep_name);
                                } else {
                                    println!("    ⏭️  Already visited: {}", dep_name);
                                }
                            }
                        }
                    }

                    resolved_packages.insert(package_name.clone(), package);
                }
                None => {
                    if progress_counter <= 10 || progress_counter % 10 == 0 {
                        println!("❌ Package not found: {}", package_name);
                    }
                    if self.try_resolve_missing_package(&package_name, &mut resolved_packages, native_db) {
                        println!("🔧 Created system stub for: {}", package_name);
                        continue;
                    }
                    
                    let severity = if package_name.contains(".so") || 
                                     package_name.starts_with("lib") ||
                                     package_name.starts_with("qt5-") ||
                                     package_name.contains("vulkan") ||
                                     package_name.contains("tbb") ||
                                     package_name.contains("fftw") ||
                                     package_name.contains("-driver") ||
                                     package_name.contains("font") ||
                                     package_name.contains("lib32-") ||
                                     self.is_likely_system_library(&package_name) {
                        ConflictSeverity::Warning
                    } else {
                        match package_name.as_str() {
                            name if name.len() < 6 && !name.contains("-") => ConflictSeverity::Critical,
                            _ => ConflictSeverity::Warning
                        }
                    };
                    
                    resolution.conflicts.push(Conflict {
                        package1: package_name.clone(),
                        package2: String::new(),
                        reason: ConflictReason::NotFound {
                            package: package_name.clone(),
                        },
                        severity,
                    });
                }
            }
        }

        resolution.install_order = self.calculate_install_order(&resolved_packages);
        resolution.packages_to_install = resolution
            .install_order
            .iter()
            .filter_map(|name| resolved_packages.get(name).cloned())
            .collect();

        self.validate_resolution(&mut resolution, installed_packages);

        resolution.resolution_time = start_time.elapsed();
        
        println!("✅ Dependency resolution completed in {:?}", resolution.resolution_time);
        println!("📋 Summary: {} packages to install, {} conflicts, {} warnings", 
            resolution.packages_to_install.len(),
            resolution.conflicts.len(),
            resolution.warnings.len());
        
        info!(
            "Dependency resolution completed in {:?}",
            resolution.resolution_time
        );

        Ok(resolution)
    }

    async fn find_best_package(
        &mut self,
        name: &str,
        native_db: &NativePackageDatabase,
    ) -> Option<CorePackage> {
        let resolved_name = self.resolve_library_to_package(name).await;
        let search_name = resolved_name.as_deref().unwrap_or(name);
        
        if search_name != name {
            debug!("Package lookup: {} -> resolved to: {}", name, search_name);
        }
        
        if self.prefer_official {
            if let Some(official_pkg) = native_db.get_official_package(search_name) {
                debug!("Found official package: {} v{}", official_pkg.name, official_pkg.version);
                return Some(official_pkg.clone());
            }
        }

        if let Some(pkg) = native_db.get_package(search_name).cloned() {
            debug!("Found package: {} v{}", pkg.name, pkg.version);
            Some(pkg)
        } else {
            debug!("Package not found: {} (searched as: {})", name, search_name);
            None
        }
    }

    async fn resolve_library_to_package(&mut self, dep_name: &str) -> Option<String> {
        if let Some(resolver) = &mut self.dynamic_resolver {
            if let Some(result) = resolver.resolve_package(dep_name).await {
                return Some(result);
            }
        }
        
        self.resolve_library_to_package_static(dep_name)
    }

    fn resolve_library_to_package_static(&self, dep_name: &str) -> Option<String> {
        if dep_name.ends_with(".so") || dep_name.contains(".so.") {
            let lib_name = if let Some(base) = dep_name.strip_prefix("lib") {
                if let Some(core_name) = base.split(".so").next() {
                    core_name.to_string()
                } else {
                    base.to_string()
                }
            } else {
                if let Some(core_name) = dep_name.split(".so").next() {
                    core_name.to_string()
                } else {
                    dep_name.to_string()
                }
            };
            
            let mapped_name = match lib_name.as_str() {
                "ass" => "libass",
                "bluray" => "libbluray", 
                "bs2b" => "libbs2b",
                "dav1d" => "dav1d",
                "freetype" => "freetype2",
                "harfbuzz" => "harfbuzz",
                "jxl" => "libjxl",
                "openmpt" => "libopenmpt",
                "placebo" => "libplacebo",
                "rav1e" => "rav1e",
                "rsvg-2" => "librsvg",
                "rubberband" => "rubberband",
                "va" | "va-drm" | "va-x11" => "libva",
                "vidstab" => "vid.stab",
                "vorbisenc" | "vorbis" => "libvorbis",
                "vpx" => "libvpx",
                "x264" => "x264",
                "x265" => "x265",
                "xvidcore" => "xvidcore",
                "zimg" => "zimg",
                "zmq" => "zeromq",
                "xkbcommon" => "libxkbcommon",
                "pipewire-0.3" => "pipewire",
                "dbus-1" => "dbus",
                "glib-2.0" => "glib2",
                "ncursesw" => "ncurses",
                "readline" => "readline",
                "systemd" => "systemd-libs",
                "udev" => "systemd-libs",
                "expat" => "expat",
                "ffi" => "libffi",
                "mount" => "util-linux-libs",
                "idn2" => "libidn2",
                "graphite2" => "graphite",
                "gobject-2.0" => "glib2",
                "gio-2.0" => "glib2",
                "sndfile" => "libsndfile",
                "dovi" => "libdovi",
                "lcms2" => "lcms2",
                "shaderc_shared" => "shaderc",
                "vulkan" => "vulkan-icd-loader",
                "INIReader" => "iniparser",
                "ogg" => "libogg",
                "fftw3" => "fftw",
                "samplerate" => "libsamplerate",
                "speexdsp" => "speexdsp",
                "lsmash" => "l-smash",
                _ => &lib_name,
            };
            
            Some(mapped_name.to_string())
        } else {
            match dep_name {
                "jack" => Some("jack2".to_string()),
                "libgl" => Some("mesa".to_string()),
                "onevpl" => Some("intel-media-driver".to_string()),
                "sdl2" => Some("sdl2-compat".to_string()),
                "sh" => Some("bash".to_string()),
                _ => None,
            }
        }
    }

    fn check_conflicts(
        &self,
        package: &CorePackage,
        resolved_packages: &HashMap<String, CorePackage>,
        installed_packages: &HashMap<String, CorePackage>,
    ) -> Option<Conflict> {
        for dep in &package.dependencies {
            let (dep_name, version_req) = self.parse_dependency_with_version(dep);
            
            if let Some(ref version_req) = version_req {
                if version_req.contains("-64") || version_req.len() > 20 {
                    warn!("Skipping malformed version requirement: {} -> {}", dep, version_req);
                    continue;
                }
            }

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
        }

        for conflict_pkg in &package.conflicts {
            if self.is_safe_conflict(&package.name, conflict_pkg) {
                continue;
            }
            
            if resolved_packages.contains_key(conflict_pkg)
                || installed_packages.contains_key(conflict_pkg)
            {
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

    fn is_safe_conflict(&self, package_name: &str, conflict_pkg: &str) -> bool {
        (package_name == "jack2" && conflict_pkg == "jack") 
            || (package_name == "jack" && conflict_pkg == "jack2")
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
        resolution: &mut FastResolutionResult,
        installed_packages: &HashMap<String, CorePackage>,
    ) {
        let package_names: HashSet<String> = resolution
            .packages_to_install
            .iter()
            .map(|p| p.name.clone())
            .collect();

        for package in &resolution.packages_to_install {
            for dep in &package.dependencies {
                let dep_name = self.parse_dependency_name(dep);
                if !package_names.contains(&dep_name) && !installed_packages.contains_key(&dep_name)
                {
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

        info!(
            "Resolution summary: {} official, {} AUR, {} other packages",
            official_count, aur_count, other_count
        );
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
        if requirement.contains("lib32-") || available.contains("lib32-") {
            return true;
        }
        
        if available == "system" {
            return true;
        }
        
        let normalize_version = |v: &str| -> String {
            v.split(&['-', '+'][..]).next().unwrap_or(v).to_string()
        };
        
        let available_base = normalize_version(available);
        
        if requirement.starts_with(">=") {
            let req_version = normalize_version(&requirement[2..]);
            available_base >= req_version
        } else if requirement.starts_with("<=") {
            let req_version = normalize_version(&requirement[2..]);
            available_base <= req_version
        } else if requirement.starts_with("==") || requirement.starts_with("=") {
            let req_version = if requirement.starts_with("==") {
                normalize_version(&requirement[2..])
            } else {
                normalize_version(&requirement[1..])
            };
            if req_version.is_empty() || available_base.is_empty() {
                return true;
            }
            available_base == req_version || available.starts_with(&format!("{}-", req_version))
        } else if requirement.starts_with("!=") {
            let req_version = normalize_version(&requirement[2..]);
            available_base != req_version
        } else if requirement.starts_with(">") {
            let req_version = normalize_version(&requirement[1..]);
            available_base > req_version
        } else if requirement.starts_with("<") {
            let req_version = normalize_version(&requirement[1..]);
            available_base < req_version
        } else {
            true
        }
    }

    fn try_resolve_missing_package(&self, package_name: &str, resolved_packages: &mut HashMap<String, CorePackage>, native_db: &NativePackageDatabase) -> bool {
        // first let's try the name alias thing
        if let Some(real_name) = self.resolve_package_alias(package_name) {
            println!("🔄 Trying package alias: {} → {}", package_name, real_name);
            
            // Try to find the real package
            if let Some(package) = self.search_package_in_all_sources(&real_name, native_db) {
                println!("✅ Found aliased package: {} (as {})", package_name, real_name);
                resolved_packages.insert(package_name.to_string(), package);
                return true;
            }
        }
        
        // ok that didn't work, let's see if it actually exists somewhere
        if self.verify_system_package_exists(package_name) {
            println!("✅ Verified system package exists: {}", package_name);
            
            let stub_package = CorePackage {
                name: package_name.to_string(),
                version: "system-verified".to_string(),
                description: format!("Verified system package: {}", package_name),
                repository: "system".to_string(),
                arch: "x86_64".to_string(),
                download_size: 0,
                installed_size: 0,
                dependencies: Vec::new(),
                conflicts: Vec::new(),
                maintainer: "System".to_string(),
                url: "".to_string(),
                checksum: None,
                source_type: crate::core::SourceType::Official,
                install_date: None,
            };
            
            resolved_packages.insert(package_name.to_string(), stub_package);
            return true;
        }
        
        // Only create unverified stubs for critical system libraries as last resort
        if self.is_critical_system_library(package_name) {
            println!("⚠️  Creating unverified stub for critical library: {}", package_name);
            println!("   This package may need to be installed manually if missing!");
            
            let stub_package = CorePackage {
                name: package_name.to_string(),
                version: "unverified-stub".to_string(),
                description: format!("UNVERIFIED system library: {}", package_name),
                repository: "system".to_string(),
                arch: "x86_64".to_string(),
                download_size: 0,
                installed_size: 0,
                dependencies: Vec::new(),
                conflicts: Vec::new(),
                maintainer: "System".to_string(),
                url: "".to_string(),
                checksum: None,
                source_type: crate::core::SourceType::Official,
                install_date: None,
            };
            
            resolved_packages.insert(package_name.to_string(), stub_package);
            return true;
        }
        
        false
    }

    fn resolve_package_alias(&self, package_name: &str) -> Option<String> {
        // some packages have dumb names so we fix them here
        let aliases = [
            ("jack", "jack2"),
            ("pulse", "pulseaudio"),
            ("alsa", "alsa-lib"),
            ("openssl", "openssl"),
            ("ssl", "openssl"),
            ("crypto", "openssl"),
            ("qt5", "qt5-base"),
            ("qt6", "qt6-base"),
            ("python", "python3"),
            ("pip", "python-pip"),
            ("nodejs", "nodejs"),
            ("node", "nodejs"),
            ("mysql", "mariadb"),
            ("postgresql", "postgresql"),
            ("redis", "redis"),
            ("nginx", "nginx"),
            ("apache", "apache"),
            ("httpd", "apache"),
        ];
        
        aliases.iter()
            .find(|(alias, _)| *alias == package_name)
            .map(|(_, real_name)| real_name.to_string())
    }
    
    fn search_package_in_all_sources(&self, package_name: &str, native_db: &NativePackageDatabase) -> Option<CorePackage> {
        // let's check our own database first
        let packages = native_db.search_packages(package_name);
        if let Some(package) = packages.first() {
            return Some(CorePackage {
                name: package.name.clone(),
                version: package.version.clone(),
                description: package.description.clone(),
                repository: package.repository.clone(),
                arch: package.arch.clone(),
                download_size: package.download_size,
                installed_size: package.installed_size,
                dependencies: package.dependencies.clone(),
                conflicts: package.conflicts.clone(),
                maintainer: package.maintainer.clone(),
                url: package.url.clone(),
                checksum: package.checksum.clone(),
                source_type: match package.repository.as_str() {
                    "extra" | "core" | "community" => crate::core::SourceType::Official,
                    "aur" => crate::core::SourceType::AUR,
                    _ => crate::core::SourceType::Binary,
                },
                install_date: None,
            });
        }
        
        None
    }
    
    fn verify_system_package_exists(&self, package_name: &str) -> bool {
        use std::process::Command;
        
        // let's see if pacman already has this package
        if let Ok(output) = Command::new("pacman")
            .args(&["-Q", package_name])
            .output() {
            if output.status.success() {
                return true;
            }
        }
        
        // maybe it's in the repos even if not installed
        if let Ok(output) = Command::new("pacman")
            .args(&["-Si", package_name])
            .output() {
            if output.status.success() {
                return true;
            }
        }
        
        // if it's a lib, maybe we can find the file somewhere
        if package_name.starts_with("lib") {
            let possible_paths = [
                format!("/usr/lib/{}.so", package_name),
                format!("/usr/lib/lib{}.so", package_name),
                format!("/usr/lib/x86_64-linux-gnu/{}.so", package_name),
                format!("/usr/lib/x86_64-linux-gnu/lib{}.so", package_name),
            ];
            
            for path in &possible_paths {
                if std::path::Path::new(path).exists() {
                    return true;
                }
            }
        }
        
        // last resort: check if it's a program we can run
        if let Ok(output) = Command::new("which")
            .arg(package_name)
            .output() {
            if output.status.success() {
                return true;
            }
        }
        
        false
    }
    
    fn is_critical_system_library(&self, name: &str) -> bool {
        // only make fake packages for really important system stuff
        let critical_libs = [
            "glibc", "gcc-libs", "bash", "coreutils", "systemd",
            "linux", "linux-headers", "glib2", "gtk3", "gtk4",
            "libx11", "libxcb", "mesa", "vulkan-icd-loader",
        ];
        
        critical_libs.contains(&name) ||
        (name.starts_with("lib") && (
            name.contains("x11") || 
            name.contains("gtk") || 
            name.contains("glib") ||
            name.contains("vulkan") ||
            name.contains("mesa") ||
            name.contains("gl")
        ))
    }

    fn is_likely_system_library(&self, name: &str) -> bool {
        let common_system_libs = [
            "glib", "gtk", "cairo", "pango", "gdk", "gio", "gobject",
            "fontconfig", "freetype", "harfbuzz", "pixbuf", "rsvg",
            "webp", "tiff", "png", "jpeg", "gif", "exif", "lcms",
            "poppler", "iniparser", "readline", "ncurses", "expat",
            "zlib", "bzip2", "lzma", "ssl", "crypto", "curl", "xml2",
            "sqlite", "pcre", "boost", "python", "qt5", "qt6",
            "xslt", "fftw", "blas", "lapack", "gsl", "hdf5",
        ];
        
        let name_lower = name.to_lowercase();
        
        if common_system_libs.iter().any(|lib| name_lower.contains(lib)) {
            return true;
        }
        
        if name_lower.starts_with("lib") && (
            name_lower.contains("dev") ||
            name_lower.contains("devel") ||
            name_lower.contains("headers") ||
            name_lower.ends_with("-dev") ||
            name_lower.ends_with("-devel")
        ) {
            return true;
        }
        
        if name_lower.starts_with("lib") && (
            name_lower.contains(".so") ||
            name_lower.matches(char::is_numeric).count() > 0
        ) {
            return true;
        }
        
        false
    }

    pub fn is_critical_conflict(&self, conflicts: &[Conflict]) -> bool {
        conflicts
            .iter()
            .any(|c| c.severity == ConflictSeverity::Critical)
    }

    pub fn format_conflicts(&self, conflicts: &[Conflict]) -> Vec<String> {
        conflicts
            .iter()
            .map(|conflict| match &conflict.reason {
                ConflictReason::VersionConflict {
                    required,
                    available,
                } => {
                    format!(
                        "Version conflict: {} requires {}, but {} is available",
                        conflict.package1, required, available
                    )
                }
                ConflictReason::PackageConflict { conflicts_with } => {
                    format!(
                        "Package conflict: {} conflicts with {}",
                        conflict.package1, conflicts_with
                    )
                }
                ConflictReason::CircularDependency { cycle } => {
                    format!("Circular dependency: {}", cycle.join(" -> "))
                }
                ConflictReason::NotFound { package } => {
                    format!("Package not found: {}", package)
                }
            })
            .collect()
    }
}

impl Default for FastDependencyResolver {
    fn default() -> Self {
        Self::new()
    }
}

// Dynamic Package Resolver (from dynamic_resolver.rs)
#[derive(Debug, Deserialize)]
struct ArchSearchResult {
    results: Vec<ArchPackage>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ArchPackage {
    #[serde(rename = "pkgname")]
    name: String,
    #[serde(rename = "pkgdesc")]
    description: String,
    repo: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PkgsOrgResult {
    packages: Vec<PkgsOrgPackage>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct PkgsOrgPackage {
    name: String,
    repo: String,
    summary: String,
}

#[derive(Debug)]
pub struct DynamicPackageResolver {
    cache: HashMap<String, String>,
    #[allow(dead_code)]
    client: reqwest::Client,
    cache_file: std::path::PathBuf,
}

impl DynamicPackageResolver {
    pub fn new(cache_dir: std::path::PathBuf) -> Self {
        let cache_file = cache_dir.join("dynamic_package_mappings.json");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("packer/0.2.2")
            .build()
            .unwrap_or_default();

        Self {
            cache: HashMap::new(),
            client,
            cache_file,
        }
    }

    pub async fn initialize(&mut self) -> PackerResult<()> {
        self.load_cache().await?;
        Ok(())
    }

    pub async fn resolve_package(&mut self, dependency: &str) -> Option<String> {
        if let Some(cached) = self.cache.get(dependency) {
            debug!("Cache hit for dependency: {} -> {}", dependency, cached);
            return Some(cached.clone());
        }

        if let Some(resolved) = self.try_all_strategies(dependency).await {
            self.cache.insert(dependency.to_string(), resolved.clone());
            if let Err(e) = self.save_cache().await {
                warn!("Failed to save cache: {}", e);
            }
            return Some(resolved);
        }

        None
    }

    async fn try_all_strategies(&self, dependency: &str) -> Option<String> {
        if let Some(result) = self.search_arch_packages(dependency).await {
            info!("Arch search resolved: {} -> {}", dependency, result);
            return Some(result);
        }

        if let Some(result) = self.resolve_library_name(dependency).await {
            info!("Library parsing resolved: {} -> {}", dependency, result);
            return Some(result);
        }

        if let Some(result) = self.search_pkgs_org(dependency).await {
            info!("pkgs.org resolved: {} -> {}", dependency, result);
            return Some(result);
        }

        if let Some(result) = self.apply_smart_heuristics(dependency) {
            info!("Heuristics resolved: {} -> {}", dependency, result);
            return Some(result);
        }

        if let Some(result) = self.fuzzy_match_existing(dependency).await {
            info!("Fuzzy match resolved: {} -> {}", dependency, result);
            return Some(result);
        }

        None
    }

    async fn search_arch_packages(&self, dependency: &str) -> Option<String> {
        let search_terms = self.generate_search_terms(dependency);
        
        for term in search_terms {
            let url = format!(
                "https://archlinux.org/packages/search/json/?name={}",
                urlencoding::encode(&term)
            );

            match timeout(Duration::from_secs(5), self.client.get(&url).send()).await {
                Ok(Ok(response)) => {
                    if let Ok(result) = response.json::<ArchSearchResult>().await {
                        if let Some(package) = result.results.first() {
                            return Some(package.name.clone());
                        }
                    }
                }
                _ => continue,
            }

            let desc_url = format!(
                "https://archlinux.org/packages/search/json/?q={}",
                urlencoding::encode(&term)
            );

            match timeout(Duration::from_secs(5), self.client.get(&desc_url).send()).await {
                Ok(Ok(response)) => {
                    if let Ok(result) = response.json::<ArchSearchResult>().await {
                        for package in result.results {
                            if self.is_relevant_match(&term, &package.name, &package.description) {
                                return Some(package.name);
                            }
                        }
                    }
                }
                _ => continue,
            }
        }

        None
    }

    async fn resolve_library_name(&self, dependency: &str) -> Option<String> {
        let lib_name = self.extract_library_name(dependency);
        
        let candidates = vec![
            lib_name.clone(),
            format!("lib{}", lib_name),
            format!("{}-dev", lib_name),
            format!("lib{}-dev", lib_name),
            format!("{}-devel", lib_name),
            format!("lib{}-devel", lib_name),
            lib_name.replace("_", "-"),
            lib_name.replace("-", "_"),
        ];

        for candidate in candidates {
            if let Some(result) = self.search_arch_packages(&candidate).await {
                return Some(result);
            }
        }

        None
    }

    async fn search_pkgs_org(&self, dependency: &str) -> Option<String> {
        let search_term = self.extract_library_name(dependency);
        let _url = format!(
            "https://pkgs.org/search/?q={}&on=name&arch=x86_64",
            urlencoding::encode(&search_term)
        );

        debug!("Would search pkgs.org for: {}", search_term);
        None
    }

    fn apply_smart_heuristics(&self, dependency: &str) -> Option<String> {
        if dependency.contains(".so") {
            let base_name = dependency
                .split(".so")
                .next()?
                .trim_start_matches("lib");
            
            let candidates = vec![
                base_name.to_string(),
                format!("lib{}", base_name),
                format!("{}-libs", base_name),
                format!("lib{}-libs", base_name),
            ];

            return candidates.first().cloned();
        }

        if dependency.starts_with("lib32-") {
            return Some(dependency.to_string());
        }

        if dependency.starts_with("lib") && !dependency.starts_with("lib32-") {
            let base = &dependency[3..];
            return Some(format!("lib{}", base));
        }

        if let Some(base) = dependency.split('>').next() {
            if let Some(base) = base.split('<').next() {
                if let Some(base) = base.split('=').next() {
                    return Some(base.trim().to_string());
                }
            }
        }

        if dependency.starts_with("python-") || dependency.contains("python") {
            if dependency.starts_with("python3") {
                return Some("python".to_string());
            }
            return Some(dependency.to_string());
        }

        if dependency.contains("qt") || dependency.contains("Qt") {
            if dependency.contains("5") {
                return Some("qt5-base".to_string());
            } else if dependency.contains("6") {
                return Some("qt6-base".to_string());
            }
        }

        None
    }

    async fn fuzzy_match_existing(&self, _dependency: &str) -> Option<String> {
        None
    }

    fn generate_search_terms(&self, dependency: &str) -> Vec<String> {
        let mut terms = Vec::new();
        
        terms.push(dependency.to_string());
        
        let base = self.extract_library_name(dependency);
        if base != dependency {
            terms.push(base.clone());
        }
        
        terms.push(base.replace("_", "-"));
        terms.push(base.replace("-", "_"));
        
        if !base.starts_with("lib") {
            terms.push(format!("lib{}", base));
        } else {
            terms.push(base[3..].to_string());
        }
        
        terms.sort();
        terms.dedup();
        terms
    }

    fn extract_library_name(&self, dependency: &str) -> String {
        let mut name = dependency;
        
        if let Some(pos) = name.find(&['>', '<', '=', '!'][..]) {
            name = &name[..pos];
        }
        
        if let Some(pos) = name.find(".so") {
            name = &name[..pos];
        }
        
        if name.starts_with("lib") && name.len() > 3 {
            name = &name[3..];
        }
        
        let suffixes = ["-dev", "-devel", "-libs", "-headers"];
        for suffix in &suffixes {
            if name.ends_with(suffix) {
                name = &name[..name.len() - suffix.len()];
                break;
            }
        }
        
        name.trim().to_string()
    }

    fn is_relevant_match(&self, search_term: &str, package_name: &str, description: &str) -> bool {
        let search_lower = search_term.to_lowercase();
        let name_lower = package_name.to_lowercase();
        let desc_lower = description.to_lowercase();
        
        if name_lower == search_lower {
            return true;
        }
        
        if name_lower.contains(&search_lower) {
            return true;
        }
        
        if desc_lower.contains(&search_lower) && (
            desc_lower.contains("library") || 
            desc_lower.contains("development") ||
            desc_lower.contains("headers")
        ) {
            return true;
        }
        
        false
    }

    async fn load_cache(&mut self) -> PackerResult<()> {
        if self.cache_file.exists() {
            match tokio::fs::read_to_string(&self.cache_file).await {
                Ok(content) => {
                    if let Ok(cache) = serde_json::from_str::<HashMap<String, String>>(&content) {
                        self.cache = cache;
                        info!("Loaded {} cached package mappings", self.cache.len());
                    }
                }
                Err(e) => warn!("Failed to load cache: {}", e),
            }
        }
        Ok(())
    }

    async fn save_cache(&self) -> PackerResult<()> {
        if let Some(parent) = self.cache_file.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        
        let content = serde_json::to_string_pretty(&self.cache)?;
        tokio::fs::write(&self.cache_file, content).await?;
        
        debug!("Saved {} package mappings to cache", self.cache.len());
        Ok(())
    }

    pub fn get_cache_stats(&self) -> (usize, f64) {
        let total_entries = self.cache.len();
        let hit_rate = 0.0;
        (total_entries, hit_rate)
    }

    pub async fn clear_cache(&mut self) -> PackerResult<()> {
        self.cache.clear();
        if self.cache_file.exists() {
            tokio::fs::remove_file(&self.cache_file).await?;
        }
        info!("Cleared package mapping cache");
        Ok(())
    }
}
