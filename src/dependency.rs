use crate::error::{PackerError, PackerResult};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_req: Option<String>,
    pub arch: Option<String>,
    pub os: Option<String>,
    pub optional: bool,
    pub description: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyResolution {
    pub package: String,
    pub version: String,
    pub repository: String,
    pub dependencies: Vec<Dependency>,
    pub conflicts: Vec<String>,
    pub provides: Vec<String>,
    pub replaces: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub nodes: HashMap<String, DependencyNode>,
    pub edges: Vec<DependencyEdge>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyNode {
    pub package: String,
    pub version: String,
    pub repository: String,
    pub dependencies: Vec<Dependency>,
    pub conflicts: Vec<String>,
    pub provides: Vec<String>,
    pub replaces: Vec<String>,
    pub installed: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub edge_type: EdgeType,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    Depends,
    Conflicts,
    Provides,
    Replaces,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictInfo {
    pub package1: String,
    pub package2: String,
    pub reason: String,
}
impl Dependency {
    pub fn new(name: String) -> Self {
        Self {
            name,
            version_req: None,
            arch: None,
            os: None,
            optional: false,
            description: None,
        }
    }
    pub fn with_version(mut self, version_req: VersionReq) -> Self {
        self.version_req = Some(version_req.to_string());
        self
    }
    pub fn with_arch(mut self, arch: String) -> Self {
        self.arch = Some(arch);
        self
    }
    pub fn with_os(mut self, os: String) -> Self {
        self.os = Some(os);
        self
    }
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
    pub fn matches(&self, package_name: &str, version: &str, arch: &str, os: &str) -> bool {
        if self.name != package_name {
            return false;
        }
        if let Some(ref version_req_str) = self.version_req {
            if let Ok(version_req) = VersionReq::parse(version_req_str) {
                if let Ok(ver) = Version::parse(version) {
                    if !version_req.matches(&ver) {
                        return false;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        if let Some(ref dep_arch) = self.arch {
            if dep_arch != arch {
                return false;
            }
        }
        if let Some(ref dep_os) = self.os {
            if dep_os != os {
                return false;
            }
        }
        true
    }
    pub fn parse(input: &str) -> PackerResult<Self> {
        if input.trim().is_empty() {
            return Err(PackerError::InvalidInput("Empty dependency string".into()));
        }
        let mut parts = input.split_whitespace();
        let name = parts
            .next()
            .ok_or_else(|| PackerError::InvalidInput("Empty dependency string".into()))?
            .to_string();
        let mut dependency = Dependency::new(name);
        for part in parts {
            if part.starts_with('>') || part.starts_with('<') || part.starts_with('=') {
                let version_req = VersionReq::parse(part).map_err(|e| {
                    PackerError::InvalidVersion(format!("Invalid version requirement: {}", e))
                })?;
                dependency.version_req = Some(version_req.to_string());
            } else if part.starts_with("arch=") {
                dependency.arch = Some(part[5..].to_string());
            } else if part.starts_with("os=") {
                dependency.os = Some(part[3..].to_string());
            } else if part == "optional" {
                dependency.optional = true;
            }
        }
        Ok(dependency)
    }
}
impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
        }
    }
    pub fn add_package(&mut self, resolution: DependencyResolution, installed: bool) {
        let node = DependencyNode {
            package: resolution.package.clone(),
            version: resolution.version,
            repository: resolution.repository,
            dependencies: resolution.dependencies,
            conflicts: resolution.conflicts,
            provides: resolution.provides,
            replaces: resolution.replaces,
            installed,
        };
        self.nodes.insert(resolution.package.clone(), node);
    }
    pub fn add_dependency_edge(&mut self, from: &str, to: &str) {
        self.edges.push(DependencyEdge {
            from: from.to_string(),
            to: to.to_string(),
            edge_type: EdgeType::Depends,
        });
    }
    pub fn add_conflict_edge(&mut self, from: &str, to: &str) {
        self.edges.push(DependencyEdge {
            from: from.to_string(),
            to: to.to_string(),
            edge_type: EdgeType::Conflicts,
        });
    }
    pub fn add_provides_edge(&mut self, from: &str, to: &str) {
        self.edges.push(DependencyEdge {
            from: from.to_string(),
            to: to.to_string(),
            edge_type: EdgeType::Provides,
        });
    }
    pub fn add_replaces_edge(&mut self, from: &str, to: &str) {
        self.edges.push(DependencyEdge {
            from: from.to_string(),
            to: to.to_string(),
            edge_type: EdgeType::Replaces,
        });
    }
    pub fn get_dependencies(&self, package: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|edge| edge.from == package && matches!(edge.edge_type, EdgeType::Depends))
            .map(|edge| edge.to.as_str())
            .collect()
    }
    pub fn get_conflicts(&self, package: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|edge| edge.from == package && matches!(edge.edge_type, EdgeType::Conflicts))
            .map(|edge| edge.to.as_str())
            .collect()
    }
    pub fn get_provides(&self, package: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|edge| edge.from == package && matches!(edge.edge_type, EdgeType::Provides))
            .map(|edge| edge.to.as_str())
            .collect()
    }
    pub fn get_replaces(&self, package: &str) -> Vec<&str> {
        self.edges
            .iter()
            .filter(|edge| edge.from == package && matches!(edge.edge_type, EdgeType::Replaces))
            .map(|edge| edge.to.as_str())
            .collect()
    }
    pub fn find_circular_dependencies(&self) -> Vec<Vec<String>> {
        use petgraph::algo::tarjan_scc;
        use petgraph::graphmap::DiGraphMap;
        let mut graph: DiGraphMap<&str, ()> = DiGraphMap::new();
        for package in self.nodes.keys() {
            graph.add_node(package.as_str());
        }
        for edge in &self.edges {
            if matches!(edge.edge_type, EdgeType::Depends) {
                graph.add_edge(edge.from.as_str(), edge.to.as_str(), ());
            }
        }
        let sccs = tarjan_scc(&graph);
        sccs.into_iter()
            .filter(|scc| scc.len() > 1)
            .map(|scc| scc.into_iter().map(|s| s.to_string()).collect())
            .collect()
    }
    pub fn find_conflicts(&self, packages: &[String]) -> Vec<ConflictInfo> {
        let mut conflicts = Vec::new();
        for (i, pkg1) in packages.iter().enumerate() {
            for pkg2 in packages.iter().skip(i + 1) {
                if let (Some(node1), Some(node2)) = (self.nodes.get(pkg1), self.nodes.get(pkg2)) {
                    if node1.conflicts.contains(pkg2) || node2.conflicts.contains(pkg1) {
                        conflicts.push(ConflictInfo {
                            package1: pkg1.clone(),
                            package2: pkg2.clone(),
                            reason: "Direct conflict".to_string(),
                        });
                        continue;
                    }
                    for provides in &node1.provides {
                        if node2.replaces.contains(provides) {
                            conflicts.push(ConflictInfo {
                                package1: pkg1.clone(),
                                package2: pkg2.clone(),
                                reason: format!(
                                    "{} provides {}, {} replaces {}",
                                    pkg1, provides, pkg2, provides
                                ),
                            });
                        }
                    }
                    for provides in &node2.provides {
                        if node1.replaces.contains(provides) {
                            conflicts.push(ConflictInfo {
                                package1: pkg1.clone(),
                                package2: pkg2.clone(),
                                reason: format!(
                                    "{} provides {}, {} replaces {}",
                                    pkg2, provides, pkg1, provides
                                ),
                            });
                        }
                    }
                }
            }
        }
        conflicts
    }
    pub fn topological_sort(&self) -> PackerResult<Vec<String>> {
        use petgraph::algo::toposort;
        use petgraph::graphmap::DiGraphMap;
        let mut graph: DiGraphMap<&str, ()> = DiGraphMap::new();
        for package in self.nodes.keys() {
            graph.add_node(package.as_str());
        }
        for edge in &self.edges {
            if matches!(edge.edge_type, EdgeType::Depends) {
                graph.add_edge(edge.from.as_str(), edge.to.as_str(), ());
            }
        }
        match toposort(&graph, None) {
            Ok(order) => Ok(order.into_iter().map(|s| s.to_string()).collect()),
            Err(_) => Err(PackerError::CircularDependency(
                "Circular dependency detected during topological sort".to_string(),
            )),
        }
    }
    pub fn get_install_order(&self, packages: &[String]) -> PackerResult<Vec<String>> {
        let mut subgraph = DependencyGraph::new();
        let mut to_add = packages.to_vec();
        let mut added = std::collections::HashSet::new();
        while let Some(package) = to_add.pop() {
            if added.contains(&package) {
                continue;
            }
            if let Some(node) = self.nodes.get(&package) {
                subgraph.add_package(
                    DependencyResolution {
                        package: node.package.clone(),
                        version: node.version.clone(),
                        repository: node.repository.clone(),
                        dependencies: node.dependencies.clone(),
                        conflicts: node.conflicts.clone(),
                        provides: node.provides.clone(),
                        replaces: node.replaces.clone(),
                    },
                    node.installed,
                );
                for dep in &node.dependencies {
                    if !added.contains(&dep.name) {
                        to_add.push(dep.name.clone());
                    }
                }
                added.insert(package);
            }
        }
        for edge in &self.edges {
            if added.contains(&edge.from) && added.contains(&edge.to) {
                match edge.edge_type {
                    EdgeType::Depends => subgraph.add_dependency_edge(&edge.from, &edge.to),
                    EdgeType::Conflicts => subgraph.add_conflict_edge(&edge.from, &edge.to),
                    EdgeType::Provides => subgraph.add_provides_edge(&edge.from, &edge.to),
                    EdgeType::Replaces => subgraph.add_replaces_edge(&edge.from, &edge.to),
                }
            }
        }
        subgraph.topological_sort()
    }
}
impl std::fmt::Display for Dependency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref version_req) = self.version_req {
            write!(f, " {}", version_req)?;
        }
        if let Some(ref arch) = self.arch {
            write!(f, " arch={}", arch)?;
        }
        if let Some(ref os) = self.os {
            write!(f, " os={}", os)?;
        }
        if self.optional {
            write!(f, " optional")?;
        }
        Ok(())
    }
}
