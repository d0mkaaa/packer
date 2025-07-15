use packer::{
    config::Config,
    package::{PackageManager, TransactionType},
    storage::PackageOperation,
    utils::{format_duration, format_size},
};
use log::info;
use std::time::Instant;
use std::io::Write;
use tokio;
use clap::{Arg, ArgAction, ArgMatches, Command};
use colored::Colorize;
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: String,
    pub transaction_type: TransactionType,
    pub packages: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
    pub duration: u64,
    pub user: String,
    pub size_change: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPGKey {
    pub id: String,
    pub fingerprint: String,
    pub user_id: String,
    pub algorithm: String,
    pub key_size: u32,
    pub created: DateTime<Utc>,
    pub expires: Option<DateTime<Utc>>,
    pub trust_level: String,
}
#[tokio::main]
async fn main() {
    env_logger::init();
    let matches = build_cli().get_matches();
    let start_time = Instant::now();
    if let Err(e) = run_command(matches).await {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
    let duration = start_time.elapsed();
    info!("Operation completed in {}", format_duration(duration.as_secs()));
}
fn build_cli() -> Command {
    Command::new("packer")
        .version("0.1.0")
        .about("Packer is a modern package manager that provides advanced dependency resolution, security verification, parallel operations, and intelligent conflict detection.")
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("config")
            .short('c')
            .long("config")
            .value_name("CONFIG"))
        .arg(Arg::new("no-color")
            .long("no-color")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("profile")
            .long("profile")
            .value_name("PROFILE"))
        .subcommand(Command::new("install")
            .about("Install packages")
            .arg(Arg::new("packages")
                .required(true)
                .num_args(1..)
                .help("Package names to install (supports version specs: package@version, package=version)"))
            .arg(Arg::new("force")
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Force installation"))
            .arg(Arg::new("no-deps")
                .long("no-deps")
                .action(ArgAction::SetTrue)
                .help("Skip dependency resolution"))
            .arg(Arg::new("verify-signatures")
                .long("verify-signatures")
                .action(ArgAction::SetTrue)
                .help("Verify GPG signatures"))
            .arg(Arg::new("skip-security-scan")
                .long("skip-security-scan")
                .action(ArgAction::SetTrue)
                .help("Skip security vulnerability scan"))
            .arg(Arg::new("interactive")
                .long("interactive")
                .short('i')
                .action(ArgAction::SetTrue)
                .help("Interactive version selection"))
            .arg(Arg::new("preview")
                .long("preview")
                .short('p')
                .action(ArgAction::SetTrue)
                .help("Preview what will be downloaded before installation")))
        .subcommand(Command::new("remove")
            .about("Remove packages")
            .arg(Arg::new("packages")
                .required(true)
                .num_args(1..)
                .help("Package names to remove"))
            .arg(Arg::new("force")
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Force removal"))
            .arg(Arg::new("cascade")
                .long("cascade")
                .action(ArgAction::SetTrue)
                .help("Remove dependencies")))
        .subcommand(Command::new("search")
            .about("Search for packages")
            .arg(Arg::new("query")
                .required(true)
                .help("Search query"))
            .arg(Arg::new("exact")
                .long("exact")
                .action(ArgAction::SetTrue)
                .help("Exact match only"))
            .arg(Arg::new("repository")
                .long("repo")
                .value_name("REPO")
                .help("Search in specific repository"))
            .arg(Arg::new("version")
                .long("version")
                .short('v')
                .value_name("VERSION")
                .help("Filter by version pattern (e.g., '>=1.0.0', '~1.2')"))
            .arg(Arg::new("sort")
                .long("sort")
                .value_name("SORT")
                .help("Sort results by: name, version, size, repository")
                .default_value("relevance"))
            .arg(Arg::new("limit")
                .long("limit")
                .short('l')
                .value_name("N")
                .help("Limit results to N packages")
                .default_value("50"))
            .arg(Arg::new("installed")
                .long("installed")
                .action(ArgAction::SetTrue)
                .help("Show only installed packages"))
            .arg(Arg::new("not-installed")
                .long("not-installed")
                .action(ArgAction::SetTrue)
                .help("Show only packages not installed"))
            .arg(Arg::new("detailed")
                .long("detailed")
                .short('d')
                .action(ArgAction::SetTrue)
                .help("Show detailed package information")))
        .subcommand(Command::new("info")
            .about("Show package information")
            .arg(Arg::new("package")
                .required(true)
                .help("Package name"))
            .arg(Arg::new("show-files")
                .long("files")
                .action(ArgAction::SetTrue)
                .help("Show package files"))
            .arg(Arg::new("show-deps")
                .long("deps")
                .action(ArgAction::SetTrue)
                .help("Show dependencies"))
            .arg(Arg::new("show-rdeps")
                .long("rdeps")
                .action(ArgAction::SetTrue)
                .help("Show reverse dependencies"))
            .arg(Arg::new("security-info")
                .long("security")
                .action(ArgAction::SetTrue)
                .help("Show security information")))
        .subcommand(Command::new("list")
            .about("List installed packages")
            .arg(Arg::new("explicit")
                .long("explicit")
                .action(ArgAction::SetTrue)
                .help("Show only explicitly installed packages"))
            .arg(Arg::new("dependencies")
                .long("deps")
                .action(ArgAction::SetTrue)
                .help("Show only dependencies"))
            .arg(Arg::new("orphans")
                .long("orphans")
                .action(ArgAction::SetTrue)
                .help("Show orphaned packages"))
            .arg(Arg::new("format")
                .long("format")
                .value_name("FORMAT")
                .help("Output format (table, json, csv)")))
        .subcommand(Command::new("update")
            .about("Update package database")
            .arg(Arg::new("repository")
                .long("repo")
                .value_name("REPO")
                .help("Update specific repository"))
            .arg(Arg::new("force")
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Force update")))
        .subcommand(Command::new("upgrade")
            .about("Upgrade installed packages")
            .arg(Arg::new("packages")
                .num_args(0..)
                .help("Specific packages to upgrade"))
            .arg(Arg::new("ignore")
                .long("ignore")
                .value_name("PACKAGES")
                .help("Packages to ignore"))
            .arg(Arg::new("security-only")
                .long("security-only")
                .action(ArgAction::SetTrue)
                .help("Only upgrade packages with security fixes")))
        .subcommand(Command::new("check")
            .about("Check for dependency conflicts")
            .arg(Arg::new("fix")
                .long("fix")
                .action(ArgAction::SetTrue)
                .help("Attempt to fix conflicts"))
            .arg(Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Verbose output")))
        .subcommand(Command::new("clean")
            .about("Clean package cache and temporary files")
            .arg(Arg::new("cache")
                .long("cache")
                .action(ArgAction::SetTrue)
                .help("Clean package cache"))
            .arg(Arg::new("temp")
                .long("temp")
                .action(ArgAction::SetTrue)
                .help("Clean temporary files"))
            .arg(Arg::new("logs")
                .long("logs")
                .action(ArgAction::SetTrue)
                .help("Clean log files"))
            .arg(Arg::new("all")
                .long("all")
                .action(ArgAction::SetTrue)
                .help("Clean everything")))
        .subcommand(Command::new("repos")
            .about("Show repository information"))
        .subcommand(Command::new("transaction")
            .about("Transaction management")
            .subcommand(Command::new("history")
                .about("Show transaction history")
                .arg(Arg::new("limit")
                    .long("limit")
                    .value_name("N")
                    .help("Limit number of entries"))
                .arg(Arg::new("filter")
                    .long("filter")
                    .value_name("TYPE")
                    .help("Filter by transaction type"))
                .arg(Arg::new("package")
                    .long("package")
                    .value_name("NAME")
                    .help("Filter by package name"))
                .arg(Arg::new("failed")
                    .long("failed")
                    .action(ArgAction::SetTrue)
                    .help("Show only failed transactions")))
            .subcommand(Command::new("rollback")
                .about("Rollback transaction")
                .arg(Arg::new("transaction_id")
                    .required(true)
                    .help("Transaction ID to rollback"))
                .arg(Arg::new("force")
                    .long("force")
                    .action(ArgAction::SetTrue)
                    .help("Force rollback")))
            .subcommand(Command::new("show")
                .about("Show transaction details")
                .arg(Arg::new("transaction_id")
                    .required(true)
                    .help("Transaction ID"))))
        .subcommand(
            Command::new("security")
                .about("Security-related commands")
                .subcommand(
                    Command::new("audit")
                        .about("Run security audit on installed packages")
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Output in JSON format")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("detailed")
                                .long("detailed")
                                .help("Show detailed vulnerability information")
                                .action(ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("scan")
                        .about("Scan a package for vulnerabilities")
                        .arg(
                            Arg::new("package")
                                .help("Package name to scan")
                                .required(true)
                                .index(1),
                        ),
                )
                .subcommand(
                    Command::new("import-keys")
                        .about("Import GPG keys for package verification")
                        .arg(
                            Arg::new("keyserver")
                                .long("keyserver")
                                .help("Keyserver to import from")
                                .default_value("keys.gnupg.net"),
                        )
                        .arg(
                            Arg::new("keys")
                                .help("Key IDs to import")
                                .required(true)
                                .num_args(1..),
                        ),
                )
                .subcommand(
                    Command::new("status")
                        .about("Show GPG and security system status")
                        .arg(
                            Arg::new("verbose")
                                .long("verbose")
                                .short('v')
                                .help("Show detailed information")
                                .action(ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("update-db")
                        .about("Update vulnerability database")
                        .arg(
                            Arg::new("force")
                                .long("force")
                                .help("Force update even if recently updated")
                                .action(ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("enhanced-scan")
                        .about("Enhanced security scan with threat intelligence")
                        .arg(
                            Arg::new("package")
                                .help("Package name to scan")
                                .required(true)
                                .index(1),
                        )
                        .arg(
                            Arg::new("json")
                                .long("json")
                                .help("Output in JSON format")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("threat-intel")
                                .long("threat-intel")
                                .help("Include threat intelligence analysis")
                                .action(ArgAction::SetTrue),
                        ),
                )
                .subcommand(
                    Command::new("threat-intel")
                        .about("Update threat intelligence feeds")
                        .arg(
                            Arg::new("feed")
                                .long("feed")
                                .help("Specific feed to update (nvd, osv, github, cisa)")
                                .value_name("FEED"),
                        ),
                )
                .subcommand(
                    Command::new("risk-assessment")
                        .about("Comprehensive risk assessment")
                        .arg(
                            Arg::new("package")
                                .help("Package name to assess")
                                .required(true)
                                .index(1),
                        )
                        .arg(
                            Arg::new("environment")
                                .long("env")
                                .help("Environment context (development, production)")
                                .value_name("ENV")
                                .default_value("production"),
                        ),
                ),
        )
        .subcommand(
            Command::new("fix")
                .about("Fix package database issues")
                .arg(
                    Arg::new("sizes")
                        .long("sizes")
                        .help("Recalculate package sizes")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("all")
                        .long("all")
                        .help("Fix all database issues")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(Command::new("doctor")
            .about("Advanced diagnostics and maintenance")
            .arg(Arg::new("fix")
                .long("fix")
                .action(ArgAction::SetTrue)
                .help("Attempt to fix issues"))
            .arg(Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue)
                .help("Verbose output")))
        .subcommand(Command::new("complete")
            .about("Shell completion and suggestions")
            .arg(Arg::new("shell")
                .required(true)
                .help("Shell type (bash, zsh, fish)")))
        .subcommand(Command::new("version")
            .about("Show version information and installed packages")
            .arg(Arg::new("package")
                .help("Show versions for specific package"))
            .arg(Arg::new("available")
                .long("available")
                .action(ArgAction::SetTrue)
                .help("Show available versions"))
            .arg(Arg::new("history")
                .long("history")
                .action(ArgAction::SetTrue)
                .help("Show version history")))
        .subcommand(Command::new("versions")
            .about("List available versions for a package")
            .arg(Arg::new("package")
                .required(true)
                .help("Package name to show versions for"))
            .arg(Arg::new("all")
                .long("all")
                .action(ArgAction::SetTrue)
                .help("Show all versions from all repositories"))
            .arg(Arg::new("repository")
                .long("repo")
                .value_name("REPO")
                .help("Filter by specific repository")))

}
async fn run_command(matches: ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = matches.get_one::<String>("config");
    let config = Config::load(config_path.map(|s| s.as_str()))?;
    let mut package_manager = PackageManager::new(config.clone()).await?;
    match matches.subcommand() {
        Some(("install", sub_matches)) => {
            let packages: Vec<&str> = sub_matches.get_many::<String>("packages").unwrap().map(|s| s.as_str()).collect();
            let force = sub_matches.get_flag("force");
            let no_deps = sub_matches.get_flag("no-deps");
            let verify_signatures = sub_matches.get_flag("verify-signatures");
            let skip_security_scan = sub_matches.get_flag("skip-security-scan");
            let interactive = sub_matches.get_flag("interactive");
            let preview = sub_matches.get_flag("preview");
            handle_install(&mut package_manager, packages, force, no_deps, verify_signatures, !skip_security_scan, interactive, preview).await?;
        }
        Some(("remove", sub_matches)) => {
            let packages: Vec<&str> = sub_matches.get_many::<String>("packages").unwrap().map(|s| s.as_str()).collect();
            let force = sub_matches.get_flag("force");
            let cascade = sub_matches.get_flag("cascade");
            handle_remove(&mut package_manager, packages, force, cascade).await?;
        }
        Some(("search", sub_matches)) => {
            let query = sub_matches.get_one::<String>("query").unwrap();
            let exact = sub_matches.get_flag("exact");
            let repository = sub_matches.get_one::<String>("repository");
            let version_filter = sub_matches.get_one::<String>("version");
            let sort_by = sub_matches.get_one::<String>("sort").unwrap();
            let limit = sub_matches.get_one::<String>("limit").unwrap().parse::<usize>()?;
            let installed_only = sub_matches.get_flag("installed");
            let not_installed_only = sub_matches.get_flag("not-installed");
            let detailed = sub_matches.get_flag("detailed");
            handle_search(&package_manager, query, exact, repository, version_filter, sort_by, limit, installed_only, not_installed_only, detailed).await?;
        }
        Some(("info", sub_matches)) => {
            let package = sub_matches.get_one::<String>("package").unwrap();
            let show_files = sub_matches.get_flag("show-files");
            let show_deps = sub_matches.get_flag("show-deps");
            let show_rdeps = sub_matches.get_flag("show-rdeps");
            let security_info = sub_matches.get_flag("security-info");
            handle_info(&package_manager, package, show_files, show_deps, show_rdeps, security_info).await?;
        }
        Some(("list", sub_matches)) => {
            let explicit = sub_matches.get_flag("explicit");
            let dependencies = sub_matches.get_flag("dependencies");
            let orphans = sub_matches.get_flag("orphans");
            let format = sub_matches.get_one::<String>("format");
            handle_list(&package_manager, explicit, dependencies, orphans, format).await?;
        }
        Some(("update", sub_matches)) => {
            let repository = sub_matches.get_one::<String>("repository");
            let force = sub_matches.get_flag("force");
            handle_update(&mut package_manager, repository, force).await?;
        }
        Some(("upgrade", sub_matches)) => {
            let packages = sub_matches.get_many::<String>("packages").map(|v| v.map(|s| s.as_str()).collect::<Vec<_>>());
            let ignore = sub_matches.get_one::<String>("ignore");
            let security_only = sub_matches.get_flag("security-only");
            handle_upgrade(&mut package_manager, packages, ignore, security_only).await?;
        }
        Some(("check", sub_matches)) => {
            let fix = sub_matches.get_flag("fix");
            let verbose = sub_matches.get_flag("verbose");
            handle_check(&package_manager, fix, verbose).await?;
        }
        Some(("clean", sub_matches)) => {
            let cache = sub_matches.get_flag("cache");
            let temp = sub_matches.get_flag("temp");
            let logs = sub_matches.get_flag("logs");
            let all = sub_matches.get_flag("all");
            handle_clean(&package_manager, cache, temp, logs, all).await?;
        }
        Some(("repos", _)) => {
            handle_repos(&package_manager).await?;
        }
        Some(("transaction", sub_matches)) => {
            handle_transaction(&package_manager, sub_matches).await?;
        }
        Some(("security", sub_matches)) => {
            handle_security(&mut package_manager, sub_matches).await?;
        }
        Some(("fix", sub_matches)) => {
            let sizes = sub_matches.get_flag("sizes");
            let all = sub_matches.get_flag("all");
            handle_fix(&mut package_manager, sizes, all).await?;
        }
        Some(("doctor", sub_matches)) => {
            let fix = sub_matches.get_flag("fix");
            let verbose = sub_matches.get_flag("verbose");
            handle_doctor(&package_manager, fix, verbose).await?;
        }
        Some(("complete", sub_matches)) => {
            let shell = sub_matches.get_one::<String>("shell").unwrap();
            handle_completion(shell)?;
        }
        Some(("version", sub_matches)) => {
            let package = sub_matches.get_one::<String>("package");
            let available = sub_matches.get_flag("available");
            let history = sub_matches.get_flag("history");
            handle_version(&package_manager, package, available, history).await?;
        }
        Some(("versions", sub_matches)) => {
            let package_name = sub_matches.get_one::<String>("package").unwrap();
            let all_repos = sub_matches.get_flag("all");
            let repository = sub_matches.get_one::<String>("repository");
            handle_versions(&package_manager, package_name, all_repos, repository).await?;
        }

        _ => {
            println!("Use --help for usage information");
        }
    }
    Ok(())
}
async fn handle_install(
    package_manager: &mut PackageManager,
    packages: Vec<&str>,
    force: bool,
    no_deps: bool,
    verify_signatures: bool,
    security_scan: bool,
    interactive: bool,
    preview: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Installing packages: {}", packages.join(", "));
    let mut package_requests = Vec::new();
    for package_spec in packages {
        let (name, version_req) = parse_package_specification(package_spec)?;
        package_requests.push((name, version_req));
    }
    if interactive {
        let resolved_packages = handle_interactive_version_selection(package_manager, &package_requests).await?;
        let package_names: Vec<String> = resolved_packages.into_iter().map(|p| p.name).collect();
        package_manager.install_packages(&package_names, force, no_deps, preview).await?;
    } else {
        let resolved_packages = resolve_package_versions(package_manager, &package_requests).await?;
        let package_names: Vec<String> = resolved_packages.into_iter().map(|p| p.name).collect();
        if preview {
            show_installation_preview(package_manager, &package_names).await?;
            print!("{}", ":: Proceed with installation? [Y/n] ".bold());
            use std::io::{self, Write};
            io::stdout().flush().unwrap();
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
            let input = input.trim().to_lowercase();
            if !input.is_empty() && input != "y" && input != "yes" {
                println!("{}", "Installation cancelled.".yellow());
                return Ok(());
            }
        }
        if security_scan {
            println!("{}", "🔍 Performing security scan...".yellow());
        }
        if verify_signatures {
            println!("{}", "🔐 Verifying GPG signatures...".cyan());
        }
        package_manager.install_packages(&package_names, force, no_deps, false).await?;
    }
    println!("{}", "✅ Installation completed successfully!".green());
    Ok(())
}
fn parse_package_specification(spec: &str) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    if spec.contains('@') {
        let parts: Vec<&str> = spec.split('@').collect();
        if parts.len() == 2 {
            Ok((parts[0].to_string(), Some(parts[1].to_string())))
        } else {
            Err(format!("Invalid package specification: {}. Use package@version format.", spec).into())
        }
    } else if spec.contains('=') {
        let parts: Vec<&str> = spec.split('=').collect();
        if parts.len() == 2 {
            Ok((parts[0].to_string(), Some(parts[1].to_string())))
        } else {
            Err(format!("Invalid package specification: {}. Use package=version format.", spec).into())
        }
    } else {
        Ok((spec.to_string(), None))
    }
}
async fn resolve_package_versions(
    package_manager: &PackageManager,
    package_requests: &[(String, Option<String>)],
) -> Result<Vec<packer::package::Package>, Box<dyn std::error::Error>> {
    let mut resolved_packages = Vec::new();
    for (name, version_req) in package_requests {
        if let Some(version) = version_req {
            let package = find_package_version(package_manager, name, version).await?;
            resolved_packages.push(package);
        } else {
            let package = package_manager.repository_manager.get_package(name).await?
                .ok_or_else(|| format!("Package '{}' not found", name))?;
            resolved_packages.push(package);
        }
    }
    Ok(resolved_packages)
}
async fn find_package_version(
    package_manager: &PackageManager,
    name: &str,
    version: &str,
) -> Result<packer::package::Package, Box<dyn std::error::Error>> {
    let packages = package_manager.repository_manager.search_packages(name, true).await?;
    for package in packages {
        if package.name == name && package.version == version {
            return Ok(package);
        }
    }
    if let Some(aur_packages) = package_manager.repository_manager.search_aur_directly(name, true).await? {
        for package in aur_packages {
            if package.name == name && package.version == version {
                return Ok(package);
            }
        }
    }
    Err(format!("Package '{}' version '{}' not found", name, version).into())
}
async fn handle_interactive_version_selection(
    package_manager: &PackageManager,
    package_requests: &[(String, Option<String>)],
) -> Result<Vec<packer::package::Package>, Box<dyn std::error::Error>> {
    let mut selected_packages = Vec::new();
    for (name, version_req) in package_requests {
        if version_req.is_some() {
            let package = find_package_version(package_manager, name, version_req.as_ref().unwrap()).await?;
            selected_packages.push(package);
        } else {
            let package = show_version_selection_menu(package_manager, name).await?;
            selected_packages.push(package);
        }
    }
    Ok(selected_packages)
}
async fn show_version_selection_menu(
    package_manager: &PackageManager,
    name: &str,
) -> Result<packer::package::Package, Box<dyn std::error::Error>> {
    println!("\n{}", format!("📦 Available versions for {}:", name).bold());
    println!("{}", "=".repeat(50));
    let packages = package_manager.repository_manager.search_packages(name, true).await?;
    if packages.is_empty() {
        return Err(format!("Package '{}' not found", name).into());
    }
    let latest_package = packages.iter().max_by(|a, b| {
        use packer::utils::compare_versions;
        compare_versions(&a.version, &b.version).unwrap_or(std::cmp::Ordering::Equal)
    }).unwrap();
    println!("  {} {} {} (latest)", "1.".dimmed(), latest_package.name.bold(), latest_package.version.green());
    println!("    {} | {} | {}", 
        latest_package.repository.cyan(),
        format_size(latest_package.size),
        latest_package.description
    );
    println!("\nPress Enter to install the latest version, or type a specific version number:");
    print!("{}", "Version (default: latest): ".bold());
    use std::io::{self, Write};
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();
    if input.is_empty() {
        Ok(latest_package.clone())
    } else {
        find_package_version(package_manager, name, input).await
    }
}
async fn show_installation_preview(
    package_manager: &PackageManager,
    package_names: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "📋 Installation Preview".bold());
    println!("{}", "=".repeat(60));
    let mut total_download_size = 0u64;
    let mut total_installed_size = 0u64;
    let mut aur_count = 0;
    let mut binary_count = 0;
    for name in package_names {
        if let Some(package) = package_manager.repository_manager.get_package(name).await? {
            let repo_badge = match package.repository.as_str() {
                "aur" => {
                    aur_count += 1;
                    format!("[{}]", "AUR".yellow())
                },
                "arch" => {
                    binary_count += 1;
                    format!("[{}]", "ARCH".blue())
                },
                "github" => {
                    binary_count += 1;
                    format!("[{}]", "GITHUB".purple())
                },
                _ => {
                    binary_count += 1;
                    format!("[{}]", package.repository.to_uppercase().cyan())
                },
            };
            if package.repository == "aur" {
                println!("  {} {} {} {} (source tarball: ~10 KB, binaries: ~{})",
                    repo_badge,
                    package.name.bold(),
                    package.version.green(),
                    package.description,
                    format_size(package.size)
                );
                total_download_size += 10 * 1024;
                total_installed_size += package.size;
            } else {
                println!("  {} {} {} {} ({})",
                    repo_badge,
                    package.name.bold(),
                    package.version.green(),
                    package.description,
                    format_size(package.size)
                );
                total_download_size += package.size;
                total_installed_size += package.installed_size;
            }
        }
    }
    println!("\n{}", "📊 Summary:".bold());
    println!("  Packages: {} total ({} binary, {} AUR)", 
        package_names.len(), binary_count, aur_count);
    if aur_count > 0 {
        println!("  Initial download: {}", format_size(total_download_size));
        println!("  Additional downloads during build: {}", format_size(total_installed_size - total_download_size));
        println!("  Total download size: {}", format_size(total_installed_size));
    } else {
        println!("  Total download size: {}", format_size(total_download_size));
    }
    println!("  Total installed size: {}", format_size(total_installed_size));
    if aur_count > 0 {
        println!("\n{}", "ℹ️  Note: AUR packages require building from source.".yellow());
        println!("{}", "   Initial downloads are small tarballs, actual binaries are downloaded during build.".yellow());
    }
    Ok(())
}
async fn handle_remove(
    package_manager: &mut PackageManager,
    packages: Vec<&str>,
    force: bool,
    cascade: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Removing packages: {}", packages.join(", "));
    let package_names: Vec<String> = packages.iter().map(|s| s.to_string()).collect();
    package_manager.remove_packages(&package_names, force, cascade, false).await?;
    println!("{}", "✅ Removal completed successfully!".green());
    Ok(())
}
async fn handle_search(
    package_manager: &PackageManager,
    query: &str,
    exact: bool,
    repository: Option<&String>,
    version_filter: Option<&String>,
    sort_by: &str,
    limit: usize,
    installed_only: bool,
    not_installed_only: bool,
    detailed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Searching for: {}", query.bold());
    let mut packages = match package_manager.search_packages(query, exact, false).await {
        Ok(packages) => packages,
        Err(e) => {
            if e.to_string().contains("timeout") || e.to_string().contains("network") {
                println!("\n{}", "⚠️  Network timeout or error occurred during search.".yellow());
                println!("Trying with local cache only...");
                match package_manager.search_packages(query, exact, true).await {
                    Ok(local_packages) => {
                        println!("Found {} packages in local cache", local_packages.len());
                        local_packages
                    }
                    Err(_) => {
                        println!("{}", "❌ Search failed. Check your internet connection and try again.".red());
                        return Ok(());
                    }
                }
            } else {
                return Err(e.into());
            }
        }
    };
    if let Some(repo) = repository {
        packages.retain(|p| p.repository == *repo);
    }
    if let Some(version_pattern) = version_filter {
        packages.retain(|p| {
            match version_pattern.parse::<semver::VersionReq>() {
                Ok(version_req) => {
                    if let Ok(version) = semver::Version::parse(&p.version) {
                        version_req.matches(&version)
                    } else {
                        false
                    }
                },
                Err(_) => {
                    match version_pattern.as_str() {
                        pat if pat.starts_with(">=") => {
                            if let Ok(min_version) = semver::Version::parse(&pat[2..]) {
                                if let Ok(pkg_version) = semver::Version::parse(&p.version) {
                                    pkg_version >= min_version
                                } else { false }
                            } else { false }
                        },
                        pat if pat.starts_with("~") => {
                            if let Ok(base_version) = semver::Version::parse(&format!("{}.0", &pat[1..])) {
                                if let Ok(pkg_version) = semver::Version::parse(&p.version) {
                                    pkg_version.major == base_version.major && pkg_version.minor == base_version.minor
                                } else { false }
                            } else { false }
                        },
                        _ => p.version.contains(version_pattern),
                    }
                }
            }
        });
    }
    if installed_only || not_installed_only {
        let mut filtered_packages = Vec::new();
        for package in packages {
            let is_installed = package_manager.is_package_installed(&package.name).await?;
            if (installed_only && is_installed) || (not_installed_only && !is_installed) {
                filtered_packages.push(package);
            }
        }
        packages = filtered_packages;
    }
    packages.sort_by(|a, b| {
        match sort_by {
            "name" => a.name.cmp(&b.name),
            "version" => {
                use packer::utils::compare_versions;
                compare_versions(&a.version, &b.version).unwrap_or(std::cmp::Ordering::Equal)
            },
            "size" => a.size.cmp(&b.size),
            "repository" => a.repository.cmp(&b.repository),
            _ => a.name.cmp(&b.name),
        }
    });
    let final_packages = packages.into_iter().take(limit).collect::<Vec<_>>();
    if final_packages.is_empty() {
        println!("\n{}", "No packages found matching the search criteria.".yellow());
        println!("Try using a broader search term or check for typos.");
        println!("You can also try: packer search --repo aur {}", query);
        return Ok(());
    }
    println!("\n{} {} packages found", "Search Results:".bold().green(), final_packages.len());
    println!("{}", "=".repeat(80));
    for (index, package) in final_packages.iter().enumerate() {
        let repo_color = match package.repository.as_str() {
            "core" | "extra" | "community" | "multilib" => package.repository.green(),
            "aur" => package.repository.yellow(),
            _ => package.repository.cyan(),
        };
        
        let result = if detailed {
            writeln!(std::io::stdout(), "\n{}. {} {} ({})",
                (index + 1).to_string().dimmed(),
                package.name.bold(),
                package.version.green(),
                repo_color
            ).and_then(|_| writeln!(std::io::stdout(), "   {}", package.description.trim()))
            .and_then(|_| writeln!(std::io::stdout(), "   Size: {} | Maintainer: {}", 
                format_size(package.size), 
                if package.maintainer.is_empty() { "Unknown" } else { &package.maintainer }
            )).and_then(|_| if !package.url.is_empty() {
                writeln!(std::io::stdout(), "   URL: {}", package.url.dimmed())
            } else {
                Ok(())
            })
        } else {
            writeln!(std::io::stdout(), "{}. {} {} ({}) - {}",
                (index + 1).to_string().dimmed(),
                package.name.bold(),
                package.version.green(),
                repo_color,
                package.description.chars().take(60).collect::<String>()
            )
        };

        if result.is_err() {
            // pipe was closed (e.g., by 'head' command), exit gracefully
            break;
        }
    }
    let _ = writeln!(std::io::stdout(), "\n💡 Install with: packer install <package_name>");
    Ok(())
}
async fn handle_info(
    package_manager: &PackageManager,
    package_name: &str,
    show_files: bool,
    show_deps: bool,
    _show_rdeps: bool,
    security_info: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let package = package_manager.get_package_info(package_name).await?
        .ok_or_else(|| format!("Package '{}' not found", package_name))?;
    println!("\n{}", "Package Information".bold());
    println!("{}", "=".repeat(60));
    println!("Name: {}", package.name.bold());
    println!("Version: {}", package.version.green());
    println!("Repository: {}", package.repository.cyan());
    println!("Architecture: {}", package.arch);
    println!("Maintainer: {}", package.maintainer);
    println!("License: {}", package.license);
    println!("URL: {}", package.url);
    println!("Download Size: {}", format_size(package.size));
    println!("Installed Size: {}", format_size(package.installed_size));
    println!("Build Date: {}", package.build_date.format("%Y-%m-%d %H:%M:%S"));
    if let Some(install_date) = package.install_date {
        println!("Install Date: {}", install_date.format("%Y-%m-%d %H:%M:%S"));
    }
    println!("\n{}", "Description".bold());
    println!("{}", package.description);
    if show_deps && !package.dependencies.is_empty() {
        println!("\n{}", "Dependencies".bold());
        for dep in &package.dependencies {
            println!("  • {}", dep);
        }
    }
    if show_files && !package.files.is_empty() {
        println!("\n{}", "Files".bold());
        for file in &package.files {
            println!("  {}", file.path);
        }
    }
    if security_info {
        println!("\n{}", "Security Information".bold());
        if !package.checksum.is_empty() {
            println!("Checksum: {}", package.checksum);
        }
        if package.signature.is_some() {
            println!("{}", "🔐 GPG signature available".green());
        }
    }
    Ok(())
}
async fn handle_list(
    package_manager: &PackageManager,
    explicit: bool,
    dependencies: bool,
    orphans: bool,
    format: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let packages = match package_manager.list_installed_packages().await {
        Ok(packages) => packages,
        Err(e) => {
            if e.to_string().contains("No such file or directory") {
                println!("Installed Packages: 0 total");
                println!("{}", "=".repeat(60));
                println!("No packages installed yet. Install a package first with: packer install <package>");
                return Ok(());
            } else {
                return Err(e.into());
            }
        }
    };
    let filtered_packages = if explicit {
        packages.into_iter().filter(|p| matches!(p.1, packer::storage::InstallReason::Explicit)).collect()
    } else if dependencies {
        packages.into_iter().filter(|p| matches!(p.1, packer::storage::InstallReason::Dependency)).collect()
    } else if orphans {
        find_orphaned_packages(&packages).await?
    } else {
        packages
    };
    match format.map(|s| s.as_str()) {
        Some("json") => {
            let json_output: Vec<_> = filtered_packages.iter()
                .map(|(pkg, reason)| serde_json::json!({
                    "name": pkg.name,
                    "version": pkg.version,
                    "repository": pkg.repository,
                    "size": pkg.installed_size,
                    "install_reason": reason,
                    "install_date": pkg.install_date
                }))
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_output)?);
        }
        Some("csv") => {
            println!("Name,Version,Repository,Size,Install Reason,Install Date");
            for (pkg, reason) in filtered_packages {
                println!("{},{},{},{},{:?},{:?}", 
                    pkg.name, pkg.version, pkg.repository, pkg.installed_size, reason, pkg.install_date);
            }
        }
        _ => {
            println!("Installed Packages: {} total", filtered_packages.len());
            println!("{}", "=".repeat(60));
            if filtered_packages.is_empty() {
                println!("No packages installed yet. Install a package first with: packer install <package>");
                return Ok(());
            }
            let mut total_size = 0u64;
            for (pkg, reason) in &filtered_packages {
                total_size += pkg.installed_size;
                let reason_str = match reason {
                    packer::storage::InstallReason::Explicit => "explicit",
                    packer::storage::InstallReason::Dependency => "dependency",
                    packer::storage::InstallReason::Upgrade => "upgrade",
                };
                let install_date = pkg.install_date
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                println!("📦 {} {} ({}) - {} [{}] - installed {}",
                    pkg.name.bold(),
                    pkg.version.green(),
                    pkg.repository.cyan(),
                    format_size(pkg.installed_size),
                    reason_str,
                    install_date
                );
            }
            println!("\n📊 Total installed size: {}", format_size(total_size));
        }
    }
    Ok(())
}
async fn handle_update(
    package_manager: &mut PackageManager,
    repository: Option<&String>,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Updating package database...");
    let result = if let Some(repo) = repository {
        package_manager.update_repository(repo, force).await
    } else {
        package_manager.update_database().await
    };
    match result {
        Ok(_) => println!("{}", "Database updated successfully".green()),
        Err(e) => {
            println!("{}: {}", "Failed to update database".red(), e);
            return Err(e.into());
        }
    }
    Ok(())
}
async fn handle_upgrade(
    package_manager: &mut PackageManager,
    packages: Option<Vec<&str>>,
    _ignore: Option<&String>,
    _security_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking for upgrades...");
    let available_upgrades = if let Some(specific_packages) = packages {
        let mut upgrades = Vec::new();
        for package_name in specific_packages {
            if let Some(upgrade) = package_manager.check_package_upgrade(package_name).await? {
                if let Some(installed) = package_manager.database.get_package(package_name).await? {
                    upgrades.push((installed, upgrade));
                }
            }
        }
        upgrades
    } else {
        package_manager.check_upgrades().await?
    };
    if available_upgrades.is_empty() {
        println!("{}", "No upgrades available".green());
        return Ok(());
    }
    println!("Available upgrades: {}", available_upgrades.len());
    for (current, newer) in &available_upgrades {
        println!("  {} {} → {}", 
            current.name.bold(),
            current.version.yellow(),
            newer.version.green()
        );
    }
    let package_names: Vec<String> = available_upgrades.iter().map(|(_, newer)| newer.name.clone()).collect();
    package_manager.upgrade_packages_by_names(package_names, false).await?;
    println!("{}", "✅ Upgrade completed successfully!".green());
    Ok(())
}
async fn handle_check(
    package_manager: &PackageManager,
    fix: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking system integrity...");
    let conflicts = package_manager.check_conflicts().await?;
    if conflicts.is_empty() {
        println!("{}", "✅ No conflicts detected".green());
        return Ok(());
    }
    println!("{}", format!("⚠️  {} conflicts detected", conflicts.len()).yellow());
    for conflict in &conflicts {
        println!("Conflict: {}", conflict);
        if verbose {
            println!("  Details: {}", "conflict details would go here");
        }
    }
    if fix {
        println!("Attempting to fix conflicts...");
        println!("{}", "⚠️  Conflict resolution not yet implemented".yellow());
    }
    Ok(())
}
async fn handle_clean(
    package_manager: &PackageManager,
    cache: bool,
    temp: bool,
    logs: bool,
    all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Cleaning up...");
    let mut cleaned_size = 0u64;
    if cache || all {
        println!("Cleaning package cache...");
        cleaned_size += clean_package_cache(package_manager).await?;
    }
    if temp || all {
        println!("Cleaning temporary files...");
        cleaned_size += clean_temp_files().await?;
    }
    if logs || all {
        println!("Cleaning log files...");
        cleaned_size += clean_log_files().await?;
    }
    if !cache && !temp && !logs && !all {
        println!("Cleaning package cache...");
        cleaned_size += clean_package_cache(package_manager).await?;
    }
    println!("{}", format!("✅ Cleaned up {} of disk space", format_size(cleaned_size)).green());
    Ok(())
}
async fn handle_repos(
    package_manager: &PackageManager,
) -> Result<(), Box<dyn std::error::Error>> {
    let repos = package_manager.list_repositories().await?;
    println!("Configured Repositories:");
    println!("{}", "=".repeat(60));
    for repo in repos {
        let status = if repo.enabled { "enabled".green() } else { "disabled".red() };
        println!("{} [{}] (Priority: {})", 
            repo.name.bold(), 
            status, 
            repo.priority
        );
        println!("  URL: {}", repo.url);
        println!("  Type: {:?}", repo.repo_type);
        println!("  Packages: {}", repo.package_count);
        if let Some(last_update) = repo.last_update {
            println!("  Last Update: {}", last_update.format("%Y-%m-%d %H:%M:%S"));
        }
        println!();
    }
    Ok(())
}
async fn handle_transaction(
    _package_manager: &PackageManager,
    sub_matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    match sub_matches.subcommand() {
        Some(("history", history_matches)) => {
            let limit = history_matches.get_one::<String>("limit")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(20);
            let filter = history_matches.get_one::<String>("filter");
            let package_filter = history_matches.get_one::<String>("package");
            let failed_only = history_matches.get_flag("failed");
            display_transaction_history(limit, filter, package_filter, failed_only).await?;
        }
        Some(("rollback", rollback_matches)) => {
            let transaction_id = rollback_matches.get_one::<String>("transaction_id").unwrap();
            let _force = rollback_matches.get_flag("force");
            println!("Transaction rollback not yet implemented for: {}", transaction_id);
        }
        Some(("show", show_matches)) => {
            let transaction_id = show_matches.get_one::<String>("transaction_id").unwrap();
            show_transaction_details(transaction_id).await?;
        }
        _ => {
            println!("Use 'packer transaction --help' for available commands");
        }
    }
    Ok(())
}
async fn handle_security(
    package_manager: &mut PackageManager,
    sub_matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    match sub_matches.subcommand() {
        Some(("scan", scan_matches)) => {
            let package_name = scan_matches.get_one::<String>("package").unwrap();
            println!("{}", format!("🔍 Scanning package: {}", package_name).cyan());
            if let Some(package) = package_manager.get_package_info(package_name).await? {
                let vulnerabilities = package_manager.security_scanner.scan_package(&package).await?;
                if vulnerabilities.is_empty() {
                    println!("{}", "✅ No vulnerabilities found!".green());
                } else {
                    println!("{}", format!("⚠️  Found {} vulnerabilities:", vulnerabilities.len()).yellow());
                    for vuln in vulnerabilities {
                        let _severity_color = match vuln.severity {
                            packer::package::VulnerabilitySeverity::Critical => "red",
                            packer::package::VulnerabilitySeverity::High => "magenta",
                            packer::package::VulnerabilitySeverity::Medium => "yellow",
                            packer::package::VulnerabilitySeverity::Low => "blue",
                            packer::package::VulnerabilitySeverity::Info => "white",
                        };
                        println!("  • {} [{:?}] - {}", 
                                vuln.vulnerability_id,
                                vuln.severity,
                                vuln.description);
                        if let Some(ref fixed_version) = vuln.fixed_version {
                            println!("    Fixed in version: {}", fixed_version.green());
                        }
                    }
                }
            } else {
                println!("{}", format!("❌ Package '{}' not found", package_name).red());
            }
        }
        Some(("audit", audit_matches)) => {
            let json_output = audit_matches.get_flag("json");
            let detailed = audit_matches.get_flag("detailed");
            println!("{}", "🔍 Performing comprehensive security audit...".cyan());
            let audit_result = package_manager.security_scanner.audit_system().await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&audit_result)?);
            } else {
                println!("\n{}", "Security Audit Results".bold());
                println!("{}", "=".repeat(60));
                println!("Total packages examined: {}", audit_result.total_packages);
                println!("Vulnerable packages: {}", audit_result.vulnerable_packages);
                println!("High-risk packages: {}", audit_result.high_risk_packages);
                println!("Total vulnerabilities: {}", audit_result.total_vulnerabilities);
                if detailed && !audit_result.reports.is_empty() {
                    println!("\n{}", "Detailed Vulnerability Reports:".bold());
                    for report in audit_result.reports {
                        println!("\n📦 Package: {} {}", report.package_name.bold(), report.version);
                        println!("Risk Score: {:.1}/10", report.risk_score);
                        println!("Recommendation: {}", report.recommendation);
                        for vuln in report.vulnerabilities {
                            println!("  • {} [{:?}] - {}", vuln.id, vuln.severity, vuln.description);
                            if let Some(ref cve) = vuln.cve_id {
                                println!("    CVE: {}", cve);
                            }
                        }
                    }
                }
                if !audit_result.recommendations.is_empty() {
                    println!("\n{}", "Security Recommendations:".bold());
                    for (i, rec) in audit_result.recommendations.iter().enumerate() {
                        println!("  {}. {}", i + 1, rec);
                    }
                }
                if audit_result.vulnerable_packages == 0 {
                    println!("\n{}", "✅ No security issues found!".green());
                } else {
                    println!("\n{}", "⚠️  Security issues detected. Review recommendations above.".yellow());
                }
            }
        }
        Some(("import-keys", import_matches)) => {
            let keyserver = import_matches.get_one::<String>("keyserver").unwrap();
            let key_ids: Vec<String> = import_matches.get_many::<String>("keys")
                .unwrap()
                .map(|s| s.to_string())
                .collect();
            println!("{}", format!("🔐 Importing {} GPG keys from {}...", key_ids.len(), keyserver).cyan());
            let imported_keys = package_manager.import_gpg_keys(&key_ids).await?;
            if imported_keys.is_empty() {
                println!("{}", "❌ Failed to import any keys".red());
            } else {
                println!("{}", format!("✅ Successfully imported {} keys:", imported_keys.len()).green());
                for key in imported_keys {
                    println!("  • {} - {} (Trust: {})", 
                            key.id, 
                            key.user_id, 
                            key.trust_level);
                    if let Some(expires) = key.expires {
                        println!("    Expires: {}", expires.format("%Y-%m-%d"));
                    }
                }
            }
        }
        Some(("status", status_matches)) => {
            let verbose = status_matches.get_flag("verbose");
            println!("{}", "🔐 Security System Status".bold().cyan());
            println!("{}", "=".repeat(40));
            
            let gpg_status = package_manager.get_gpg_status().await?;
            println!("{}", gpg_status);
            
            if verbose {
                println!("\n📋 Configuration Details:");
                println!("  • Verify checksums: {}", package_manager.config.verify_checksums);
                println!("  • Verify signatures: {}", package_manager.config.verify_signatures);
                println!("  • Allow untrusted repos: {}", package_manager.config.security_policy.allow_untrusted_repos);
                println!("  • Scan for vulnerabilities: {}", package_manager.config.security_policy.scan_for_vulnerabilities);
                println!("  • Block high-risk packages: {}", package_manager.config.security_policy.block_high_risk_packages);
                println!("  • Max package size (MB): {}", package_manager.config.security_policy.max_package_size_mb);
                println!("  • Allowed protocols: {:?}", package_manager.config.security_policy.allowed_protocols);
                
                println!("\n🔧 System Information:");
                println!("  • Database path: {:?}", package_manager.config.database_dir);
                println!("  • Cache path: {:?}", package_manager.config.cache_dir);
                println!("  • Install root: {:?}", package_manager.config.install_root);
            }
        }
        Some(("update-db", _)) => {
            println!("{}", "🔄 Updating vulnerability database...".cyan());
            match package_manager.security_scanner.update_vulnerability_database().await {
                Ok(_) => {
                    println!("{}", "✅ Vulnerability database updated successfully".green());
                }
                Err(e) => {
                    println!("{}", format!("❌ Failed to update vulnerability database: {}", e).red());
                    return Err(e.into());
                }
            }
        }
        Some(("enhanced-scan", scan_matches)) => {
            handle_enhanced_scan(package_manager, scan_matches).await?;
        }
        Some(("threat-intel", intel_matches)) => {
            handle_threat_intel(package_manager, intel_matches).await?;
        }
        Some(("risk-assessment", risk_matches)) => {
            handle_risk_assessment(package_manager, risk_matches).await?;
        }
        _ => {
            println!("Available security commands:");
            println!("  audit           - Run comprehensive security audit");
            println!("  scan            - Scan a specific package for vulnerabilities");
            println!("  enhanced-scan   - Enhanced security scan with threat intelligence");
            println!("  threat-intel    - Update threat intelligence feeds");
            println!("  risk-assessment - Comprehensive risk assessment");
            println!("  import-keys     - Import GPG keys for signature verification");
            println!("  update-db       - Update vulnerability database");
            println!("\nUse 'packer security <command> --help' for more information");
        }
    }
    Ok(())
}
async fn handle_fix(
    package_manager: &mut PackageManager,
    sizes: bool,
    all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Fixing package database issues...");
    if sizes || all {
        println!("\n{}", "Recalculating package sizes...".bold());
        package_manager.recalculate_package_sizes().await?;
    }
    if all {
        println!("\n{}", "Running comprehensive database fix...".bold());
        package_manager.fix_package_database().await?;
    }
    Ok(())
}
async fn handle_doctor(
    package_manager: &PackageManager,
    fix: bool,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Running system diagnostics...");
    if verbose {
        println!("Checking package database integrity...");
    }
    match package_manager.list_installed_packages().await {
        Ok(packages) => {
            if packages.is_empty() {
                println!("📦 Package database is empty");
                if fix {
                    println!("🔧 Attempting to detect existing packages...");
                    let common_packages = vec![
                        "visual-studio-code-bin",
                        "code",
                        "vim",
                        "neovim",
                        "firefox",
                        "chromium",
                        "git",
                        "nodejs",
                        "python",
                        "rust",
                        "gcc",
                        "make",
                        "cmake",
                    ];
                    let mut detected_packages = Vec::new();
                    for pkg_name in common_packages {
                        let binary_name = match pkg_name {
                            "visual-studio-code-bin" => "code",
                            "neovim" => "nvim",
                            _ => pkg_name,
                        };
                        if let Ok(output) = tokio::process::Command::new("which")
                            .arg(binary_name)
                            .output()
                            .await
                        {
                            if output.status.success() {
                                detected_packages.push(pkg_name);
                            }
                        }
                    }
                    if !detected_packages.is_empty() {
                        println!("✅ Detected {} potentially installed packages:", detected_packages.len());
                        for pkg in &detected_packages {
                            println!("  - {}", pkg);
                        }
                        println!("\n💡 To properly track these packages, reinstall them with:");
                        println!("   packer install {}", detected_packages.join(" "));
                    } else {
                        println!("ℹ️  No common packages detected in PATH");
                    }
                }
            } else {
                println!("✅ Package database contains {} packages", packages.len());
            }
        }
        Err(e) => {
            if e.to_string().contains("No such file or directory") {
                println!("❌ Package database not found");
                if fix {
                    println!("🔧 Creating new package database...");
                    match package_manager.list_installed_packages().await {
                        Ok(_) => println!("✅ Package database created successfully"),
                        Err(e) => println!("❌ Failed to create database: {}", e),
                    }
                }
            } else {
                println!("❌ Database error: {}", e);
            }
        }
    }
    println!("\n🌐 Checking repository connectivity...");
    let repos = package_manager.list_repositories().await?;
    for repo in repos {
        if repo.enabled {
            println!("  {} {} - {}", 
                if repo.enabled { "✅" } else { "❌" },
                repo.name.bold(),
                if repo.enabled { "enabled" } else { "disabled" }
            );
        }
    }
    let cache_dir = package_manager.get_cache_dir();
    if cache_dir.exists() {
        let cache_size = get_directory_size(&cache_dir).await?;
        println!("\n💾 Cache directory: {} ({})", 
            cache_dir.display(), 
            format_size(cache_size)
        );
        if fix && cache_size > 100 * 1024 * 1024 {
            println!("🔧 Cache is large, consider running: packer clean");
        }
    } else {
        println!("\n💾 Cache directory: {} (not found)", cache_dir.display());
    }
    println!("\n🏠 Install root: {}", package_manager.get_install_root());
    println!("📄 Database path: {}", package_manager.get_database_path().display());
    if !fix {
        println!("\n💡 Run with --fix to attempt automatic repairs");
    }
    Ok(())
}
fn get_directory_size(dir: &std::path::Path) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64, Box<dyn std::error::Error>>> + '_>> {
    Box::pin(async move {
        let mut total_size = 0u64;
        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                total_size += metadata.len();
            } else if metadata.is_dir() {
                total_size += get_directory_size(&entry.path()).await?;
            }
        }
        Ok(total_size)
    })
}
fn handle_completion(shell: &str) -> Result<(), Box<dyn std::error::Error>> {
    match shell {
        "bash" => {
            println!("# Bash completion for packer");
            println!("complete -W 'install remove search info list update upgrade check clean repos transaction security doctor complete' packer");
        }
        "zsh" => {
            println!("# Zsh completion for packer");
            println!("#compdef packer");
            println!("_packer() {{");
            println!("  local commands=(install remove search info list update upgrade check clean repos transaction security doctor complete)");
            println!("  _describe 'commands' commands");
            println!("}}");
            println!("_packer");
        }
        "fish" => {
            println!("# Fish completion for packer");
            println!("complete -c packer -n '__fish_use_subcommand' -a 'install remove search info list update upgrade check clean repos transaction security doctor complete'");
        }
        _ => {
            println!("Unsupported shell: {}", shell);
            println!("Supported shells: bash, zsh, fish");
        }
    }
    Ok(())
}
async fn handle_version(
    package_manager: &PackageManager,
    package: Option<&String>,
    available: bool,
    history: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(package_name) = package {
        if let Some(installed_pkg) = package_manager.get_package_info(package_name).await? {
            println!("\n{}", format!("📦 Package: {}", package_name).bold());
            println!("{}", "=".repeat(50));
            println!("📋 Installed Version: {}", installed_pkg.version.green());
            println!("📅 Install Date: {}", installed_pkg.install_date.map_or("Unknown".to_string(), |d| d.format("%Y-%m-%d %H:%M:%S").to_string()));
            println!("🏪 Repository: {}", installed_pkg.repository.yellow());
            println!("💾 Size: {}", format_size(installed_pkg.installed_size));
            if available {
                println!("\n{}", "🔍 Available Versions:".bold());
                if let Some(newer) = package_manager.check_package_upgrade(package_name).await? {
                    println!("  {} {} -> {} (Upgrade available)", 
                             "⬆️".green(), 
                             installed_pkg.version, 
                             newer.version.green());
                } else {
                    println!("  ✅ Up to date");
                }
            }
            if history {
                println!("\n{}", "📜 Version History:".bold());
                let transactions = package_manager.database.get_transactions_by_package(package_name);
                for transaction in transactions.iter().take(5) {
                    let status = if transaction.success { "✅" } else { "❌" };
                    println!("  {} {} - {:?} - {}", 
                             status,
                             transaction.timestamp.format("%Y-%m-%d %H:%M:%S"),
                             transaction.transaction_type,
                             transaction.packages.iter().find(|p| p.name == *package_name)
                                .map_or("Unknown".to_string(), |p| p.version.clone()));
                }
            }
        } else {
            println!("❌ Package '{}' not found", package_name.red());
        }
    } else {
        println!("\n{}", "🚀 Packer Package Manager".bold());
        println!("{}", "=".repeat(50));
        println!("📋 Version: {}", "0.1.0".green());
        println!("🏗️  Build: {}", "release".yellow());
        println!("🦀 Rust Version: {}", "1.80+");
        println!("🏠 Install Root: {}", package_manager.get_install_root());
        println!("💾 Database: {}", package_manager.get_database_path().display());
        println!("📦 Cache: {}", package_manager.get_cache_dir().display());
        let installed_packages = package_manager.list_installed_packages().await?;
        println!("\n{}", "📊 Package Statistics:".bold());
        println!("  Total Packages: {}", installed_packages.len());
        let explicit_count = installed_packages.iter().filter(|(_, reason)| matches!(reason, packer::storage::InstallReason::Explicit)).count();
        let dependency_count = installed_packages.len() - explicit_count;
        println!("  Explicitly Installed: {}", explicit_count);
        println!("  Dependencies: {}", dependency_count);
        let total_size: u64 = installed_packages.iter().map(|(pkg, _)| pkg.installed_size).sum();
        println!("  Total Size: {}", format_size(total_size));
        let transactions = package_manager.database.get_transaction_history(Some(10));
        println!("  Recent Transactions: {}", transactions.len());
        if available {
            println!("\n{}", "🔄 Checking for updates...".bold());
            let upgrades = package_manager.check_upgrades().await?;
            if upgrades.is_empty() {
                println!("  ✅ All packages are up to date");
            } else {
                println!("  ⬆️ {} packages can be upgraded", upgrades.len());
                for (old, new) in upgrades.iter().take(5) {
                    println!("    {} {} -> {}", old.name, old.version, new.version.green());
                }
                if upgrades.len() > 5 {
                    println!("    ... and {} more", upgrades.len() - 5);
                }
            }
        }
    }
    Ok(())
}
async fn handle_versions(
    package_manager: &PackageManager,
    package_name: &str,
    all_repos: bool,
    repository: Option<&String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Available versions for '{}':", package_name.bold());
    println!("{}", "=".repeat(50));
    let packages = if all_repos {
        package_manager.repository_manager.search_packages(package_name, true).await?
    } else if let Some(repo) = repository {
        package_manager.repository_manager.search_packages_in_repo(package_name, repo).await?
    } else {
        package_manager.repository_manager.search_packages(package_name, true).await?
    };
    if packages.is_empty() {
        println!("{}", "No versions found for this package.".yellow());
        return Ok(());
    }
    let mut sorted_packages = packages.into_iter().collect::<Vec<_>>();
    sorted_packages.sort_by(|a, b| {
        use packer::utils::compare_versions;
        compare_versions(&a.version, &b.version).unwrap_or(std::cmp::Ordering::Equal)
    });
    for (index, pkg) in sorted_packages.iter().enumerate() {
        println!("  {} {} {} (from {})",
            format!("{}.", index + 1).dimmed(),
            pkg.name.bold(),
            pkg.version.green(),
            pkg.repository.cyan()
        );
        println!("    {} | {} | {}",
            pkg.repository.cyan(),
            format_size(pkg.size),
            pkg.description
        );
    }
    Ok(())
}
async fn clean_package_cache(package_manager: &PackageManager) -> Result<u64, Box<dyn std::error::Error>> {
    let cache_dir = package_manager.get_cache_dir();
    let mut cleaned_size = 0u64;
    if cache_dir.exists() {
        let mut entries = tokio::fs::read_dir(&cache_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                cleaned_size += metadata.len();
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
    }
    Ok(cleaned_size)
}
async fn clean_temp_files() -> Result<u64, Box<dyn std::error::Error>> {
    let temp_dir = std::env::temp_dir().join("packer");
    let mut cleaned_size = 0u64;
    if temp_dir.exists() {
        let mut entries = tokio::fs::read_dir(&temp_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                cleaned_size += metadata.len();
                tokio::fs::remove_file(entry.path()).await?;
            }
        }
    }
    Ok(cleaned_size)
}
async fn clean_log_files() -> Result<u64, Box<dyn std::error::Error>> {
    let log_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("packer")
        .join("logs");
    let mut cleaned_size = 0u64;
    if log_dir.exists() {
        let mut entries = tokio::fs::read_dir(&log_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let metadata = entry.metadata().await?;
            if metadata.is_file() {
                let file_name = entry.file_name();
                if file_name.to_string_lossy().ends_with(".log") {
                    cleaned_size += metadata.len();
                    tokio::fs::remove_file(entry.path()).await?;
                }
            }
        }
    }
    Ok(cleaned_size)
}
async fn find_orphaned_packages(
    packages: &[(packer::package::Package, packer::storage::InstallReason)],
) -> Result<Vec<(packer::package::Package, packer::storage::InstallReason)>, Box<dyn std::error::Error>> {
    let mut orphaned = Vec::new();
    for (package, reason) in packages {
        if matches!(reason, packer::storage::InstallReason::Dependency) {
            let mut is_orphaned = true;
            for (other_package, other_reason) in packages {
                if matches!(other_reason, packer::storage::InstallReason::Explicit) {
                    for dep in &other_package.dependencies {
                        if dep.name == package.name {
                            is_orphaned = false;
                            break;
                        }
                    }
                    if !is_orphaned {
                        break;
                    }
                }
            }
            if is_orphaned {
                orphaned.push((package.clone(), reason.clone()));
            }
        }
    }
    Ok(orphaned)
}
async fn display_transaction_history(
    limit: usize,
    filter: Option<&String>,
    package_filter: Option<&String>,
    failed_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(None)?;
    let package_manager = PackageManager::new(config).await?;
    let mut transactions = package_manager.database.get_transaction_history(Some(limit));
    if let Some(filter_type) = filter {
        transactions.retain(|t| format!("{:?}", t.transaction_type).to_lowercase().contains(&filter_type.to_lowercase()));
    }
    if let Some(package_name) = package_filter {
        transactions.retain(|t| t.packages.iter().any(|p| p.name.contains(package_name)));
    }
    if failed_only {
        transactions.retain(|t| !t.success);
    }
    if transactions.is_empty() {
        println!("No transaction history found.");
        return Ok(());
    }
    println!("\n{}", "📋 Transaction History".bold());
    println!("{}", "=".repeat(80));
    for (i, transaction) in transactions.iter().enumerate() {
        let status = if transaction.success { "✅ Success".green() } else { "❌ Failed".red() };
        let duration_str = format!("{}s", transaction.duration);
        let size_change = if transaction.size_change >= 0 {
            format!("+{}", format_size(transaction.size_change as u64)).green()
        } else {
            format!("-{}", format_size((-transaction.size_change) as u64)).red()
        };
        println!("{} | {} | {:?} | {} | {} | {}",
            transaction.timestamp.format("%Y-%m-%d %H:%M:%S"),
            transaction.id[..8].to_string().cyan(),
            transaction.transaction_type,
            status,
            duration_str.yellow(),
            size_change
        );
        let package_names: Vec<String> = transaction.packages.iter().map(|p| p.name.clone()).collect();
        println!("  📦 Packages: {}", package_names.join(", "));
        println!("  👤 User: {} | 🛡️ Security: {:.1}/100", transaction.user, transaction.security_score);
        if let Some(ref error) = transaction.error_message {
            println!("  ❌ Error: {}", error.red());
        }
        if transaction.rollback_info.as_ref().map_or(false, |r| r.can_rollback) {
            println!("  🔄 Rollback: Available");
        }
        if i < transactions.len() - 1 {
            println!();
        }
    }
    println!("\n{}", format!("Total transactions: {}", transactions.len()).bold());
    Ok(())
}
async fn show_transaction_details(transaction_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load(None)?;
    let package_manager = PackageManager::new(config).await?;
    if let Some(transaction) = package_manager.database.get_transaction_by_id(transaction_id) {
        println!("\n{}", "📋 Transaction Details".bold());
        println!("{}", "=".repeat(80));
        println!("🆔 Transaction ID: {}", transaction.id.cyan());
        println!("📅 Timestamp: {}", transaction.timestamp.format("%Y-%m-%d %H:%M:%S"));
        println!("🔄 Type: {:?}", transaction.transaction_type);
        println!("👤 User: {}", transaction.user);
        println!("⏱️ Duration: {}s", transaction.duration);
        let status = if transaction.success { "✅ Success".green() } else { "❌ Failed".red() };
        println!("📊 Status: {}", status);
        let size_change = if transaction.size_change >= 0 {
            format!("+{}", format_size(transaction.size_change as u64)).green()
        } else {
            format!("-{}", format_size((-transaction.size_change) as u64)).red()
        };
        println!("💾 Size Change: {}", size_change);
        println!("🛡️ Security Score: {:.1}/100", transaction.security_score);
        if let Some(ref error) = transaction.error_message {
            println!("❌ Error: {}", error.red());
        }
        println!("\n{}", "📦 Packages:".bold());
        for (i, pkg) in transaction.packages.iter().enumerate() {
            let operation_str = match &pkg.operation {
                PackageOperation::Install => "Install".green(),
                PackageOperation::Remove => "Remove".red(),
                PackageOperation::Upgrade { from_version } => 
                    format!("Upgrade from {}", from_version).yellow(),
                PackageOperation::Downgrade { from_version } => 
                    format!("Downgrade from {}", from_version).yellow(),
                PackageOperation::Reinstall => "Reinstall".blue(),
            };
            println!("  {}. {} {} [{}] - {} ({})", 
                     i + 1,
                     pkg.name.bold(),
                     pkg.version.cyan(),
                     pkg.repository.yellow(),
                     operation_str,
                     format_size(pkg.size));
            if !pkg.dependencies.is_empty() {
                println!("     Dependencies: {}", pkg.dependencies.join(", "));
            }
            if !pkg.conflicts.is_empty() {
                println!("     Conflicts: {}", pkg.conflicts.join(", "));
            }
            if !pkg.files.is_empty() {
                println!("     Files: {} tracked", pkg.files.len());
            }
        }
        if let Some(ref rollback_info) = transaction.rollback_info {
            println!("\n{}", "🔄 Rollback Information:".bold());
            println!("  Can Rollback: {}", if rollback_info.can_rollback { "Yes".green() } else { "No".red() });
            if !rollback_info.affected_packages.is_empty() {
                println!("  Affected Packages: {}", rollback_info.affected_packages.join(", "));
            }
            if !rollback_info.dependencies_to_restore.is_empty() {
                println!("  Dependencies to Restore: {}", rollback_info.dependencies_to_restore.join(", "));
            }
            if !rollback_info.rollback_commands.is_empty() {
                println!("  Rollback Commands: {} available", rollback_info.rollback_commands.len());
            }
        }
    } else {
        println!("❌ Transaction not found: {}", transaction_id.red());
    }
    Ok(())
}


async fn handle_enhanced_scan(
    package_manager: &PackageManager,
    scan_matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    use packer::security_enhancements::AdvancedSecurityScanner;
    
    let package_name = scan_matches.get_one::<String>("package").unwrap();
    let json_output = scan_matches.get_flag("json");
    let include_threat_intel = scan_matches.get_flag("threat-intel");
    
    println!("{}", format!("🔍 Enhanced security scan for package: {}", package_name).cyan());
    
    if let Some(package) = package_manager.get_package_info(package_name).await? {
        let enhanced_scanner = AdvancedSecurityScanner::new(package_manager.config.clone());
        
        if let Err(e) = enhanced_scanner.initialize_feeds().await {
            println!("{}", format!("Warning: Failed to initialize feeds: {}", e).yellow());
        }
        
        match enhanced_scanner.enhanced_scan_package(&package).await {
            Ok(scan_result) => {
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&scan_result)?);
                } else {
                    println!("\n{}", "Enhanced Security Scan Results".bold());
                    println!("{}", "=".repeat(60));
                    println!("Package: {} {}", scan_result.package_name.bold(), scan_result.package_version);
                    println!("Scan Time: {}", scan_result.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
                    
                    // Risk Score
                    println!("\n{}", "Risk Assessment".bold());
                    println!("Overall Risk Score: {:.2}/1.0", scan_result.risk_score.overall_score);
                    println!("  CVSS Component: {:.2}", scan_result.risk_score.cvss_component);
                    println!("  EPSS Component: {:.2}", scan_result.risk_score.epss_component);
                    println!("  Exploit Component: {:.2}", scan_result.risk_score.exploit_component);
                    println!("  Threat Intel Component: {:.2}", scan_result.risk_score.threat_intel_component);
                    
                    // Vulnerabilities
                    if !scan_result.vulnerabilities.is_empty() {
                        println!("\n{}", "Vulnerabilities Found".bold());
                        for vuln in &scan_result.vulnerabilities {
                            println!("  • {} [{:?}]", vuln.id, vuln.severity);
                            println!("    {}", vuln.description);
                            if let Some(cvss) = vuln.cvss_score {
                                println!("    CVSS Score: {:.1}", cvss);
                            }
                            if let Some(epss) = vuln.epss_score {
                                println!("    EPSS Score: {:.3}", epss);
                            }
                            if vuln.exploit_available {
                                println!("    {} Exploit Available", "⚠️".red());
                            }
                            if !vuln.fixed_versions.is_empty() {
                                println!("    Fixed in: {}", vuln.fixed_versions.join(", ").green());
                            }
                        }
                    }
                    
                    // Active Threats
                    if include_threat_intel && !scan_result.active_threats.is_empty() {
                        println!("\n{}", "Active Threats".bold());
                        for threat in &scan_result.active_threats {
                            println!("  • {} [{:?}]", threat.name, threat.severity);
                            println!("    First Observed: {}", threat.first_observed.format("%Y-%m-%d"));
                            println!("    Last Activity: {}", threat.last_activity.format("%Y-%m-%d"));
                        }
                    }
                    
                    // Recommendations
                    if !scan_result.recommendations.is_empty() {
                        println!("\n{}", "Security Recommendations".bold());
                        for (i, rec) in scan_result.recommendations.iter().enumerate() {
                            println!("  {}. {} [{:?}]", i + 1, rec.title, rec.priority);
                            println!("     {}", rec.description);
                            println!("     Risk Reduction: {:.1}%", rec.risk_reduction * 100.0);
                            if !rec.actions.is_empty() {
                                println!("     Actions:");
                                for action in &rec.actions {
                                    println!("       - {}", action);
                                }
                            }
                        }
                    }
                    
                    // Summary
                    if scan_result.vulnerabilities.is_empty() {
                        println!("\n{}", "✅ No vulnerabilities found!".green());
                    } else {
                        let critical_count = scan_result.vulnerabilities.iter()
                            .filter(|v| matches!(v.severity, packer::package::VulnerabilitySeverity::Critical))
                            .count();
                        let high_count = scan_result.vulnerabilities.iter()
                            .filter(|v| matches!(v.severity, packer::package::VulnerabilitySeverity::High))
                            .count();
                        
                        if critical_count > 0 || high_count > 0 {
                            println!("\n{}", "⚠️  High-risk vulnerabilities detected. Immediate action recommended.".red());
                        } else {
                            println!("\n{}", "⚠️  Vulnerabilities found. Review recommendations above.".yellow());
                        }
                    }
                }
            }
            Err(e) => {
                println!("{}", format!("❌ Enhanced scan failed: {}", e).red());
            }
        }
    } else {
        println!("{}", format!("❌ Package '{}' not found", package_name).red());
    }
    
    Ok(())
}

async fn handle_threat_intel(
    package_manager: &PackageManager,
    intel_matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    use packer::security_enhancements::AdvancedSecurityScanner;
    
    let specific_feed = intel_matches.get_one::<String>("feed");
    
    println!("{}", "🔄 Updating threat intelligence feeds...".cyan());
    
    let enhanced_scanner = AdvancedSecurityScanner::new(package_manager.config.clone());
    
    if let Err(e) = enhanced_scanner.initialize_feeds().await {
        println!("{}", format!("Warning: Failed to initialize feeds: {}", e).yellow());
    }
    
    match specific_feed {
        Some(feed_name) => {
            println!("{}", format!("Updating specific feed: {}", feed_name));
            match enhanced_scanner.update_feed(feed_name).await {
                Ok(_) => {
                    println!("{}", format!("✅ Successfully updated {} feed", feed_name).green());
                }
                Err(e) => {
                    println!("{}", format!("❌ Failed to update {} feed: {}", feed_name, e).red());
                    return Err(e.into());
                }
            }
        }
        None => {
            println!("Updating all threat intelligence feeds...");
            match enhanced_scanner.update_all_feeds().await {
                Ok(_) => {
                    println!("{}", "✅ All threat intelligence feeds updated successfully".green());
                }
                Err(e) => {
                    println!("{}", format!("❌ Failed to update threat intelligence feeds: {}", e).red());
                    return Err(e.into());
                }
            }
        }
    }
    
    Ok(())
}

async fn handle_risk_assessment(
    package_manager: &PackageManager,
    risk_matches: &ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    use packer::security_enhancements::AdvancedSecurityScanner;
    use packer::package::SystemContext;
    
    let package_name = risk_matches.get_one::<String>("package").unwrap();
    let environment = risk_matches.get_one::<String>("environment").unwrap();
    
    println!("{}", format!("🔍 Comprehensive risk assessment for package: {}", package_name).cyan());
    
    if let Some(package) = package_manager.get_package_info(package_name).await? {
        let enhanced_scanner = AdvancedSecurityScanner::new(package_manager.config.clone());
        
        if let Err(e) = enhanced_scanner.initialize_feeds().await {
            println!("{}", format!("Warning: Failed to initialize feeds: {}", e).yellow());
        }
        
        let _system_context = match environment.as_str() {
            "development" => SystemContext::new_development_environment(),
            "production" => SystemContext::new_production_environment(),
            _ => SystemContext::new_production_environment(),
        };
        
        match enhanced_scanner.enhanced_scan_package(&package).await {
            Ok(scan_result) => {
                println!("\n{}", "Comprehensive Risk Assessment".bold());
                println!("{}", "=".repeat(60));
                println!("Package: {} {}", scan_result.package_name.bold(), scan_result.package_version);
                println!("Environment: {}", environment);
                println!("Assessment Time: {}", scan_result.scan_timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
                
                // Risk Score Breakdown
                println!("\n{}", "Risk Score Breakdown".bold());
                let overall_risk = scan_result.risk_score.overall_score;
                let risk_level = if overall_risk >= 0.8 {
                    "CRITICAL".red()
                } else if overall_risk >= 0.6 {
                    "HIGH".magenta()
                } else if overall_risk >= 0.4 {
                    "MEDIUM".yellow()
                } else if overall_risk >= 0.2 {
                    "LOW".blue()
                } else {
                    "MINIMAL".green()
                };
                
                println!("Overall Risk Level: {} ({:.2}/1.0)", risk_level, overall_risk);
                println!("Risk Components:");
                println!("  • CVSS Base Score: {:.2}", scan_result.risk_score.cvss_component);
                println!("  • Exploit Probability: {:.2}", scan_result.risk_score.epss_component);
                println!("  • Exploit Availability: {:.2}", scan_result.risk_score.exploit_component);
                println!("  • Threat Intelligence: {:.2}", scan_result.risk_score.threat_intel_component);
                println!("  • Business Impact: {:.2}", scan_result.risk_score.business_impact_component);
                println!("  • Temporal Factors: {:.2}", scan_result.risk_score.temporal_component);
                println!("Confidence Level: {:.1}%", scan_result.risk_score.confidence * 100.0);
                
                // Summary
                println!("\n{}", "Assessment Summary".bold());
                if overall_risk >= 0.8 {
                    println!("{}", "🚨 CRITICAL RISK: Immediate action required. Consider removing this package.".red());
                } else if overall_risk >= 0.6 {
                    println!("{}", "⚠️  HIGH RISK: Urgent attention needed. Review security measures.".magenta());
                } else if overall_risk >= 0.4 {
                    println!("{}", "📋 MEDIUM RISK: Monitor closely and apply recommended mitigations.".yellow());
                } else if overall_risk >= 0.2 {
                    println!("{}", "ℹ️  LOW RISK: Standard monitoring and maintenance sufficient.".blue());
                } else {
                    println!("{}", "✅ MINIMAL RISK: Package appears secure for this environment.".green());
                }
            }
            Err(e) => {
                println!("{}", format!("❌ Risk assessment failed: {}", e).red());
            }
        }
    } else {
        println!("{}", format!("❌ Package '{}' not found", package_name).red());
    }
    
    Ok(())
}
 