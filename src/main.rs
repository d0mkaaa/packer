use chrono::{DateTime, Utc};
use clap::{Arg, ArgAction, ArgMatches, Command};
use colored::Colorize;
use log::info;
use packer::{
    config::Config,
    core::{CorePackageManager, InstallStatus},
    utils::{format_duration, format_size},
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::Instant;
use tokio;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub id: String,
    pub packages: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
    pub duration: u64,
    pub user: String,
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
    info!(
        "Operation completed in {}",
        format_duration(duration.as_secs())
    );
}

fn build_cli() -> Command {
    Command::new("packer")
        .version("0.2.2")
        .about("Packer is a simplified, fast package manager with native dependency resolution and intelligent package handling.")
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
        .subcommand(Command::new("install")
            .about("Install packages")
            .alias("i")
            .arg(Arg::new("packages")
                .required(true)
                .num_args(1..)
                .help("Package names to install"))
            .arg(Arg::new("force")
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Force installation")))
        .subcommand(Command::new("remove")
            .about("Remove packages")
            .alias("r")
            .arg(Arg::new("packages")
                .required(true)
                .num_args(1..)
                .help("Package names to remove")))
        .subcommand(Command::new("search")
            .about("Search for packages")
            .alias("s")
            .arg(Arg::new("query")
                .required(true)
                .help("Search query")))
        .subcommand(Command::new("list")
            .about("List installed packages (interactive by default)")
            .alias("l")
            .arg(Arg::new("simple")
                .long("simple")
                .action(ArgAction::SetTrue)
                .help("Use simple non-interactive output"))
            .arg(Arg::new("updates")
                .long("updates")
                .action(ArgAction::SetTrue)
                .help("Show only packages with available updates"))
            .arg(Arg::new("system")
                .long("system")
                .action(ArgAction::SetTrue)
                .help("Include system-wide packages from pacman")))
        .subcommand(Command::new("info")
            .about("Show package information")
            .arg(Arg::new("package")
                .required(true)
                .help("Package name")))
        .subcommand(Command::new("update")
            .about("Update package database")
            .alias("u"))
        .subcommand(Command::new("upgrade")
            .about("Upgrade all packages"))
        .subcommand(Command::new("mirrors")
            .about("Mirror management commands")
            .subcommand(Command::new("list")
                .about("List available mirrors")
                .arg(Arg::new("repo")
                    .help("Repository to list mirrors for")
                    .value_name("REPO")))
            .subcommand(Command::new("test")
                .about("Test mirror speeds")
                .arg(Arg::new("repo")
                    .help("Repository to test mirrors for")
                    .value_name("REPO")))
            .subcommand(Command::new("rank")
                .about("Rank all mirrors by performance"))
            .subcommand(Command::new("stats")
                .about("Show mirror statistics"))
            .subcommand(Command::new("update")
                .about("Update mirror list from official sources")))
}

async fn run_command(matches: ArgMatches) -> packer::PackerResult<()> {
    let config = load_config(&matches).await?;
    let mut package_manager = CorePackageManager::new(config.clone()).await?;

    match matches.subcommand() {
        Some(("install", sub_matches)) => {
            let packages: Vec<String> = sub_matches
                .get_many::<String>("packages")
                .unwrap()
                .cloned()
                .collect();

            if package_manager.should_auto_update() {
                println!("🔄 Database is stale, updating automatically before installation...");
                match package_manager.check_and_auto_update().await {
                    Ok(true) => println!("✅ Database updated successfully!"),
                    Ok(false) => {}
                    Err(e) => {
                        println!("⚠️  Failed to auto-update database: {}", e);
                        println!("Proceeding with installation using current data...");
                    }
                }
            }

            println!(
                "{}",
                format!("📦 Installing {} package(s)...", packages.len()).cyan()
            );

            match package_manager.install(&packages).await {
                Ok(()) => {
                    println!("{}", "✅ Installation completed successfully!".green());
                }
                Err(e) => {
                    println!("{}: {}", "❌ Installation failed".red(), e);
                    return Err(e);
                }
            }
        }

        Some(("remove", sub_matches)) => {
            let packages: Vec<String> = sub_matches
                .get_many::<String>("packages")
                .unwrap()
                .cloned()
                .collect();

            println!(
                "{}",
                format!("🗑️  Removing {} package(s)...", packages.len()).cyan()
            );
            package_manager.remove(&packages).await?;
            println!("{}", "✅ Removal completed successfully!".green());
        }

        Some(("search", sub_matches)) => {
            let query = sub_matches.get_one::<String>("query").unwrap();

            if package_manager.should_auto_update() {
                if let Some(age) = package_manager.get_database_age() {
                    let hours = age.num_hours();
                    let days = age.num_days();
                    if days > 0 {
                        println!(
                            "⚠️  Database is {} days old. Consider running 'packer update'",
                            days
                        );
                    } else if hours > 6 {
                        println!(
                            "⚠️  Database is {} hours old. Consider running 'packer update'",
                            hours
                        );
                    }
                }
            }

            println!("{}", format!("🔍 Searching for: {}", query).cyan());
            let results = package_manager.search(query).await?;

            if results.is_empty() {
                println!("{}", "No packages found anywhere.".yellow());
                return Ok(());
            }

            println!("\n{}", "Search Results:".bold());
            println!("{}", "=".repeat(80));

            for (i, package) in results.iter().enumerate() {
                if i >= 20 {
                    println!("... and {} more results", results.len() - 20);
                    break;
                }

                let status_icon = match package_manager.get_package_status(&package.name) {
                    InstallStatus::Installed => "✅",
                    InstallStatus::UpdateAvailable(_) => "🔄",
                    _ => "📦",
                };

                println!(
                    "{} {}/{} {} [{}]",
                    status_icon,
                    package.repository.blue(),
                    package.name.bold(),
                    package.version.green(),
                    package.arch.dimmed()
                );

                if !package.description.is_empty() {
                    println!("    {}", package.description.dimmed());
                }
                println!();
            }
        }

        Some(("list", sub_matches)) => {
            let simple = sub_matches.get_flag("simple");
            let updates_only = sub_matches.get_flag("updates");
            let include_system = sub_matches.get_flag("system");

            if simple || updates_only {
                simple_list_packages(&mut package_manager, updates_only, include_system).await?;
            } else {
                interactive_list_packages(&mut package_manager, include_system).await?;
            }
        }

        Some(("info", sub_matches)) => {
            let package_name = sub_matches.get_one::<String>("package").unwrap();
            let status = package_manager.get_package_status(package_name);

            println!(
                "{}",
                format!("📋 Package Information: {}", package_name)
                    .cyan()
                    .bold()
            );
            println!("{}", "=".repeat(50));

            match status {
                InstallStatus::Installed => {
                    if let Some(pkg) = package_manager
                        .list_installed()
                        .iter()
                        .find(|p| p.name == *package_name)
                    {
                        display_package_info(pkg);
                    }
                }
                InstallStatus::UpdateAvailable(new_version) => {
                    println!("{}", "Status: Update Available".yellow());
                    println!("New version: {}", new_version.green());
                    if let Some(pkg) = package_manager
                        .list_installed()
                        .iter()
                        .find(|p| p.name == *package_name)
                    {
                        display_package_info(pkg);
                    }
                }
                InstallStatus::NotInstalled => {
                    println!("{}", "Status: Not Installed".yellow());
                    if let Ok(results) = package_manager.search(package_name).await {
                        if let Some(pkg) = results.iter().find(|p| p.name == *package_name) {
                            display_package_info(pkg);
                        }
                    }
                }
                _ => {
                    println!("{}", "Package not found".red());
                }
            }
        }

        Some(("update", _)) => {
            println!("{}", "🔄 Updating package database...".cyan());

            if let Some(age) = package_manager.get_database_age() {
                let hours = age.num_hours();
                let days = age.num_days();
                if days > 0 {
                    println!("📅 Current database is {} days old", days);
                } else if hours > 0 {
                    println!("📅 Current database is {} hours old", hours);
                } else {
                    println!("📅 Current database is less than 1 hour old");
                }
            } else {
                println!("📅 No existing database found");
            }

            match package_manager.update_database().await {
                Ok(()) => {
                    let stats = package_manager.get_database_stats();
                    println!("{}", "✅ Database updated successfully!".green());
                    println!(
                        "📊 Official packages: {}",
                        stats.official_packages.to_string().bold()
                    );
                    println!("📊 AUR packages: {}", stats.aur_packages.to_string().bold());
                    println!(
                        "📊 Total packages: {}",
                        stats.total_packages.to_string().bold()
                    );

                    if let Some(last_updated) = stats.last_updated {
                        println!(
                            "🕒 Last updated: {}",
                            last_updated.format("%Y-%m-%d %H:%M:%S UTC")
                        );
                    }
                }
                Err(e) => {
                    println!("{}: {}", "❌ Failed to update database".red(), e);
                }
            }
        }

        Some(("upgrade", _)) => {
            println!("{}", "🔄 Checking for upgrades...".cyan());
            let installed = package_manager.list_installed();
            let mut upgradeable = Vec::new();

            for package in installed {
                if let InstallStatus::UpdateAvailable(new_version) =
                    package_manager.get_package_status(&package.name)
                {
                    upgradeable.push((package.name.clone(), package.version.clone(), new_version));
                }
            }

            if upgradeable.is_empty() {
                println!("{}", "✅ All packages are up to date!".green());
            } else {
                println!("Found {} upgradeable packages:", upgradeable.len());
                for (name, old_ver, new_ver) in &upgradeable {
                    println!("  {} {} → {}", name.bold(), old_ver.red(), new_ver.green());
                }

                print!("Proceed with upgrade? [Y/n] ");
                std::io::stdout().flush().unwrap();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();

                if input.trim().is_empty() || input.trim().to_lowercase() == "y" {
                    let package_names: Vec<String> =
                        upgradeable.into_iter().map(|(name, _, _)| name).collect();
                    package_manager.install(&package_names).await?;
                    println!("{}", "✅ Upgrade completed!".green());
                } else {
                    println!("{}", "Upgrade cancelled.".yellow());
                }
            }
        }

        Some(("mirrors", sub_matches)) => match sub_matches.subcommand() {
            Some(("list", list_matches)) => {
                let repo = list_matches
                    .get_one::<String>("repo")
                    .map(|s| s.as_str())
                    .unwrap_or("core");

                println!(
                    "{}",
                    format!("🪞 Available mirrors for {}:", repo).cyan().bold()
                );
                println!("{}", "=".repeat(60));

                let mirrors = package_manager.get_mirrors_for_repo(repo).await?;

                if mirrors.is_empty() {
                    println!("{}", "No mirrors available for this repository.".yellow());
                } else {
                    for (i, mirror) in mirrors.iter().enumerate() {
                        println!("{}. {}", i + 1, mirror.blue());
                    }
                    println!("\nTotal: {} mirrors", mirrors.len());
                }
            }

            Some(("test", test_matches)) => {
                let repo = test_matches
                    .get_one::<String>("repo")
                    .map(|s| s.as_str())
                    .unwrap_or("core");

                println!(
                    "{}",
                    format!("⚡ Testing mirror speeds for {}...", repo).cyan()
                );
                let results = package_manager.test_mirror_speeds(repo).await?;

                println!("\n{}", "Mirror Speed Test Results:".bold());
                println!("{}", "=".repeat(80));

                for (i, result) in results.iter().enumerate() {
                    let status = if result.success { "✅" } else { "❌" };
                    let time_str = format!("{}ms", result.response_time.as_millis());

                    println!(
                        "{} {}. {} - {}",
                        status,
                        i + 1,
                        result.mirror_url.blue(),
                        if result.success {
                            time_str.green()
                        } else {
                            "failed".red()
                        }
                    );

                    if let Some(error) = &result.error_message {
                        println!("     Error: {}", error.dimmed());
                    }
                }
            }

            Some(("rank", _)) => {
                println!("{}", "🏆 Ranking mirrors by performance...".cyan());
                package_manager.rank_mirrors().await?;
                println!("{}", "✅ Mirror ranking completed!".green());

                let stats = package_manager.get_mirror_stats();
                println!("\n{}", "Mirror Statistics:".bold());
                println!("Total mirrors: {}", stats.total_mirrors);
                println!("Active mirrors: {}", stats.active_mirrors);
                println!("Tested mirrors: {}", stats.tested_mirrors);
                println!(
                    "Average response time: {}ms",
                    stats.avg_response_time.as_millis()
                );
            }

            Some(("stats", _)) => {
                println!("{}", "📊 Mirror Statistics:".cyan().bold());
                println!("{}", "=".repeat(40));

                let stats = package_manager.get_mirror_stats();
                println!("Total mirrors: {}", stats.total_mirrors.to_string().bold());
                println!(
                    "Active mirrors: {}",
                    stats.active_mirrors.to_string().green()
                );
                println!(
                    "Tested mirrors: {}",
                    stats.tested_mirrors.to_string().blue()
                );
                println!(
                    "Average response time: {}ms",
                    stats.avg_response_time.as_millis().to_string().cyan()
                );

                if let Some(last_update) = stats.last_update {
                    println!(
                        "Last mirror update: {}",
                        last_update
                            .format("%Y-%m-%d %H:%M:%S UTC")
                            .to_string()
                            .dimmed()
                    );
                }
            }

            Some(("update", _)) => {
                println!("{}", "🔄 Updating mirror list...".cyan());
                package_manager.update_mirrors().await?;
                println!("{}", "✅ Mirror list updated successfully!".green());
            }

            _ => {
                println!(
                    "❌ Invalid mirror command. Use 'packer mirrors --help' for usage information."
                );
            }
        },

        _ => {
            println!("❌ Invalid command. Use --help for usage information.");
        }
    }

    Ok(())
}

fn display_package_info(package: &packer::core::CorePackage) {
    println!("Name: {}", package.name.bold());
    println!("Version: {}", package.version.green());
    println!("Repository: {}", package.repository.blue());
    println!("Architecture: {}", package.arch);
    println!("Description: {}", package.description);

    if package.download_size > 0 {
        println!("Download Size: {}", format_size(package.download_size));
    }
    if package.installed_size > 0 {
        println!("Installed Size: {}", format_size(package.installed_size));
    }

    if !package.dependencies.is_empty() {
        println!("Dependencies: {}", package.dependencies.join(", "));
    }

    if !package.maintainer.is_empty() {
        println!("Maintainer: {}", package.maintainer);
    }

    if !package.url.is_empty() {
        println!("URL: {}", package.url.blue().underline());
    }

    if let Some(install_date) = package.install_date {
        println!("Installed: {}", install_date.format("%Y-%m-%d %H:%M:%S"));
    }

    println!("Source Type: {:?}", package.source_type);
}

async fn get_system_packages() -> packer::PackerResult<Vec<packer::core::CorePackage>> {
    use std::process::Command;

    let output = Command::new("pacman")
        .args(&["-Q"])
        .output()
        .map_err(|e| packer::PackerError::Io(e))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut packages = Vec::new();

    for line in stdout.lines() {
        if let Some((name, version)) = line.split_once(' ') {
            packages.push(packer::core::CorePackage {
                name: name.to_string(),
                version: version.to_string(),
                description: String::new(),
                repository: "pacman".to_string(),
                arch: "x86_64".to_string(),
                download_size: 0,
                installed_size: 0,
                dependencies: Vec::new(),
                conflicts: Vec::new(),
                maintainer: "System".to_string(),
                url: String::new(),
                checksum: None,
                source_type: packer::core::SourceType::Official,
                install_date: None,
            });
        }
    }

    Ok(packages)
}

async fn simple_list_packages(
    package_manager: &mut CorePackageManager,
    updates_only: bool,
    include_system: bool,
) -> packer::PackerResult<()> {
    let mut all_packages = Vec::new();

    // Get packer-managed packages
    let packer_installed = package_manager.list_installed();
    for pkg in packer_installed {
        all_packages.push(pkg.clone());
    }

    // Get system packages if requested
    if include_system {
        let system_packages = get_system_packages().await?;
        for sys_pkg in system_packages {
            // don't add the same package twice that would be dumb
            if !all_packages.iter().any(|p| p.name == sys_pkg.name) {
                all_packages.push(sys_pkg);
            }
        }
    }

    if all_packages.is_empty() {
        println!("{}", "No packages installed.".yellow());
        return Ok(());
    }

    let mut packages_to_show = Vec::new();

    for package in &all_packages {
        let status = package_manager.get_package_status(&package.name);

        if updates_only {
            if let InstallStatus::UpdateAvailable(_) = status {
                packages_to_show.push((package, status));
            }
        } else {
            packages_to_show.push((package, status));
        }
    }

    if packages_to_show.is_empty() {
        if updates_only {
            println!("{}", "✅ All packages are up to date!".green());
        } else {
            println!("{}", "No packages installed.".yellow());
        }
        return Ok(());
    }

    if updates_only {
        println!("{}", "📋 Packages with Available Updates:".cyan().bold());
    } else {
        println!("{}", "📋 Installed Packages:".cyan().bold());
    }
    println!("{}", "=".repeat(80));

    for (package, status) in &packages_to_show {
        let install_date = package
            .install_date
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let status_info = match status {
            InstallStatus::UpdateAvailable(new_version) => {
                format!(" → {} {}", "UPDATE:".yellow(), new_version.green())
            }
            _ => String::new(),
        };

        println!(
            "{}/{} {} [{}] (installed: {}){}",
            package.repository.blue(),
            package.name.bold(),
            package.version.green(),
            package.arch.dimmed(),
            install_date.dimmed(),
            status_info
        );

        if !package.description.is_empty() {
            println!("    {}", package.description.dimmed());
        }
    }

    println!("\nTotal: {} packages", packages_to_show.len());
    Ok(())
}

async fn interactive_list_packages(
    package_manager: &mut CorePackageManager,
    include_system: bool,
) -> packer::PackerResult<()> {
    let mut all_packages = Vec::new();

    // Get packer-managed packages
    let packer_installed = package_manager.list_installed();
    for pkg in packer_installed {
        all_packages.push(pkg.clone());
    }

    // Get system packages if requested
    if include_system {
        let system_packages = get_system_packages().await?;
        for sys_pkg in system_packages {
            // don't add the same package twice that would be dumb
            if !all_packages.iter().any(|p| p.name == sys_pkg.name) {
                all_packages.push(sys_pkg);
            }
        }
    }

    if all_packages.is_empty() {
        println!("{}", "No packages installed.".yellow());
        return Ok(());
    }

    let mut filtered_packages = all_packages.clone();
    let mut current_page = 0;
    const PACKAGES_PER_PAGE: usize = 20;

    loop {
        // Clear screen
        print!("\x1B[2J\x1B[1;1H");

        let title = if include_system {
            "📋 All Installed Packages (Interactive Mode)"
        } else {
            "📋 Packer-Managed Packages (Interactive Mode)"
        };
        println!("{}", title.cyan().bold());
        println!("{}", "=".repeat(80));
        println!("Commands: [s]earch, [n]ext page, [p]revious page, [r]eset, [q]uit");
        if !include_system {
            println!("Tip: Use --system flag to include system packages from pacman");
        }
        println!("{}", "=".repeat(80));

        if filtered_packages.is_empty() {
            println!("{}", "No packages match your search criteria.".yellow());
        } else {
            let total_pages = (filtered_packages.len() + PACKAGES_PER_PAGE - 1) / PACKAGES_PER_PAGE;
            let start_idx = current_page * PACKAGES_PER_PAGE;
            let end_idx = std::cmp::min(start_idx + PACKAGES_PER_PAGE, filtered_packages.len());

            println!(
                "Page {}/{} | Showing {}-{} of {} packages",
                current_page + 1,
                total_pages,
                start_idx + 1,
                end_idx,
                filtered_packages.len()
            );
            println!();

            for (i, package) in filtered_packages[start_idx..end_idx].iter().enumerate() {
                let install_date = package
                    .install_date
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                // see if there's a newer version we can get
                let status_info = match package_manager.get_package_status(&package.name) {
                    InstallStatus::UpdateAvailable(new_version) => {
                        format!(" → {} {}", "UPDATE:".yellow(), new_version.green())
                    }
                    _ => String::new(),
                };

                println!(
                    "{:2}. {}/{} {} [{}] (installed: {}){}",
                    start_idx + i + 1,
                    package.repository.blue(),
                    package.name.bold(),
                    package.version.green(),
                    package.arch.dimmed(),
                    install_date.dimmed(),
                    status_info
                );

                if !package.description.is_empty() {
                    println!("     {}", package.description.dimmed());
                }
            }
        }

        println!();
        print!("Enter command: ");
        std::io::stdout().flush().unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let input = input.trim().to_lowercase();

        match input.as_str() {
            "q" | "quit" | "exit" => break,
            "s" | "search" => {
                print!("Search packages (name/description): ");
                std::io::stdout().flush().unwrap();
                let mut search_term = String::new();
                std::io::stdin().read_line(&mut search_term).unwrap();
                let search_term = search_term.trim().to_lowercase();

                if search_term.is_empty() {
                    continue;
                }

                filtered_packages = all_packages
                    .iter()
                    .filter(|pkg| {
                        pkg.name.to_lowercase().contains(&search_term)
                            || pkg.description.to_lowercase().contains(&search_term)
                            || pkg.repository.to_lowercase().contains(&search_term)
                    })
                    .cloned()
                    .collect();

                current_page = 0;
            }
            "r" | "reset" => {
                filtered_packages = all_packages.clone();
                current_page = 0;
            }
            "n" | "next" => {
                let total_pages =
                    (filtered_packages.len() + PACKAGES_PER_PAGE - 1) / PACKAGES_PER_PAGE;
                if current_page + 1 < total_pages {
                    current_page += 1;
                }
            }
            "p" | "prev" | "previous" => {
                if current_page > 0 {
                    current_page -= 1;
                }
            }
            _ => {
                if let Ok(num) = input.parse::<usize>() {
                    let start_idx = current_page * PACKAGES_PER_PAGE;
                    if num > 0
                        && num <= PACKAGES_PER_PAGE
                        && start_idx + num - 1 < filtered_packages.len()
                    {
                        let package = &filtered_packages[start_idx + num - 1];
                        display_package_info(package);
                        println!("\nPress Enter to continue...");
                        let mut _dummy = String::new();
                        std::io::stdin().read_line(&mut _dummy).unwrap();
                    }
                } else {
                    println!("Invalid command. Use s, n, p, r, q, or enter a package number.");
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }

    println!("{}", "Exited interactive package list.".green());
    Ok(())
}

async fn load_config(matches: &ArgMatches) -> packer::PackerResult<Config> {
    if let Some(config_path) = matches.get_one::<String>("config") {
        Config::load(Some(config_path))
    } else {
        Config::load(None)
    }
}
