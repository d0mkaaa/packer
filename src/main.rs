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
        .version("0.1.0")
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
            .about("List installed packages")
            .alias("l"))
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

        Some(("list", _)) => {
            println!("{}", "📋 Installed Packages:".cyan().bold());
            let installed = package_manager.list_installed();

            if installed.is_empty() {
                println!("{}", "No packages installed.".yellow());
                return Ok(());
            }

            println!("{}", "=".repeat(80));
            let package_count = installed.len();
            for package in &installed {
                // pls use reference to avoid moving
                let install_date = package
                    .install_date
                    .map(|d| d.format("%Y-%m-%d").to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                println!(
                    "{}/{} {} [{}] (installed: {})",
                    package.repository.blue(),
                    package.name.bold(),
                    package.version.green(),
                    package.arch.dimmed(),
                    install_date.dimmed()
                );

                if !package.description.is_empty() {
                    println!("    {}", package.description.dimmed());
                }
            }
            println!("\nTotal: {} packages", package_count);
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

async fn load_config(matches: &ArgMatches) -> packer::PackerResult<Config> {
    if let Some(config_path) = matches.get_one::<String>("config") {
        Config::load(Some(config_path))
    } else {
        Config::load(None)
    }
}
