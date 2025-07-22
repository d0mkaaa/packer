pub mod compression;
pub mod config;
pub mod core;
pub mod dependency;
pub mod error;
pub mod gpg_manager;
pub mod mirrors;
pub mod native_db;
pub mod native_format;
pub mod package;
pub mod parallel_ops;
pub mod repository;
pub mod resolver;
pub mod security_enhancements;
pub mod storage;
pub mod utils;

pub use compression::{CompressionFormat, CompressionManager, DeltaManager, PackageDelta};
pub use config::Config;
pub use core::{CorePackage, CorePackageManager, InstallStatus, SourceType};
pub use error::{PackerError, PackerResult};
pub use mirrors::{Mirror, MirrorConfig, MirrorManager, MirrorStats};
pub use native_db::{DatabaseStats, NativePackageDatabase};
pub use native_format::{NativePackage, NativePackageManager, PackageFormat, PackageMetadata};
pub use package::PackageManager;
pub use resolver::{
    Conflict, ConflictReason, ConflictSeverity, DependencyResolver, DynamicPackageResolver,
    FastDependencyResolver, FastResolutionResult, ResolutionResult,
};

pub const PACKER_VERSION: &str = "0.2.2";

use lazy_static::lazy_static;
use std::path::PathBuf;

lazy_static! {
    pub static ref PACKER_HOME: PathBuf = {
        if let Ok(home) = std::env::var("PACKER_HOME") {
            PathBuf::from(home)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".packer")
        } else {
            PathBuf::from("/tmp/.packer")
        }
    };
    pub static ref PACKER_CONFIG: PathBuf = {
        if let Ok(config_home) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(config_home).join("packer")
        } else {
            PACKER_HOME.join("config")
        }
    };
    pub static ref PACKER_CACHE: PathBuf = {
        if let Ok(cache_home) = std::env::var("XDG_CACHE_HOME") {
            PathBuf::from(cache_home).join("packer")
        } else {
            PACKER_HOME.join("cache")
        }
    };
    pub static ref PACKER_DATA: PathBuf = {
        if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(data_home).join("packer")
        } else {
            PACKER_HOME.join("data")
        }
    };
}
