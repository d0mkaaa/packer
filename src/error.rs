use thiserror::Error;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

pub type PackerResult<T> = Result<T, PackerError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCategory {
    Network,
    Security,
    Dependency,
    Compatibility,
    Database,
    Integrity,
    Operation,
    General,
    Transaction,
    Performance,
    Resource,
    UserInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub error_id: String,
    pub timestamp: u64,
    pub operation: String,
    pub component: String,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub recoverable: bool,
    pub recovery_suggestions: Vec<RecoverySuggestion>,
    pub additional_info: HashMap<String, String>,
    pub stack_trace: Option<String>,
    pub user_impact: UserImpact,
    pub telemetry_data: Option<TelemetryData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ErrorSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySuggestion {
    pub suggestion_type: RecoveryType,
    pub description: String,
    pub automatic: bool,
    pub user_action_required: bool,
    pub estimated_fix_time: Option<std::time::Duration>,
    pub success_probability: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryType {
    Retry,
    Alternative,
    Rollback,
    UserIntervention,
    SystemRepair,
    ConfigurationFix,
    DependencyInstall,
    NetworkFix,
    PermissionFix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserImpact {
    None,
    Low,
    Medium,
    High,
    Severe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryData {
    pub system_info: HashMap<String, String>,
    pub resource_usage: HashMap<String, f64>,
    pub recent_operations: Vec<String>,
    pub performance_metrics: HashMap<String, f64>,
}

#[derive(Error, Debug)]
pub enum PackerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("Semaphore error: {0}")]
    Semaphore(#[from] tokio::sync::AcquireError),

    #[error("Package '{0}' not found")]
    PackageNotFound(String),

    #[error("Package '{0}' is not installed")]
    PackageNotInstalled(String),

    #[error("Package '{0}' is already installed")]
    PackageAlreadyInstalled(String),

    #[error("Dependency conflict: {0}")]
    DependencyConflict(String),

    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),

    #[error("Invalid package name: {0}")]
    InvalidPackageName(String),

    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),

    #[error("Repository error: {0}")]
    RepositoryError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Installation failed: {0}")]
    InstallationFailed(String),

    #[error("Removal failed: {0}")]
    RemovalFailed(String),

    #[error("Download failed: {0}")]
    DownloadFailed(String),

    #[error("Build failed: {0}")]
    BuildFailed(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Security error: {0}")]
    SecurityError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Operation timed out: {0}")]
    Timeout(String),

    #[error("Operation cancelled: {0}")]
    Cancelled(String),

    #[error("Repository sync failed: {0}")]
    RepositorySyncFailed(String),

    #[error("Transaction error: {0}")]
    TransactionError(String),

    #[error("Transaction rollback failed: {0}")]
    TransactionRollbackFailed(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("System integration error: {0}")]
    SystemIntegrationError(String),

    #[error("Parallel operation error: {0}")]
    ParallelOperationError(String),

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Critical system error: {0}")]
    CriticalSystemError(String),

    #[error("Enhanced error: {message}")]
    EnhancedError {
        message: String,
        context: ErrorContext,
    },

    /// Network-related errors
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Integrity check failures
    #[error("Integrity check failed: {0}")]
    IntegrityCheckFailed(String),

    /// Compatibility issues
    #[error("Compatibility error: {0}")]
    CompatibilityError(String),

    /// User input validation errors
    #[error("User input error: {0}")]
    UserInputError(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Archive errors
    #[error("Archive error: {0}")]
    ArchiveError(String),

    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),

    /// Validation error
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Timeout error
    #[error("Timeout error: {0}")]
    TimeoutError(String),

    /// Service unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Hash verification failed
    #[error("Hash verification failed: {0}")]
    HashVerificationFailed(String),

    /// Authentication error
    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    /// Authorization error
    #[error("Authorization error: {0}")]
    AuthorizationError(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    /// Mirror unavailable
    #[error("Mirror unavailable: {0}")]
    MirrorUnavailable(String),

    /// Package corrupted
    #[error("Package corrupted: {0}")]
    PackageCorrupted(String),

    /// Health check failed
    #[error("Health check failed: {0}")]
    HealthCheckFailed(String),

    /// System incompatible
    #[error("System incompatible: {0}")]
    SystemIncompatible(String),

    /// Rollback failed
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
}

impl From<zip::result::ZipError> for PackerError {
    fn from(err: zip::result::ZipError) -> Self {
        PackerError::ArchiveError(format!("ZIP error: {}", err))
    }
}
impl From<uuid::Error> for PackerError {
    fn from(err: uuid::Error) -> Self {
        PackerError::Unknown(format!("UUID error: {}", err))
    }
}
impl From<semver::Error> for PackerError {
    fn from(err: semver::Error) -> Self {
        PackerError::InvalidVersion(format!("Semver error: {}", err))
    }
}
impl From<tokio::task::JoinError> for PackerError {
    fn from(err: tokio::task::JoinError) -> Self {
        PackerError::Unknown(format!("Task join error: {}", err))
    }
}
impl From<tempfile::PersistError> for PackerError {
    fn from(err: tempfile::PersistError) -> Self {
        PackerError::Io(err.error)
    }
}
impl From<std::num::ParseIntError> for PackerError {
    fn from(err: std::num::ParseIntError) -> Self {
        PackerError::ValidationError(format!("Parse int error: {}", err))
    }
}
impl From<std::str::Utf8Error> for PackerError {
    fn from(err: std::str::Utf8Error) -> Self {
        PackerError::ValidationError(format!("UTF-8 error: {}", err))
    }
}
impl From<std::string::FromUtf8Error> for PackerError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        PackerError::ValidationError(format!("UTF-8 conversion error: {}", err))
    }
}
impl PackerError {
    pub fn is_network_error(&self) -> bool {
        matches!(
            self,
            PackerError::Http(_)
                | PackerError::NetworkError(_)
                | PackerError::TimeoutError(_)
                | PackerError::ServiceUnavailable(_)
        )
    }
    pub fn is_security_error(&self) -> bool {
        matches!(
            self,
            PackerError::SecurityError(_)
                | PackerError::SignatureVerificationFailed(_)
                | PackerError::HashVerificationFailed(_)
                | PackerError::AuthenticationError(_)
                | PackerError::AuthorizationError(_)
        )
    }
    pub fn is_dependency_error(&self) -> bool {
        matches!(
            self,
            PackerError::DependencyConflict(_) | PackerError::CircularDependency(_)
        )
    }
    pub fn is_user_error(&self) -> bool {
        matches!(
            self,
            PackerError::InvalidArguments(_)
                | PackerError::InvalidPackageName(_)
                | PackerError::InvalidVersion(_)
                | PackerError::PackageNotFound(_)
        )
    }
    pub fn is_system_error(&self) -> bool {
        matches!(
            self,
            PackerError::Io(_)
                | PackerError::PermissionDenied(_)
                | PackerError::ResourceExhausted(_)
        )
    }
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            PackerError::Http(_)
                | PackerError::NetworkError(_)
                | PackerError::TimeoutError(_)
                | PackerError::RateLimitExceeded(_)
                | PackerError::ServiceUnavailable(_)
                | PackerError::MirrorUnavailable(_)
                | PackerError::RepositorySyncFailed(_)
                | PackerError::PackageCorrupted(_)
                | PackerError::HealthCheckFailed(_)
                | PackerError::DownloadFailed(_)
        )
    }
    pub fn is_compatibility_error(&self) -> bool {
        matches!(
            self,
            PackerError::CompatibilityError(_)
                | PackerError::SystemIncompatible(_)
                | PackerError::DependencyConflict(_)
        )
    }
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            PackerError::DatabaseError(_)
                | PackerError::SecurityError(_)
                | PackerError::PackageCorrupted(_)
                | PackerError::RecoveryFailed(_)
                | PackerError::RollbackFailed(_)
        )
    }
//     pub fn requires_immediate_attention(&self) -> bool {
//         matches!(
//             self,
//             PackerError::SecurityError(_)
//                 | PackerError::PackageQuarantined(_)
//                 | PackerError::RecoveryFailed(_)
//                 | PackerError::RollbackFailed(_)
//         )
// //     }
// //     pub fn get_recovery_suggestion(&self) -> Option<String> {
//         match self {
//             PackerError::NetworkError(_) => Some("Check network connection and try again".to_string()),
//             PackerError::TimeoutError(_) => Some("Increase timeout or try again later".to_string()),
//             PackerError::DownloadFailed(_) => Some("Try downloading from a different mirror".to_string()),
//             PackerError::PackageCorrupted(_) => Some("Re-download the package or verify checksums".to_string()),
//             PackerError::HealthCheckFailed(_) => Some("Run package verification and repair".to_string()),
//             PackerError::MirrorUnavailable(_) => Some("Switch to a different mirror or repository".to_string()),
//             PackerError::RepositorySyncFailed(_) => Some("Update repository cache and try again".to_string()),
//             PackerError::DependencyConflict(_) => Some("Resolve dependency conflicts manually".to_string()),
//             PackerError::CompatibilityError(_) => Some("Check system compatibility requirements".to_string()),
//             PackerError::SystemIncompatible(_) => Some("Upgrade system or find compatible version".to_string()),
//             _ => None,
//         }
//     }
//     pub fn get_error_category(&self) -> ErrorCategory {
//         match self {
//             PackerError::NetworkError(_) | PackerError::TimeoutError(_) | PackerError::Http(_) => ErrorCategory::Network,
//             PackerError::SecurityError(_) | PackerError::SignatureVerificationFailed(_) => ErrorCategory::Security,
//             PackerError::DependencyConflict(_) | PackerError::CircularDependency(_) => ErrorCategory::Dependency,
//             PackerError::CompatibilityError(_) | PackerError::SystemIncompatible(_) => ErrorCategory::Compatibility,
//             PackerError::DatabaseError(_) | PackerError::TransactionError(_) => ErrorCategory::Database,
//             PackerError::PackageCorrupted(_) | PackerError::HealthCheckFailed(_) => ErrorCategory::Integrity,
//             PackerError::InstallationFailed(_) | PackerError::RemovalFailed(_) => ErrorCategory::Operation,
//             _ => ErrorCategory::General,
//         }
//     }
//     pub fn exit_code(&self) -> i32 {
//         match self {
//             PackerError::InvalidArguments(_) => 2,
//             PackerError::PackageNotFound(_) => 3,
//             PackerError::DependencyConflict(_) => 4,
//             PackerError::PermissionDenied(_) => 5,
//             PackerError::SecurityError(_) | PackerError::PackageQuarantined(_) => 6,
//             PackerError::NetworkError(_) | PackerError::Http(_) => 7,
//             PackerError::ConfigError(_) => 8,
//             PackerError::DatabaseError(_) => 9,
//             PackerError::CompatibilityError(_) | PackerError::SystemIncompatible(_) => 10,
//             PackerError::PackageCorrupted(_) | PackerError::HealthCheckFailed(_) => 11,
//             PackerError::RecoveryFailed(_) | PackerError::RollbackFailed(_) => 12,
//             PackerError::MirrorUnavailable(_) | PackerError::RepositorySyncFailed(_) => 13,
//             _ => 1,
//         }
}

pub struct ErrorHandler {
    error_history: Vec<ErrorContext>,
    _recovery_strategies: HashMap<String, Vec<RecoverySuggestion>>,
    auto_recovery_enabled: bool,
    telemetry_enabled: bool,
}

impl ErrorHandler {
    pub fn new() -> Self {
        Self {
            error_history: Vec::new(),
            _recovery_strategies: HashMap::new(),
            auto_recovery_enabled: true,
            telemetry_enabled: true,
        }
    }

    pub fn create_enhanced_error(
        &mut self,
        message: String,
        operation: String,
        component: String,
        severity: ErrorSeverity,
        category: ErrorCategory,
    ) -> PackerError {
        let error_id = self.generate_error_id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let context = ErrorContext {
            error_id: error_id.clone(),
            timestamp,
            operation,
            component,
            severity: severity.clone(),
            category: category.clone(),
            recoverable: self.is_recoverable(&category),
            recovery_suggestions: self.generate_recovery_suggestions(&category),
            additional_info: HashMap::new(),
            stack_trace: None,
            user_impact: self.assess_user_impact(&severity),
            telemetry_data: if self.telemetry_enabled {
                Some(self.collect_telemetry_data())
            } else {
                None
            },
        };

        self.error_history.push(context.clone());

        PackerError::EnhancedError { message, context }
    }

    pub async fn attempt_recovery(&self, error: &PackerError) -> PackerResult<bool> {
        if !self.auto_recovery_enabled {
            return Ok(false);
        }

        match error {
            PackerError::EnhancedError { context, .. } => {
                for suggestion in &context.recovery_suggestions {
                    if suggestion.automatic && suggestion.success_probability > 0.7 {
                        match suggestion.suggestion_type {
                            RecoveryType::Retry => {
                                log::info!("Attempting automatic retry for error {}", context.error_id);
                                return Ok(true);
                            }
                            RecoveryType::Alternative => {
                                log::info!("Attempting alternative approach for error {}", context.error_id);
                                return Ok(true);
                            }
                            RecoveryType::SystemRepair => {
                                log::info!("Attempting system repair for error {}", context.error_id);
                                return Ok(self.attempt_system_repair().await);
                            }
                            _ => continue,
                        }
                    }
                }
            }
            PackerError::NetworkError(_) => {
                return Ok(self.attempt_network_recovery().await);
            }
            PackerError::RepositoryError(_) => {
                return Ok(self.attempt_repository_recovery().await);
            }
            _ => {}
        }

        Ok(false)
    }

    fn generate_recovery_suggestions(&self, category: &ErrorCategory) -> Vec<RecoverySuggestion> {
        match category {
            ErrorCategory::Network => vec![
                RecoverySuggestion {
                    suggestion_type: RecoveryType::Retry,
                    description: "Retry operation with exponential backoff".to_string(),
                    automatic: true,
                    user_action_required: false,
                    estimated_fix_time: Some(std::time::Duration::from_secs(30)),
                    success_probability: 0.8,
                },
                RecoverySuggestion {
                    suggestion_type: RecoveryType::NetworkFix,
                    description: "Check network connectivity and proxy settings".to_string(),
                    automatic: false,
                    user_action_required: true,
                    estimated_fix_time: Some(std::time::Duration::from_secs(120)),
                    success_probability: 0.9,
                },
            ],
            ErrorCategory::Dependency => vec![
                RecoverySuggestion {
                    suggestion_type: RecoveryType::DependencyInstall,
                    description: "Install missing dependencies automatically".to_string(),
                    automatic: true,
                    user_action_required: false,
                    estimated_fix_time: Some(std::time::Duration::from_secs(60)),
                    success_probability: 0.75,
                },
                RecoverySuggestion {
                    suggestion_type: RecoveryType::Alternative,
                    description: "Use alternative dependency resolution strategy".to_string(),
                    automatic: true,
                    user_action_required: false,
                    estimated_fix_time: Some(std::time::Duration::from_secs(45)),
                    success_probability: 0.6,
                },
            ],
            ErrorCategory::Transaction => vec![
                RecoverySuggestion {
                    suggestion_type: RecoveryType::Rollback,
                    description: "Rollback transaction to previous state".to_string(),
                    automatic: true,
                    user_action_required: false,
                    estimated_fix_time: Some(std::time::Duration::from_secs(90)),
                    success_probability: 0.95,
                },
            ],
            _ => vec![
                RecoverySuggestion {
                    suggestion_type: RecoveryType::Retry,
                    description: "Retry operation".to_string(),
                    automatic: false,
                    user_action_required: true,
                    estimated_fix_time: Some(std::time::Duration::from_secs(10)),
                    success_probability: 0.5,
                },
            ],
        }
    }

    /// Helper methods for error analysis and recovery
    fn is_recoverable(&self, category: &ErrorCategory) -> bool {
        matches!(
            category,
            ErrorCategory::Network
                | ErrorCategory::Dependency
                | ErrorCategory::Transaction
                | ErrorCategory::Operation
        )
    }

    fn assess_user_impact(&self, severity: &ErrorSeverity) -> UserImpact {
        match severity {
            ErrorSeverity::Critical => UserImpact::Severe,
            ErrorSeverity::High => UserImpact::High,
            ErrorSeverity::Medium => UserImpact::Medium,
            ErrorSeverity::Low => UserImpact::Low,
            ErrorSeverity::Info | ErrorSeverity::Warning => UserImpact::None,
        }
    }

    fn generate_error_id(&self) -> String {
        format!(
            "ERR-{}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            self.error_history.len()
        )
    }

    fn collect_telemetry_data(&self) -> TelemetryData {
        TelemetryData {
            system_info: HashMap::new(),
            resource_usage: HashMap::new(),
            recent_operations: Vec::new(),
            performance_metrics: HashMap::new(),
        }
    }

    async fn attempt_system_repair(&self) -> bool {
        log::info!("Attempting system repair");
        true
    }

    async fn attempt_network_recovery(&self) -> bool {
        log::info!("Attempting network recovery");
        true
    }

    async fn attempt_repository_recovery(&self) -> bool {
        log::info!("Attempting repository recovery");
        true
    }

    /// Get error statistics and patterns
    pub fn get_error_statistics(&self) -> ErrorStatistics {
        let total_errors = self.error_history.len();
        let mut category_counts = HashMap::new();
        let mut severity_counts = HashMap::new();
        let mut recoverable_count = 0;

        for error in &self.error_history {
            *category_counts.entry(error.category.clone()).or_insert(0) += 1;
            *severity_counts.entry(error.severity.clone()).or_insert(0) += 1;
            if error.recoverable {
                recoverable_count += 1;
            }
        }

        ErrorStatistics {
            total_errors,
            category_distribution: category_counts,
            severity_distribution: severity_counts,
            recoverable_percentage: if total_errors > 0 {
                (recoverable_count as f64 / total_errors as f64) * 100.0
            } else {
                0.0
            },
            recent_error_trend: self.calculate_error_trend(),
        }
    }

    fn calculate_error_trend(&self) -> f64 {
        if self.error_history.len() < 10 {
            return 0.0;
        }
        
        let recent_errors = self.error_history.len().saturating_sub(10);
        let total_errors = self.error_history.len();
        
        (recent_errors as f64 / total_errors as f64) * 100.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorStatistics {
    pub total_errors: usize,
    pub category_distribution: HashMap<ErrorCategory, usize>,
    pub severity_distribution: HashMap<ErrorSeverity, usize>,
    pub recoverable_percentage: f64,
    pub recent_error_trend: f64,
} 