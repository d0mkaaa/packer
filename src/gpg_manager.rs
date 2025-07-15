use crate::error::{PackerError, PackerResult};
use crate::config::Config;
use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GPGKeyInfo {
    pub id: String,
    pub fingerprint: String,
    pub user_id: String,
    pub expires: Option<DateTime<Utc>>,
    pub trust_level: TrustLevel,
    pub imported_at: DateTime<Utc>,
    pub key_type: String,
    pub key_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustLevel {
    Ultimate,
    Full,
    Marginal,
    Never,
    Unknown,
    Undefined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureVerificationResult {
    pub verified: bool,
    pub key_id: Option<String>,
    pub key_fingerprint: Option<String>,
    pub trust_level: TrustLevel,
    pub signature_timestamp: Option<DateTime<Utc>>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct GPGConfig {
    pub keyring_path: PathBuf,
    pub keyservers: Vec<String>,
    pub auto_import_keys: bool,
    pub require_signatures: bool,
    pub minimum_trust_level: TrustLevel,
    pub signature_timeout_secs: u64,
    pub allow_expired_keys: bool,
    pub verify_subkeys: bool,
}

pub struct GPGManager {
    config: GPGConfig,
    keyring_path: PathBuf,
    trusted_keys: HashMap<String, GPGKeyInfo>,
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Unknown
    }
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustLevel::Ultimate => write!(f, "ultimate"),
            TrustLevel::Full => write!(f, "full"),
            TrustLevel::Marginal => write!(f, "marginal"),
            TrustLevel::Never => write!(f, "never"),
            TrustLevel::Unknown => write!(f, "unknown"),
            TrustLevel::Undefined => write!(f, "undefined"),
        }
    }
}

impl TrustLevel {
    pub fn from_gpg_string(s: &str) -> Self {
        match s {
            "o" | "unknown" => TrustLevel::Unknown,
            "i" | "invalid" => TrustLevel::Never,
            "d" | "disabled" => TrustLevel::Never,
            "r" | "revoked" => TrustLevel::Never,
            "e" | "expired" => TrustLevel::Unknown,
            "-" | "none" => TrustLevel::Undefined,
            "q" | "undefined" => TrustLevel::Undefined,
            "n" | "never" => TrustLevel::Never,
            "m" | "marginal" => TrustLevel::Marginal,
            "f" | "full" => TrustLevel::Full,
            "u" | "ultimate" => TrustLevel::Ultimate,
            _ => TrustLevel::Unknown,
        }
    }

    pub fn is_trusted(&self) -> bool {
        matches!(self, TrustLevel::Full | TrustLevel::Ultimate)
    }

    pub fn is_acceptable(&self, minimum: &TrustLevel) -> bool {
        let self_level = self.level_value();
        let min_level = minimum.level_value();
        self_level >= min_level
    }

    fn level_value(&self) -> u8 {
        match self {
            TrustLevel::Never => 0,
            TrustLevel::Unknown => 1,
            TrustLevel::Undefined => 2,
            TrustLevel::Marginal => 3,
            TrustLevel::Full => 4,
            TrustLevel::Ultimate => 5,
        }
    }
}

impl Default for GPGConfig {
    fn default() -> Self {
        let keyring_path = dirs::data_dir()
            .map(|d| d.join("packer").join("gnupg"))
            .unwrap_or_else(|| PathBuf::from("/tmp/packer/gnupg"));

        Self {
            keyring_path,
            keyservers: vec![
                "keyserver.ubuntu.com".to_string(),
                "keys.openpgp.org".to_string(),
                "pgp.mit.edu".to_string(),
            ],
            auto_import_keys: true,
            require_signatures: false, // default to false for stability and security
            minimum_trust_level: TrustLevel::Marginal,
            signature_timeout_secs: 30,
            allow_expired_keys: false,
            verify_subkeys: true,
        }
    }
}

impl GPGManager {
    pub fn new(config: Config) -> Self {
        let gpg_config = GPGConfig {
            keyring_path: config.gpg_config.keyring_path
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(|| GPGConfig::default().keyring_path),
            keyservers: if config.gpg_config.trusted_keyservers.is_empty() {
                GPGConfig::default().keyservers
            } else {
                config.gpg_config.trusted_keyservers
            },
            auto_import_keys: config.gpg_config.auto_import_keys,
            require_signatures: config.security_policy.require_signatures,
            minimum_trust_level: TrustLevel::from_gpg_string(&config.gpg_config.minimum_trust_level),
            ..GPGConfig::default()
        };

        Self {
            keyring_path: gpg_config.keyring_path.clone(),
            config: gpg_config,
            trusted_keys: HashMap::new(),
        }
    }

    pub async fn initialize(&mut self) -> PackerResult<()> {
        info!("Initializing GPG manager");
        
        if let Err(e) = fs::create_dir_all(&self.keyring_path).await {
            warn!("Failed to create GPG directory {:?}: {}", self.keyring_path, e);
        }

        if !self.is_gpg_available().await? {
            warn!("GPG is not available on this system. Signature verification will be disabled.");
            return Ok(());
        }

        self.load_trusted_keys().await?;

        info!("GPG manager initialized with {} trusted keys", self.trusted_keys.len());
        Ok(())
    }

    pub async fn verify_package_signature(&self, package_path: &Path, signature_path: Option<&Path>) -> PackerResult<SignatureVerificationResult> {
        if !self.is_gpg_available().await? {
            return Ok(SignatureVerificationResult {
                verified: false,
                key_id: None,
                key_fingerprint: None,
                trust_level: TrustLevel::Unknown,
                signature_timestamp: None,
                warnings: vec!["GPG not available".to_string()],
                errors: vec![],
            });
        }

        let sig_path = if let Some(sig) = signature_path {
            sig.to_path_buf()
        } else {
            let mut sig_file = package_path.to_path_buf();
            sig_file.set_extension("sig");
            if !sig_file.exists() {
                sig_file = package_path.with_extension("asc");
            }
            if !sig_file.exists() {
                return Ok(SignatureVerificationResult {
                    verified: false,
                    key_id: None,
                    key_fingerprint: None,
                    trust_level: TrustLevel::Unknown,
                    signature_timestamp: None,
                    warnings: vec!["No signature file found".to_string()],
                    errors: vec![],
                });
            }
            sig_file
        };

        self.verify_detached_signature(package_path, &sig_path).await
    }

    async fn verify_detached_signature(&self, file_path: &Path, signature_path: &Path) -> PackerResult<SignatureVerificationResult> {
        debug!("Verifying signature for {:?} with {:?}", file_path, signature_path);

        let mut cmd = Command::new("gpg");
        cmd.env("GNUPGHOME", &self.keyring_path)
           .arg("--batch")
           .arg("--no-tty")
           .arg("--status-fd").arg("2")
           .arg("--verify")
           .arg(signature_path)
           .arg(file_path)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(self.config.signature_timeout_secs),
            cmd.output()
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(PackerError::TimeoutError("GPG signature verification timed out".to_string())),
        };

        self.parse_verification_output(&output.stderr, &output.stdout).await
    }

    async fn parse_verification_output(&self, stderr: &[u8], _stdout: &[u8]) -> PackerResult<SignatureVerificationResult> {
        let stderr_str = String::from_utf8_lossy(stderr);
        
        let mut result = SignatureVerificationResult {
            verified: false,
            key_id: None,
            key_fingerprint: None,
            trust_level: TrustLevel::Unknown,
            signature_timestamp: None,
            warnings: Vec::new(),
            errors: Vec::new(),
        };

        let mut missing_key_id = None;
        let mut signature_valid = false;

        for line in stderr_str.lines() {
            if line.starts_with("[GNUPG:] ") {
                let parts: Vec<&str> = line[9..].split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                match parts[0] {
                    "GOODSIG" => {
                        signature_valid = true;
                        if parts.len() > 1 {
                            result.key_id = Some(parts[1].to_string());
                        }
                    }
                    "VALIDSIG" => {
                        if parts.len() > 1 {
                            result.key_fingerprint = Some(parts[1].to_string());
                        }
                        if parts.len() > 3 {
                            if let Ok(timestamp) = parts[3].parse::<i64>() {
                                result.signature_timestamp = DateTime::from_timestamp(timestamp, 0);
                            }
                        }
                    }
                    "TRUST_UNKNOWN" => {
                        result.trust_level = TrustLevel::Unknown;
                        result.warnings.push("Key trust level is unknown".to_string());
                    }
                    "TRUST_NEVER" => {
                        result.trust_level = TrustLevel::Never;
                        result.errors.push("Key is marked as never trusted".to_string());
                    }
                    "TRUST_MARGINAL" => {
                        result.trust_level = TrustLevel::Marginal;
                    }
                    "TRUST_FULL" => {
                        result.trust_level = TrustLevel::Full;
                    }
                    "TRUST_ULTIMATE" => {
                        result.trust_level = TrustLevel::Ultimate;
                    }
                    "NO_PUBKEY" => {
                        if parts.len() > 1 {
                            missing_key_id = Some(parts[1].to_string());
                            result.errors.push(format!("Public key {} not found", parts[1]));
                        }
                    }
                    "EXPKEYSIG" => {
                        result.warnings.push("Signature made by expired key".to_string());
                        if !self.config.allow_expired_keys {
                            result.errors.push("Expired key signatures not allowed".to_string());
                        }
                    }
                    "KEYEXPIRED" => {
                        result.warnings.push("Signing key has expired".to_string());
                    }
                    "SIGEXPIRED" => {
                        result.errors.push("Signature has expired".to_string());
                    }
                    "BADSIG" => {
                        result.errors.push("Bad signature".to_string());
                    }
                    _ => {}
                }
            }
        }

        if let Some(key_id) = missing_key_id {
            if self.config.auto_import_keys {
                info!("Attempting to auto-import missing key: {}", key_id);
                match self.import_key(&key_id).await {
                    Ok(key_info) => {
                        info!("Successfully imported key: {} ({})", key_info.id, key_info.user_id);
                        result.warnings.push("Key was automatically imported, consider manual verification".to_string());
                        // it marks as partially successful since it imported the key
                        result.key_id = Some(key_info.id);
                        result.trust_level = key_info.trust_level;
                        result.verified = result.trust_level.is_acceptable(&self.config.minimum_trust_level);
                    }
                    Err(e) => {
                        warn!("Failed to import key {}: {}", key_id, e);
                        result.errors.push(format!("Failed to import required key: {}", e));
                    }
                }
            }
        }

        result.verified = signature_valid && 
                         result.trust_level.is_acceptable(&self.config.minimum_trust_level) &&
                         result.errors.is_empty();

        Ok(result)
    }

    pub async fn import_key(&self, key_id: &str) -> PackerResult<GPGKeyInfo> {
        for keyserver in &self.config.keyservers {
            match self.import_from_keyserver(key_id, keyserver).await {
                Ok(key_info) => {
                    info!("Successfully imported key {} from {}", key_id, keyserver);
                    return Ok(key_info);
                }
                Err(e) => {
                    warn!("Failed to import key {} from {}: {}", key_id, keyserver, e);
                    continue;
                }
            }
        }

        Err(PackerError::SecurityError(format!(
            "Failed to import key {} from any keyserver", key_id
        )))
    }

    async fn import_from_keyserver(&self, key_id: &str, keyserver: &str) -> PackerResult<GPGKeyInfo> {
        debug!("Importing key {} from keyserver {}", key_id, keyserver);

        let mut cmd = Command::new("gpg");
        cmd.env("GNUPGHOME", &self.keyring_path)
           .arg("--batch")
           .arg("--no-tty")
           .arg("--keyserver").arg(keyserver)
           .arg("--recv-keys").arg(key_id)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        let output = match tokio::time::timeout(
            std::time::Duration::from_secs(60), // Longer timeout for key import
            cmd.output()
        ).await {
            Ok(result) => result?,
            Err(_) => return Err(PackerError::TimeoutError("GPG key import timed out".to_string())),
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PackerError::SecurityError(format!(
                "Failed to import key from {}: {}", keyserver, stderr
            )));
        }

        self.get_key_info(key_id).await
    }

    async fn get_key_info(&self, key_id: &str) -> PackerResult<GPGKeyInfo> {
        let mut cmd = Command::new("gpg");
        cmd.env("GNUPGHOME", &self.keyring_path)
           .arg("--batch")
           .arg("--no-tty")
           .arg("--with-colons")
           .arg("--list-keys")
           .arg(key_id)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        let output = cmd.output().await?;
        if !output.status.success() {
            return Err(PackerError::SecurityError(format!(
                "Failed to get key info for {}", key_id
            )));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        self.parse_key_info(&output_str)
    }

    fn parse_key_info(&self, gpg_output: &str) -> PackerResult<GPGKeyInfo> {
        let mut key_info = None;
        let mut user_id = "Unknown".to_string();

        for line in gpg_output.lines() {
            if line.starts_with("pub:") {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 10 {
                    let trust_level = TrustLevel::from_gpg_string(fields[1]);
                    let key_size = fields[2].parse::<u32>().unwrap_or(0);
                    let key_type = fields[3].to_string();
                    let key_id = fields[4].to_string();
                    let creation_time = fields[5].parse::<i64>().ok()
                        .and_then(|ts| DateTime::from_timestamp(ts, 0));
                    let expiration_time = if !fields[6].is_empty() {
                        fields[6].parse::<i64>().ok()
                            .and_then(|ts| DateTime::from_timestamp(ts, 0))
                    } else {
                        None
                    };

                    key_info = Some(GPGKeyInfo {
                        id: key_id.clone(),
                        fingerprint: key_id, // will be updated with full fingerprint if available
                        user_id: user_id.clone(),
                        expires: expiration_time,
                        trust_level,
                        imported_at: creation_time.unwrap_or_else(Utc::now),
                        key_type,
                        key_size,
                    });
                }
            } else if line.starts_with("uid:") {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 10 && !fields[9].is_empty() {
                    user_id = fields[9].to_string();
                    if let Some(ref mut info) = key_info {
                        info.user_id = user_id.clone();
                    }
                }
            } else if line.starts_with("fpr:") {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 10 && !fields[9].is_empty() {
                    if let Some(ref mut info) = key_info {
                        info.fingerprint = fields[9].to_string();
                    }
                }
            }
        }

        key_info.ok_or_else(|| {
            PackerError::SecurityError("Failed to parse key information".to_string())
        })
    }

    pub async fn list_keys(&self) -> PackerResult<Vec<GPGKeyInfo>> {
        let mut cmd = Command::new("gpg");
        cmd.env("GNUPGHOME", &self.keyring_path)
           .arg("--batch")
           .arg("--no-tty")
           .arg("--with-colons")
           .arg("--list-keys")
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        let output = cmd.output().await?;
        if !output.status.success() {
            return Err(PackerError::SecurityError(
                "Failed to list GPG keys".to_string()
            ));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut keys = Vec::new();
        let mut current_key = None;
        let mut current_uid = "Unknown".to_string();

        for line in output_str.lines() {
            if line.starts_with("pub:") {
                if let Some(key) = current_key.take() {
                    keys.push(key);
                }
                if let Ok(key) = self.parse_key_info(&format!("{}\\nuid:::::::::::{}\\n", line, current_uid)) {
                    current_key = Some(key);
                }
            } else if line.starts_with("uid:") {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 10 && !fields[9].is_empty() {
                    current_uid = fields[9].to_string();
                    if let Some(ref mut key) = current_key {
                        key.user_id = current_uid.clone();
                    }
                }
            } else if line.starts_with("fpr:") {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 10 && !fields[9].is_empty() {
                    if let Some(ref mut key) = current_key {
                        key.fingerprint = fields[9].to_string();
                    }
                }
            }
        }

        if let Some(key) = current_key {
            keys.push(key);
        }

        Ok(keys)
    }

    async fn load_trusted_keys(&mut self) -> PackerResult<()> {
        match self.list_keys().await {
            Ok(keys) => {
                for key in keys {
                    self.trusted_keys.insert(key.id.clone(), key);
                }
                debug!("Loaded {} trusted keys", self.trusted_keys.len());
            }
            Err(e) => {
                warn!("Failed to load trusted keys: {}", e);
            }
        }
        Ok(())
    }

    async fn is_gpg_available(&self) -> PackerResult<bool> {
        match Command::new("gpg").arg("--version").output().await {
            Ok(output) => Ok(output.status.success()),
            Err(_) => Ok(false),
        }
    }

    pub fn should_skip_signature_check(&self) -> bool {
        !self.config.require_signatures
    }

    pub fn get_trusted_keys(&self) -> &HashMap<String, GPGKeyInfo> {
        &self.trusted_keys
    }

    pub fn get_keyring_path(&self) -> &PathBuf {
        &self.keyring_path
    }

    pub fn get_config(&self) -> &GPGConfig {
        &self.config
    }
} 