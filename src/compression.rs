use crate::error::PackerResult;
use async_compression::tokio::bufread::{GzipDecoder, XzDecoder, ZstdDecoder};
use log::{debug, info};
use std::path::Path;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionFormat {
    Gzip,
    Xz,
    Zstd,
    Brotli,
    None,
}

impl CompressionFormat {
    pub fn from_path(path: &Path) -> Self {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            match ext.to_lowercase().as_str() {
                "gz" | "gzip" => Self::Gzip,
                "xz" => Self::Xz,
                "zst" | "zstd" => Self::Zstd,
                "br" => Self::Brotli,
                _ => Self::None,
            }
        } else {
            Self::None
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Gzip => "gz",
            Self::Xz => "xz",
            Self::Zstd => "zst",
            Self::Brotli => "br",
            Self::None => "",
        }
    }

    pub fn compression_ratio(&self) -> f32 {
        match self {
            Self::Gzip => 0.6,
            Self::Xz => 0.4,      // better compression
            Self::Zstd => 0.45,   // good balance of speed/ratio
            Self::Brotli => 0.35, // best compression but slower
            Self::None => 1.0,
        }
    }

    pub fn speed_score(&self) -> u8 {
        match self {
            Self::Gzip => 8,
            Self::Xz => 3,     // slow but good compression
            Self::Zstd => 9,   // very fast
            Self::Brotli => 4, // slower
            Self::None => 10,
        }
    }
}

pub struct CompressionManager {
    preferred_format: CompressionFormat,
    compression_level: u8,
}

impl CompressionManager {
    pub fn new() -> Self {
        Self {
            preferred_format: CompressionFormat::Zstd, // fast and good compression
            compression_level: 6,                      // balanced level
        }
    }

    pub fn with_format(mut self, format: CompressionFormat) -> Self {
        self.preferred_format = format;
        self
    }

    pub fn with_level(mut self, level: u8) -> Self {
        self.compression_level = level;
        self
    }

    pub async fn decompress_file(
        &self,
        input_path: &Path,
        output_path: &Path,
    ) -> PackerResult<u64> {
        info!(
            "Decompressing {} to {}",
            input_path.display(),
            output_path.display()
        );

        let format = CompressionFormat::from_path(input_path);
        let input_file = File::open(input_path).await?;
        let reader = BufReader::new(input_file);

        let mut output_file = File::create(output_path).await?;
        let mut bytes_written = 0u64;

        match format {
            CompressionFormat::Gzip => {
                let mut decoder = GzipDecoder::new(reader);
                let mut buffer = [0u8; 8192];
                loop {
                    let n = decoder.read(&mut buffer).await?;
                    if n == 0 {
                        break;
                    }
                    output_file.write_all(&buffer[..n]).await?;
                    bytes_written += n as u64;
                }
            }
            CompressionFormat::Xz => {
                let mut decoder = XzDecoder::new(reader);
                let mut buffer = [0u8; 8192];
                loop {
                    let n = decoder.read(&mut buffer).await?;
                    if n == 0 {
                        break;
                    }
                    output_file.write_all(&buffer[..n]).await?;
                    bytes_written += n as u64;
                }
            }
            CompressionFormat::Zstd => {
                let mut decoder = ZstdDecoder::new(reader);
                let mut buffer = [0u8; 8192];
                loop {
                    let n = decoder.read(&mut buffer).await?;
                    if n == 0 {
                        break;
                    }
                    output_file.write_all(&buffer[..n]).await?;
                    bytes_written += n as u64;
                }
            }
            CompressionFormat::Brotli => {
                // brotli support would need additional dependency
                return Err(crate::error::PackerError::CompressionError(
                    "Brotli decompression not implemented yet".to_string(),
                ));
            }
            CompressionFormat::None => {
                // just copy the file
                tokio::fs::copy(input_path, output_path).await?;
                let metadata = tokio::fs::metadata(output_path).await?;
                bytes_written = metadata.len();
            }
        }

        output_file.flush().await?;
        debug!("Decompression complete: {} bytes written", bytes_written);
        Ok(bytes_written)
    }

    pub fn choose_best_format(&self, file_size: u64, speed_priority: bool) -> CompressionFormat {
        if speed_priority {
            // prioritize speed
            if file_size > 100_000_000 {
                // 100MB+
                CompressionFormat::Zstd
            } else {
                CompressionFormat::Gzip
            }
        } else {
            // prioritize compression ratio
            if file_size > 500_000_000 {
                // 500MB+
                CompressionFormat::Xz
            } else if file_size > 50_000_000 {
                // 50MB+
                CompressionFormat::Zstd
            } else {
                CompressionFormat::Brotli
            }
        }
    }

    pub fn estimate_compressed_size(&self, original_size: u64, format: CompressionFormat) -> u64 {
        (original_size as f32 * format.compression_ratio()) as u64
    }
}

impl Default for CompressionManager {
    fn default() -> Self {
        Self::new()
    }
}

// package delta support for efficient updates
#[derive(Debug, Clone)]
pub struct PackageDelta {
    pub from_version: String,
    pub to_version: String,
    pub delta_url: String,
    pub delta_size: u64,
    pub delta_checksum: String,
}

impl PackageDelta {
    pub fn new(from: String, to: String, url: String, size: u64, checksum: String) -> Self {
        Self {
            from_version: from,
            to_version: to,
            delta_url: url,
            delta_size: size,
            delta_checksum: checksum,
        }
    }

    pub fn is_applicable(&self, current_version: &str, target_version: &str) -> bool {
        self.from_version == current_version && self.to_version == target_version
    }

    pub fn size_savings(&self, full_package_size: u64) -> u64 {
        if full_package_size > self.delta_size {
            full_package_size - self.delta_size
        } else {
            0
        }
    }
}

pub struct DeltaManager {
    deltas: Vec<PackageDelta>,
}

impl DeltaManager {
    pub fn new() -> Self {
        Self { deltas: Vec::new() }
    }

    pub fn add_delta(&mut self, delta: PackageDelta) {
        self.deltas.push(delta);
    }

    pub fn find_best_delta(
        &self,
        _package_name: &str,
        from: &str,
        to: &str,
    ) -> Option<&PackageDelta> {
        self.deltas
            .iter()
            .find(|delta| delta.is_applicable(from, to))
    }

    pub fn calculate_savings(
        &self,
        package_name: &str,
        from: &str,
        to: &str,
        full_size: u64,
    ) -> u64 {
        if let Some(delta) = self.find_best_delta(package_name, from, to) {
            delta.size_savings(full_size)
        } else {
            0
        }
    }
}

impl Default for DeltaManager {
    fn default() -> Self {
        Self::new()
    }
}
