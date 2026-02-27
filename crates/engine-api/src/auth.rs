use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("JWT encoding error: {0}")]
    Encode(#[from] jsonwebtoken::errors::Error),
    #[error("invalid secret: {0}")]
    InvalidSecret(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// JWT claims for Engine API authentication.
/// Only `iat` (issued at) is required per the Engine API spec.
#[derive(Debug, Serialize)]
struct Claims {
    iat: i64,
}

/// Create a JWT token for Engine API authentication.
///
/// The token uses HS256 with the shared secret and contains only
/// an `iat` claim set to the current Unix timestamp.
pub fn create_token(secret: &[u8]) -> Result<String, AuthError> {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims { iat: now };
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret);
    Ok(encode(&header, &claims, &key)?)
}

/// Load a JWT secret from a hex-encoded file.
///
/// The file should contain 32 bytes encoded as 64 hex characters,
/// optionally prefixed with "0x".
pub fn load_secret(path: &Path) -> Result<Vec<u8>, AuthError> {
    let content = std::fs::read_to_string(path)?;
    let hex_str = content.trim().strip_prefix("0x").unwrap_or(content.trim());

    let bytes = hex::decode(hex_str).map_err(|e| AuthError::InvalidSecret(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(AuthError::InvalidSecret(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn create_valid_token() {
        let secret = [0x42u8; 32];
        let token = create_token(&secret).unwrap();
        assert!(!token.is_empty());
        // JWT has 3 parts separated by dots.
        assert_eq!(token.split('.').count(), 3);
    }

    #[test]
    fn load_secret_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt.hex");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "0x{}", hex::encode([0xABu8; 32])).unwrap();

        let secret = load_secret(&path).unwrap();
        assert_eq!(secret, vec![0xABu8; 32]);
    }

    #[test]
    fn load_secret_without_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt.hex");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", hex::encode([0xCDu8; 32])).unwrap();

        let secret = load_secret(&path).unwrap();
        assert_eq!(secret, vec![0xCDu8; 32]);
    }

    #[test]
    fn load_secret_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jwt.hex");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "{}", hex::encode([0xAAu8; 16])).unwrap();

        let result = load_secret(&path);
        assert!(result.is_err());
    }
}
