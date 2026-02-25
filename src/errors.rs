
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid parameter: {0}")] InvalidParam(&'static str),
    #[error("Unsupported algorithm: {0}")] UnsupportedAlgorithm(&'static str),
    #[error("Key handling error")] KeyError,
    #[error("Encryption failed")] EncryptionError,
    #[error("Decryption failed")] DecryptionError,
    #[error("Signature error")] SignatureError,
    #[error("Verification failed")] VerifyError,
    #[error("Random generation failed")] RandomError,
    #[error("General provider error: {0}")] ProviderError(&'static str),
}
