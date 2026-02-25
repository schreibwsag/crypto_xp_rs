
use crate::errors::CryptoError;
use crate::api::provider::{AlgorithmId, AES_CBC, AES_GCM, AES_CCM, CHACHA20_POLY1305};

use aes::Aes256;
use aes::cipher::BlockSizeUser;
use aes_gcm::Aes256Gcm;
use cbc::{Encryptor as CbcEnc, Decryptor as CbcDec};
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7, BlockEncryptMut, BlockDecryptMut};
use chacha20poly1305::ChaCha20Poly1305;
use ccm::aead::{Aead, KeyInit};
use ccm::consts::{U16, U13};
use ccm::Ccm;
// use aes_gcm::aead::Aead as _;
// use chacha20poly1305::aead::Aead as _;

// CCM type: AES-256, 16-byte tag, 13-byte nonce
// Ensure you pass 13-byte IV for AES-CCM

type AesCcm = Ccm<Aes256, U16, U13>;

pub fn encrypt(alg: AlgorithmId, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match alg {
        a if a == AES_CBC => {
            if key.len() != 32 || iv.len() != 16 { return Err(CryptoError::InvalidParam("AES-CBC requires 32-byte key and 16-byte IV")); }
            let cipher = CbcEnc::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| CryptoError::EncryptionError)?;
            let mut buf = plaintext.to_vec();
            let pos = buf.len();
            // allocate extra block for padding
            buf.resize(pos + Aes256::block_size(), 0u8);
            let ct = cipher
                .encrypt_padded_mut::<Pkcs7>(&mut buf, pos)
                .map_err(|_| CryptoError::EncryptionError)?;
            Ok(ct.to_vec())
        }
        a if a == AES_GCM => {
            if key.len() != 32 || iv.len() != 12 { return Err(CryptoError::InvalidParam("AES-GCM requires 32-byte key and 12-byte nonce")); }
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::EncryptionError)?;
            cipher.encrypt(iv.into(), plaintext).map_err(|_| CryptoError::EncryptionError)
        }
        a if a == AES_CCM => {
            if key.len() != 32 || iv.len() != 13 { return Err(CryptoError::InvalidParam("AES-CCM requires 32-byte key and 13-byte nonce")); }
            let cipher = AesCcm::new_from_slice(key).map_err(|_| CryptoError::EncryptionError)?;
            cipher.encrypt(iv.into(), plaintext).map_err(|_| CryptoError::EncryptionError)
        }
        a if a == CHACHA20_POLY1305 => {
            if key.len() != 32 || iv.len() != 12 { return Err(CryptoError::InvalidParam("ChaCha20-Poly1305 requires 32-byte key and 12-byte nonce")); }
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::EncryptionError)?;
            cipher.encrypt(iv.into(), plaintext).map_err(|_| CryptoError::EncryptionError)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm("symmetric.encrypt")),
    }
}

pub fn decrypt(alg: AlgorithmId, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match alg {
        a if a == AES_CBC => {
            if key.len() != 32 || iv.len() != 16 { return Err(CryptoError::InvalidParam("AES-CBC requires 32-byte key and 16-byte IV")); }
            let cipher = CbcDec::<Aes256>::new_from_slices(key, iv)
                .map_err(|_| CryptoError::DecryptionError)?;
            let mut buf = ciphertext.to_vec();
            let pt = cipher
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| CryptoError::DecryptionError)?;
            Ok(pt.to_vec())
        }
        a if a == AES_GCM => {
            if key.len() != 32 || iv.len() != 12 { return Err(CryptoError::InvalidParam("AES-GCM requires 32-byte key and 12-byte nonce")); }
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::DecryptionError)?;
            cipher.decrypt(iv.into(), ciphertext).map_err(|_| CryptoError::DecryptionError)
        }
        a if a == AES_CCM => {
            if key.len() != 32 || iv.len() != 13 { return Err(CryptoError::InvalidParam("AES-CCM requires 32-byte key and 13-byte nonce")); }
            let cipher = AesCcm::new_from_slice(key).map_err(|_| CryptoError::DecryptionError)?;
            cipher.decrypt(iv.into(), ciphertext).map_err(|_| CryptoError::DecryptionError)
        }
        a if a == CHACHA20_POLY1305 => {
            if key.len() != 32 || iv.len() != 12 { return Err(CryptoError::InvalidParam("ChaCha20-Poly1305 requires 32-byte key and 12-byte nonce")); }
            let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::DecryptionError)?;
            cipher.decrypt(iv.into(), ciphertext).map_err(|_| CryptoError::DecryptionError)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm("symmetric.decrypt")),
    }
}
