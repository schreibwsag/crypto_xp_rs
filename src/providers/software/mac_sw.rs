
use crate::errors::CryptoError;
use crate::api::provider::{AlgorithmId, HMAC_SHA256, HMAC_SHA512};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub fn mac(alg: AlgorithmId, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    match alg {
        a if a == HMAC_SHA256 => {
            let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::ProviderError("hmac key"))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        a if a == HMAC_SHA512 => {
            let mut mac = HmacSha512::new_from_slice(key).map_err(|_| CryptoError::ProviderError("hmac key"))?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(CryptoError::UnsupportedAlgorithm("mac")),
    }
}

pub fn mac_verify(alg: AlgorithmId, key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool, CryptoError> {
    match alg {
        a if a == HMAC_SHA256 => {
            let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CryptoError::ProviderError("hmac key"))?;
            mac.update(data);
            Ok(mac.verify_slice(tag).is_ok())
        }
        a if a == HMAC_SHA512 => {
            let mut mac = HmacSha512::new_from_slice(key).map_err(|_| CryptoError::ProviderError("hmac key"))?;
            mac.update(data);
            Ok(mac.verify_slice(tag).is_ok())
        }
        _ => Err(CryptoError::UnsupportedAlgorithm("mac_verify")),
    }
}
