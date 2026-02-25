
use crate::errors::CryptoError;
use zeroize::Zeroize;
use crate::api::symmetric::SymKey;

pub fn import_symmetric(data: &[u8]) -> Result<SymKey, CryptoError> { Ok(SymKey { opaque: data.to_vec() }) }

pub fn delete_symmetric(key: &mut SymKey) -> Result<(), CryptoError> { key.opaque.zeroize(); Ok(()) }

pub fn import_private_key(data: &[u8]) -> Result<Vec<u8>, CryptoError> { Ok(data.to_vec()) }

pub fn delete_private_key(key: &mut Vec<u8>) -> Result<(), CryptoError> { key.zeroize(); Ok(()) }
