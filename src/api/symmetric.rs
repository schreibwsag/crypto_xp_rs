use crate::errors::CryptoError; use crate::api::provider::AlgorithmId;
#[derive(Clone, Debug)]
pub struct SymKey {
    pub(crate) opaque: Vec<u8>,
}
pub trait SymmetricCrypto{fn encrypt(&self,alg:AlgorithmId,key:&SymKey,iv:&[u8],pt:&[u8])->Result<Vec<u8>,CryptoError>; fn decrypt(&self,alg:AlgorithmId,key:&SymKey,iv:&[u8],ct:&[u8])->Result<Vec<u8>,CryptoError>;}
