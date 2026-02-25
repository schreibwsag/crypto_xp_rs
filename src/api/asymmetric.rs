use crate::errors::CryptoError; use crate::api::provider::AlgorithmId;
#[derive(Clone,Debug)] pub struct AsymKeyPair{pub private:Vec<u8>,pub public:Vec<u8>} 
pub trait AsymmetricCrypto{fn generate_keypair(&self,alg:AlgorithmId)->Result<AsymKeyPair,CryptoError>; fn ecdh(&self,alg:AlgorithmId,sk:&[u8],pk:&[u8])->Result<Vec<u8>,CryptoError>;}