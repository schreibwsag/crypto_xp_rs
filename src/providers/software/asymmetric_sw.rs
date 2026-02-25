
use crate::errors::CryptoError;
use crate::api::provider::{AlgorithmId, ECDH_P256, ECDSA_P256};
use crate::api::asymmetric::AsymKeyPair;
use p256::{PublicKey, SecretKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::ecdsa::SigningKey;
use p256::ecdh::diffie_hellman;
use rand_core::OsRng;

pub fn generate_keypair(alg: AlgorithmId) -> Result<AsymKeyPair, CryptoError> {
    match alg {
        a if a == ECDH_P256 => {
            let sk = SecretKey::random(&mut OsRng);
            let pk = sk.public_key();
            let priv_bytes = sk.to_bytes().to_vec();
            let pub_bytes = pk.to_encoded_point(false).as_bytes().to_vec();
            Ok(AsymKeyPair { private: priv_bytes, public: pub_bytes })
        }
        a if a == ECDSA_P256 => {
            let sk = SigningKey::random(&mut OsRng);
            let vk = sk.verifying_key();
            let priv_bytes = sk.to_bytes().to_vec();
            let pub_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            Ok(AsymKeyPair { private: priv_bytes, public: pub_bytes })
        }
        _ => Err(CryptoError::UnsupportedAlgorithm("generate_keypair")),
    }
}

pub fn ecdh(alg: AlgorithmId, private_key: &[u8], peer_public: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if alg != ECDH_P256 { return Err(CryptoError::UnsupportedAlgorithm("ecdh")); }
    let sk = SecretKey::from_slice(private_key).map_err(|_| CryptoError::KeyError)?;
    let pk = PublicKey::from_sec1_bytes(peer_public).map_err(|_| CryptoError::KeyError)?;
    let ss = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    Ok(ss.raw_secret_bytes().to_vec())
}
