use std::fmt;
use std::hash::{Hash, Hasher};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{AeadCore, NewAead};
use rand::Rng;
use rsa::{
    PaddingScheme, PublicKey as _, PublicKeyEncoding, PublicKeyParts, RSAPrivateKey, RSAPublicKey,
};
use sha2::Digest;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use typenum::Unsigned;

use super::types::*;
use crate::proto::hashable::Hashable;
use rand::rngs::OsRng;

type AesGcm = aes_gcm::Aes256Gcm;
pub(super) type AesNonceSize = <AesGcm as AeadCore>::NonceSize;
pub(super) type AesNonce = aes_gcm::Nonce<AesNonceSize>;
pub(super) type AesKeySize = <AesGcm as NewAead>::KeySize;
pub(super) type AesKey = aes_gcm::Key<AesKeySize>;

const MAX_NONCE: u128 = (1 << 97) - 1;

#[cfg(not(test))]
const RSA_BIT_SIZE: usize = 4096;
#[cfg(test)]
const RSA_BIT_SIZE: usize = 256; // Smaller size for tests

/// Enclave master key used for attestation
///
/// We mock it as local attestation is not implemented yet
#[derive(Serialize, Deserialize)]
pub struct MockedEnclaveMasterKey {
    sk: RSAPrivateKey,
}

impl MockedEnclaveMasterKey {
    pub fn random<R: Rng>(rng: &mut R) -> rsa::errors::Result<Self> {
        let sk = RSAPrivateKey::new(rng, RSA_BIT_SIZE)?;
        Ok(Self { sk })
    }

    pub fn sign<H: Hashable>(&self, response: &H) -> rsa::errors::Result<AttestationSignature> {
        let hashed = response.hash::<sha2::Sha256>();
        self.sk
            .sign(
                rsa::padding::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::hash::Hash::SHA2_256),
                },
                &hashed,
            )
            .map(|bytes| AttestationSignature { bytes })
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        self.sk.decrypt(PaddingScheme::PKCS1v15Encrypt, ciphertext)
    }

    pub fn public_key(&self) -> MockedEnclavePublicMasterKey {
        MockedEnclavePublicMasterKey {
            pk: self.sk.to_public_key(),
        }
    }
}

impl fmt::Debug for MockedEnclaveMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MockedEnclaveMasterKey")
            .field("key", &"[hidden]")
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MockedEnclavePublicMasterKey {
    pk: RSAPublicKey,
}

impl MockedEnclavePublicMasterKey {
    pub fn verify<H: Hashable>(&self, response: &H, signature: &AttestationSignature) -> bool {
        let hashed = response.hash::<sha2::Sha256>();
        self.pk
            .verify(
                rsa::padding::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::hash::Hash::SHA2_256),
                },
                &hashed,
                &signature.bytes,
            )
            .is_ok()
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> rsa::errors::Result<Vec<u8>> {
        self.pk
            .encrypt(&mut OsRng, PaddingScheme::PKCS1v15Encrypt, plaintext)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SgxKey {
    #[serde(with = "super::serde::aes_key")]
    key: AesKey,
    next_nonce: Option<u128>,
}

impl SgxKey {
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let mut private_key = [0u8; AesKeySize::USIZE];
        private_key.iter_mut().for_each(|x| *x = rng.gen());
        Self {
            key: AesKey::from_slice(&private_key).clone(),
            next_nonce: Some(0),
        }
    }

    pub fn cipher(&mut self) -> SgxCipher {
        SgxCipher {
            cipher: AesGcm::new(&self.key),
            next_nonce: &mut self.next_nonce,
        }
    }
}

impl fmt::Debug for SgxKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SgxKey")
            .field("key", &"[hidden]")
            .field("next_nonce", &self.next_nonce)
            .finish()
    }
}

pub struct SgxCipher<'k> {
    cipher: AesGcm,
    next_nonce: &'k mut Option<u128>,
}

impl<'k> SgxCipher<'k> {
    pub fn seal(
        &mut self,
        pk: &ReceiverEncryptionKey,
        j: u16,
        location: Location,
    ) -> Result<SealedLocation, SealError> {
        let mut buffer = location.bytes;
        let nonce = self.seal_buffer(pk, j, &mut buffer)?;
        Ok(SealedLocation {
            ciphertext: buffer,
            nonce,
        })
    }

    fn seal_buffer(
        &mut self,
        pk: &ReceiverEncryptionKey,
        j: u16,
        buffer: &mut Vec<u8>,
    ) -> Result<AesNonce, SealError> {
        let nonce = self.issue_nonce().ok_or(SealError::NonceOverflow)?;
        let mut ad = vec![];
        ad.extend_from_slice(&pk.pk.n().to_bytes_be());
        ad.extend_from_slice(&pk.pk.e().to_bytes_be());
        ad.extend_from_slice(&j.to_be_bytes());
        self.cipher
            .encrypt_in_place(&nonce, &ad, buffer)
            .map_err(|_| SealError::Encrypt)?;
        Ok(nonce)
    }

    pub fn rerandomize(
        &mut self,
        pk: &ReceiverEncryptionKey,
        j: u16,
        location: &mut SealedLocation,
    ) -> Result<(), RerandomizeError> {
        let buffer = &mut location.ciphertext;
        let nonce = &mut location.nonce;

        self.open(pk, j, nonce, buffer)
            .map_err(RerandomizeError::Open)?;
        *nonce = self
            .seal_buffer(pk, j, buffer)
            .map_err(RerandomizeError::Seal)?;
        Ok(())
    }

    pub fn open_to_receiver<R: Rng>(
        &self,
        rng: &mut R,
        pk: &ReceiverEncryptionKey,
        j: u16,
        location: SealedLocation,
    ) -> Result<ReceiverEncryptedLocation, OpenToReceiverError> {
        let mut buffer = location.ciphertext;
        self.open(pk, j, &location.nonce, &mut buffer)
            .map_err(OpenToReceiverError::Open)?;
        let encrypted_location = pk
            .encrypt(rng, Location::new(buffer))
            .map_err(OpenToReceiverError::Encrypt)?;
        Ok(encrypted_location)
    }

    fn issue_nonce(&mut self) -> Option<AesNonce> {
        let nonce = *self.next_nonce.as_ref()?;
        *self.next_nonce = self.next_nonce.and_then(|n| n.checked_add(1));

        assert!(nonce <= MAX_NONCE);

        let nonce_bytes = nonce.to_be_bytes();
        let mut truncated_nonce = [0u8; AesNonceSize::USIZE];
        truncated_nonce.copy_from_slice(&nonce_bytes[4..]);

        Some(AesNonce::from(truncated_nonce))
    }

    fn open(
        &self,
        pk: &ReceiverEncryptionKey,
        j: u16,
        nonce: &AesNonce,
        buffer: &mut Vec<u8>,
    ) -> Result<(), OpenError> {
        let mut ad = vec![];
        ad.extend_from_slice(&pk.pk.n().to_bytes_be());
        ad.extend_from_slice(&pk.pk.e().to_bytes_be());
        ad.extend_from_slice(&j.to_be_bytes());
        self.cipher
            .decrypt_in_place(&nonce, &ad, buffer)
            .map_err(|_| OpenError::UnauthenticCiphertext)?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum SealError {
    #[error("nonce overflow")]
    NonceOverflow,
    #[error("can't encrypt")]
    Encrypt,
}

#[derive(Debug, Error)]
pub enum OpenError {
    #[error("unauthentic ciphertext")]
    UnauthenticCiphertext,
}

#[derive(Debug, Error)]
pub enum RerandomizeError {
    #[error("{0}")]
    Open(OpenError),
    #[error("{0}")]
    Seal(SealError),
}

#[derive(Debug, Error)]
pub enum OpenToReceiverError {
    #[error("decrypt AES: {0}")]
    Open(OpenError),
    #[error("encrypt RSA: {0}")]
    Encrypt(rsa::errors::Error),
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct ReceiverDecryptionKey {
    sk: RSAPrivateKey,
}

impl ReceiverDecryptionKey {
    const SUFFIX_SIZE: usize = 32;

    pub fn random<R: Rng>(rng: &mut R) -> rsa::errors::Result<Self> {
        let sk = RSAPrivateKey::new(rng, RSA_BIT_SIZE)?;
        Ok(Self { sk })
    }

    pub fn encryption_key(&self) -> ReceiverEncryptionKey {
        ReceiverEncryptionKey {
            pk: self.sk.to_public_key(),
        }
    }

    pub fn decrypt(
        &self,
        location: &ReceiverEncryptedLocation,
    ) -> Result<Location, ReceiverDecryptError> {
        let mut plaintext = self
            .sk
            .decrypt(
                rsa::padding::PaddingScheme::OAEP {
                    digest: Box::new(sha2::Sha256::default()),
                    label: None,
                },
                &location.ciphertext,
            )
            .map_err(ReceiverDecryptError::Decryption)?;
        if !plaintext.ends_with(&[0u8; Self::SUFFIX_SIZE]) {
            return Err(ReceiverDecryptError::CiphertextDoesntCorrespondToThisKey);
        }
        plaintext.truncate(plaintext.len() - Self::SUFFIX_SIZE);
        Ok(Location::new(plaintext))
    }
}

impl fmt::Debug for ReceiverDecryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ReceiverDecryptionKey")
            .field("key", &"[hidden]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum ReceiverDecryptError {
    #[error("decrypt: {0}")]
    Decryption(rsa::errors::Error),
    #[error("ciphertext doesn't correspond to the decryption key")]
    CiphertextDoesntCorrespondToThisKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceiverEncryptionKey {
    pk: RSAPublicKey,
}

impl ReceiverEncryptionKey {
    pub fn encrypt<R: Rng>(
        &self,
        rng: &mut R,
        location: Location,
    ) -> rsa::errors::Result<ReceiverEncryptedLocation> {
        let mut plaintext = location.bytes;
        plaintext.extend_from_slice(&[0u8; ReceiverDecryptionKey::SUFFIX_SIZE]);

        let ciphertext = self.pk.encrypt(
            rng,
            rsa::padding::PaddingScheme::OAEP {
                digest: Box::new(sha2::Sha256::default()),
                label: None,
            },
            &plaintext,
        )?;
        Ok(ReceiverEncryptedLocation { ciphertext })
    }

    pub fn to_pkcs8(&self) -> rsa::errors::Result<String> {
        Ok(base64::encode(self.pk.to_pkcs8()?))
    }
    pub fn from_pkcs8(encoded: &str) -> rsa::errors::Result<Self> {
        Ok(Self {
            pk: RSAPublicKey::from_pkcs8(&base64::decode(encoded).map_err(|_| {
                rsa::errors::Error::ParseError {
                    reason: "invalid base64 encoded string".to_string(),
                }
            })?)?,
        })
    }
}

impl Hash for ReceiverEncryptionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.pk.e().hash(state);
        self.pk.n().hash(state);
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerificationPrivateKey {
    sk: RSAPrivateKey,
}

impl VerificationPrivateKey {
    pub fn random<R: Rng>(rng: &mut R) -> rsa::errors::Result<Self> {
        let sk = RSAPrivateKey::new(rng, RSA_BIT_SIZE)?;
        Ok(VerificationPrivateKey { sk })
    }

    pub fn sign(&self, ctr: u64) -> rsa::errors::Result<VerificationSignature> {
        let hashed = sha2::Sha256::digest(&ctr.to_be_bytes());
        let signature = self.sk.sign(
            rsa::padding::PaddingScheme::PKCS1v15Sign {
                hash: Some(rsa::hash::Hash::SHA2_256),
            },
            &hashed,
        )?;
        Ok(VerificationSignature { bytes: signature })
    }

    pub fn public_key(&self) -> VerificationPublicKey {
        VerificationPublicKey {
            pk: self.sk.to_public_key(),
        }
    }
}

impl fmt::Debug for VerificationPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("VerificationPrivateKey")
            .field("key", &"[hidden]")
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct VerificationPublicKey {
    pk: RSAPublicKey,
}

impl VerificationPublicKey {
    pub fn verify(&self, ctr: u64, signature: &VerificationSignature) -> bool {
        let hashed = sha2::Sha256::digest(&ctr.to_be_bytes());
        self.pk
            .verify(
                rsa::padding::PaddingScheme::PKCS1v15Sign {
                    hash: Some(rsa::hash::Hash::SHA2_256),
                },
                &hashed,
                &signature.bytes,
            )
            .is_ok()
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub struct ClientKeysBundle {
    pub pk: ReceiverEncryptionKey,
    pub vk: VerificationPublicKey,
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::secp256_k1::GE;
    use rand::rngs::OsRng;

    use super::*;
    use crate::proto::pps::SetupResponse;

    lazy_static::lazy_static! {
        static ref RECEIVER_DECRYPTION_KEY: ReceiverDecryptionKey =
            serde_json::from_slice(include_bytes!("../../testdata/receiver_decryption_key.json")).unwrap();
        static ref VERIFICATION_PRIVATE_KEY: VerificationPrivateKey =
            serde_json::from_slice(include_bytes!("../../testdata/verification_private_key.json")).unwrap();
        static ref MOCKED_MASTER_KEY: MockedEnclaveMasterKey =
            serde_json::from_slice(include_bytes!("../../testdata/attestation_private_key.json")).unwrap();
    }

    #[test]
    fn generate_receiver_decryption_key() {
        let sk = ReceiverDecryptionKey::random(&mut OsRng).unwrap();
        println!("Private key: {}", serde_json::to_string(&sk).unwrap());
    }

    #[test]
    fn generate_verifier_key() {
        let sk = VerificationPrivateKey::random(&mut OsRng).unwrap();
        println!("Private key: {}", serde_json::to_string(&sk).unwrap());
    }

    #[test]
    fn generate_attestation_key() {
        let sk = MockedEnclaveMasterKey::random(&mut OsRng).unwrap();
        println!("Private key: {}", serde_json::to_string(&sk).unwrap());
    }

    #[test]
    fn generate_sgx_key() {
        let sk = SgxKey::random(&mut OsRng);
        println!("Private key: {}", serde_json::to_string(&sk).unwrap());
    }

    #[test]
    fn encrypt_decrypt_location() {
        let plaintext = Location::new(b"secret place".to_vec());
        let sk = &RECEIVER_DECRYPTION_KEY;
        let pk = sk.encryption_key();
        let ciphertext = pk.encrypt(&mut OsRng, plaintext.clone()).unwrap();
        let decrypted = sk.decrypt(&ciphertext).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn sign_and_verify_crt() {
        let crt = 1;

        let sk = &VERIFICATION_PRIVATE_KEY;
        let signature = sk.sign(crt).unwrap();

        let pk = sk.public_key();
        assert!(pk.verify(crt, &signature))
    }

    #[test]
    fn sign_and_verify_different_crt() {
        let crt = 1;

        let sk = &VERIFICATION_PRIVATE_KEY;
        let signature = sk.sign(crt).unwrap();

        let pk = sk.public_key();
        assert!(!pk.verify(crt + 1, &signature))
    }

    #[test]
    fn sign_and_verify_attestation() {
        let msg = SetupResponse {
            public_key: b"hello attestation".to_vec(),
        };

        let sk = &MOCKED_MASTER_KEY;
        let signature = sk.sign(&msg).unwrap();

        let pk = sk.public_key();
        assert!(pk.verify(&msg, &signature))
    }

    #[test]
    fn sign_and_verify_different_attestation() {
        let msg1 = SetupResponse {
            public_key: b"hello attestation".to_vec(),
        };
        let msg2 = SetupResponse {
            public_key: b"hello, attestation!".to_vec(),
        };

        let sk = &MOCKED_MASTER_KEY;
        let signature = sk.sign(&msg1).unwrap();

        let pk = sk.public_key();
        assert!(!pk.verify(&msg2, &signature))
    }

    #[test]
    fn sgx_cipher_location_seal_open_decrypt() {
        let location = Location::new(b"secret place".to_vec());
        let receiver_sk = &RECEIVER_DECRYPTION_KEY;
        let receiver_pk = receiver_sk.encryption_key();

        let mut sgx_key = SgxKey::random(&mut OsRng);
        let mut sgx_cipher = sgx_key.cipher();

        let ciphertext = sgx_cipher.seal(1, location.clone()).unwrap();
        let ciphertext2 = sgx_cipher
            .open_to_receiver(&mut OsRng, 1, ciphertext, &receiver_pk)
            .unwrap();
        let plaintext = receiver_sk.decrypt(&ciphertext2).unwrap();

        assert_eq!(location, plaintext);
    }

    #[test]
    fn sgx_cipher_requires_j_to_be_the_same() {
        let location = Location::new(b"secret place".to_vec());
        let receiver_sk = &RECEIVER_DECRYPTION_KEY;
        let receiver_pk = receiver_sk.encryption_key();

        let mut sgx_key = SgxKey::random(&mut OsRng);
        let mut sgx_cipher = sgx_key.cipher();

        let ciphertext = sgx_cipher.seal(1, location.clone()).unwrap();
        let result = sgx_cipher.open_to_receiver(&mut OsRng, 2, ciphertext, &receiver_pk);

        assert!(result.is_err());
    }

    #[test]
    fn sgx_cipher_produces_different_ciphertext_for_the_same_plaintext() {
        let location = Location::new(b"secret place".to_vec());

        let mut sgx_key = SgxKey::random(&mut OsRng);
        let mut sgx_cipher = sgx_key.cipher();

        let ciphertext1 = sgx_cipher.seal(1, location.clone()).unwrap();
        let ciphertext2 = sgx_cipher.seal(1, location.clone()).unwrap();

        let ciphertext1_serialized = serde_json::to_string(&ciphertext1).unwrap();
        let ciphertext2_serialized = serde_json::to_string(&ciphertext2).unwrap();

        assert_ne!(ciphertext1_serialized, ciphertext2_serialized)
    }
}
