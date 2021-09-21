use std::fmt;

use serde::de::{Error, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use typenum::Unsigned;

use crate::crypto::keys::{AesNonce, AesNonceSize};
use crate::crypto::ReceiverEncryptionKey;

/// Plain location, not encrypted
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct Location {
    pub(super) bytes: Vec<u8>,
}

impl Location {
    pub fn new(location: Vec<u8>) -> Self {
        Self { bytes: location }
    }
}

impl AsRef<[u8]> for Location {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Location encrypted using party public key
#[derive(Debug)]
pub struct ReceiverEncryptedLocation {
    pub ciphertext: Vec<u8>,
}

/// Location encrypted using SGXKey
#[derive(Debug, Clone)]
pub struct SealedLocation {
    pub(super) ciphertext: Vec<u8>,
    pub(super) nonce: AesNonce,
}

impl Serialize for SealedLocation {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = self.ciphertext.clone();
        bytes.extend_from_slice(&self.nonce);
        s.serialize_str(&base64::encode(&bytes))
    }
}

impl<'de> Deserialize<'de> for SealedLocation {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = SealedLocation;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "encrypted location")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let bytes =
                    base64::decode(v).map_err(|_e| E::custom("invalid base64 encoded string"))?;
                if bytes.len() < AesNonceSize::USIZE {
                    return Err(E::invalid_length(
                        v.len(),
                        &format!("at least {}", AesNonceSize::USIZE).as_str(),
                    ));
                }

                let ciphertext = bytes[..bytes.len() - AesNonceSize::USIZE].to_vec();
                let nonce =
                    AesNonce::from_slice(&bytes[bytes.len() - AesNonceSize::USIZE..]).clone();

                Ok(SealedLocation { ciphertext, nonce })
            }
        }

        d.deserialize_str(V)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationSignature {
    pub bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationSignature {
    pub(super) bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignalPlaintext {
    pub recipient: ReceiverEncryptionKey,
    pub signal: Location,
}
