pub mod aes_key {
    use std::fmt;

    use serde::de::{Error, Unexpected, Visitor};
    use serde::{Deserializer, Serializer};
    use typenum::Unsigned;

    use crate::crypto::keys::{AesKey, AesKeySize};

    pub fn serialize<S>(private_key: &AesKey, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&base64::encode(private_key.as_slice()))
    }

    pub fn deserialize<'de, D>(d: D) -> Result<AesKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = AesKey;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "base64 encoded private key")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let bytes = base64::decode(v)
                    .map_err(|_e| E::invalid_value(Unexpected::Str(v), &"base64 encoded bytes"))?;
                if bytes.len() != AesKeySize::USIZE {
                    return Err(E::invalid_length(
                        bytes.len(),
                        &AesKeySize::USIZE.to_string().as_str(),
                    ));
                }
                Ok(AesKey::from_slice(&bytes).clone())
            }
        }

        d.deserialize_str(V)
    }
}
