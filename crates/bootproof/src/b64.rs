//! Base64 newtype so `Vec<u8>` fields serialize as b64 strings in the Bundle.

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serializer};

/// Base64-encoded byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct B64(pub Vec<u8>);

impl B64 {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for B64 {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<B64> for Vec<u8> {
    fn from(b: B64) -> Self {
        b.0
    }
}

impl AsRef<[u8]> for B64 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl serde::Serialize for B64 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let s = base64::engine::general_purpose::STANDARD.encode(&self.0);
        ser.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        let v = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(v))
    }
}
