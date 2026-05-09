use std::{collections::BTreeMap, str::FromStr};

use pubkegaard_types::{DiscoveryDocument, PubkyId, ValidationError};
use url::Url;

pub const POINTER_VERSION: &str = "pkg1";
pub const POINTER_OWNER: &str = "_pubkegaard";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DiscoveryError {
    #[error("missing pointer field: {0}")]
    MissingField(&'static str),
    #[error("unsupported pointer version: {0}")]
    UnsupportedVersion(String),
    #[error("unsupported discovery URI scheme")]
    UnsupportedScheme,
    #[error("invalid pointer field: {0}")]
    InvalidField(&'static str),
    #[error("discovery hash mismatch")]
    HashMismatch,
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactPointer {
    pub document_uri: String,
    pub blake3_hex: String,
    pub sequence: u64,
    pub expires_at_ms: u64,
}

impl CompactPointer {
    pub fn new(
        document_uri: String,
        blake3_hex: String,
        sequence: u64,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            document_uri,
            blake3_hex,
            sequence,
            expires_at_ms,
        }
    }

    pub fn render(&self) -> String {
        format!(
            "v={};doc={};h=b3:{};seq={};exp={}",
            POINTER_VERSION, self.document_uri, self.blake3_hex, self.sequence, self.expires_at_ms
        )
    }

    pub fn validate(&self, now_ms: u64, last_sequence: Option<u64>) -> Result<(), DiscoveryError> {
        if self.expires_at_ms <= now_ms {
            return Err(DiscoveryError::Validation(ValidationError::Expired));
        }
        if last_sequence.is_some_and(|last| self.sequence < last) {
            return Err(DiscoveryError::Validation(ValidationError::StaleSequence));
        }
        validate_document_uri(&self.document_uri)?;
        if self.blake3_hex.len() != 64 || !self.blake3_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DiscoveryError::InvalidField("h"));
        }
        Ok(())
    }
}

impl FromStr for CompactPointer {
    type Err = DiscoveryError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let fields = input
            .split(';')
            .filter_map(|part| part.split_once('='))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect::<BTreeMap<_, _>>();

        let version = fields.get("v").ok_or(DiscoveryError::MissingField("v"))?;
        if *version != POINTER_VERSION {
            return Err(DiscoveryError::UnsupportedVersion((*version).to_string()));
        }

        let document_uri = fields
            .get("doc")
            .ok_or(DiscoveryError::MissingField("doc"))?
            .to_string();
        let hash = fields.get("h").ok_or(DiscoveryError::MissingField("h"))?;
        let blake3_hex = hash
            .strip_prefix("b3:")
            .ok_or(DiscoveryError::InvalidField("h"))?
            .to_string();
        let sequence = fields
            .get("seq")
            .ok_or(DiscoveryError::MissingField("seq"))?
            .parse()
            .map_err(|_| DiscoveryError::InvalidField("seq"))?;
        let expires_at_ms = fields
            .get("exp")
            .ok_or(DiscoveryError::MissingField("exp"))?
            .parse()
            .map_err(|_| DiscoveryError::InvalidField("exp"))?;

        Ok(Self::new(document_uri, blake3_hex, sequence, expires_at_ms))
    }
}

pub fn pointer_for(
    identity: &PubkyId,
    document: &DiscoveryDocument,
) -> Result<CompactPointer, serde_json::Error> {
    Ok(CompactPointer::new(
        identity.discovery_uri(),
        document.hash_hex()?,
        document.sequence,
        document.expires_at_ms,
    ))
}

pub fn verify_document_bytes(
    pointer: &CompactPointer,
    bytes: &[u8],
    expected_identity: &PubkyId,
    now_ms: u64,
    last_sequence: Option<u64>,
) -> Result<DiscoveryDocument, DiscoveryError> {
    pointer.validate(now_ms, last_sequence)?;
    let actual = blake3::hash(bytes).to_hex().to_string();
    if actual != pointer.blake3_hex {
        return Err(DiscoveryError::HashMismatch);
    }
    let document: DiscoveryDocument =
        serde_json::from_slice(bytes).map_err(|_| DiscoveryError::InvalidField("document"))?;
    document.validate(expected_identity, now_ms, last_sequence)?;
    Ok(document)
}

pub fn validate_document_uri(uri: &str) -> Result<(), DiscoveryError> {
    if uri.starts_with("pubky://") {
        return Ok(());
    }
    let parsed = Url::parse(uri).map_err(|_| DiscoveryError::InvalidField("doc"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        _ => Err(DiscoveryError::UnsupportedScheme),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pointer() {
        let input = "v=pkg1;doc=pubky://abc/pub/pubkegaard/v1/discovery.json;h=b3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;seq=7;exp=99";
        let pointer = CompactPointer::from_str(input).unwrap();
        assert_eq!(pointer.sequence, 7);
        assert_eq!(pointer.render(), input);
    }

    #[test]
    fn rejects_expired_pointer() {
        let input = "v=pkg1;doc=https://example.com/discovery.json;h=b3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;seq=7;exp=99";
        let pointer = CompactPointer::from_str(input).unwrap();
        assert!(matches!(
            pointer.validate(99, None),
            Err(DiscoveryError::Validation(ValidationError::Expired))
        ));
    }
}
