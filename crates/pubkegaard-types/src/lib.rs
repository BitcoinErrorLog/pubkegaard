use std::{fmt, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const DISCOVERY_TYPE: &str = "pubkegaard.discovery";
pub const TRUST_GRANT_TYPE: &str = "pubkegaard.trust_grant";
pub const VERSION_1: u16 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("invalid Pubky identity: {0}")]
    InvalidIdentity(String),
    #[error("invalid WireGuard public key")]
    InvalidWireGuardKey,
    #[error("unsupported type: {0}")]
    UnsupportedType(String),
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u16),
    #[error("object has expired")]
    Expired,
    #[error("sequence is stale")]
    StaleSequence,
    #[error("identity mismatch")]
    IdentityMismatch,
    #[error("route is not permitted by policy")]
    RouteDenied,
    #[error("discovery document has no devices")]
    NoDevices,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PubkyId(String);

impl PubkyId {
    pub fn parse(input: impl AsRef<str>) -> Result<Self, ValidationError> {
        let raw = input.as_ref().trim();
        let normalized = raw
            .strip_prefix("pubky://")
            .or_else(|| raw.strip_prefix("pk:"))
            .unwrap_or(raw);

        pkarr::PublicKey::try_from(normalized)
            .map_err(|_| ValidationError::InvalidIdentity(raw.to_string()))?;

        Ok(Self(normalized.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn discovery_uri(&self) -> String {
        format!("pubky://{}/pub/pubkegaard/v1/discovery.json", self.0)
    }
}

impl fmt::Display for PubkyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PubkyId {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for PubkyId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PubkyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireGuardPublicKey(String);

impl WireGuardPublicKey {
    pub fn parse(input: impl Into<String>) -> Result<Self, ValidationError> {
        let value = input.into();
        let raw = value.strip_prefix("wg:").unwrap_or(&value);
        let bytes = STANDARD
            .decode(raw)
            .map_err(|_| ValidationError::InvalidWireGuardKey)?;
        if bytes.len() != 32 {
            return Err(ValidationError::InvalidWireGuardKey);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_base64(&self) -> &str {
        &self.0
    }
}

impl Serialize for WireGuardPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_base64())
    }
}

impl<'de> Deserialize<'de> for WireGuardPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub priority: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RouteKind {
    Mesh,
    Lan,
    ExitIpv4,
    ExitIpv6,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Route {
    pub cidr: IpNet,
    pub kind: RouteKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Device {
    pub device_id: String,
    pub wg_public_key: WireGuardPublicKey,
    pub addresses: Vec<IpNet>,
    pub endpoints: Vec<Endpoint>,
    pub routes: Vec<Route>,
    pub capabilities: Permissions,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryDocument {
    pub r#type: String,
    pub version: u16,
    pub identity: PubkyId,
    pub sequence: u64,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub devices: Vec<Device>,
}

impl DiscoveryDocument {
    pub fn validate(
        &self,
        expected_identity: &PubkyId,
        now_ms: u64,
        last_sequence: Option<u64>,
    ) -> Result<(), ValidationError> {
        if self.r#type != DISCOVERY_TYPE {
            return Err(ValidationError::UnsupportedType(self.r#type.clone()));
        }
        if self.version != VERSION_1 {
            return Err(ValidationError::UnsupportedVersion(self.version));
        }
        if &self.identity != expected_identity {
            return Err(ValidationError::IdentityMismatch);
        }
        if self.expires_at_ms <= now_ms {
            return Err(ValidationError::Expired);
        }
        if last_sequence.is_some_and(|last| self.sequence < last) {
            return Err(ValidationError::StaleSequence);
        }
        if self.devices.is_empty() {
            return Err(ValidationError::NoDevices);
        }
        Ok(())
    }

    pub fn hash_hex(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Permissions {
    pub mesh: bool,
    pub relay_client: bool,
    pub relay_server: bool,
    pub exit_client: bool,
    pub exit_server: bool,
    pub lan_client: bool,
    pub lan_server: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrustGrant {
    pub r#type: String,
    pub version: u16,
    pub subject: PubkyId,
    pub label: Option<String>,
    pub expires_at_ms: Option<u64>,
    pub permissions: Permissions,
    pub allowed_routes: Vec<IpNet>,
    pub denied_routes: Vec<IpNet>,
}

impl TrustGrant {
    pub fn mesh_only(subject: PubkyId) -> Self {
        Self {
            r#type: TRUST_GRANT_TYPE.to_string(),
            version: VERSION_1,
            subject,
            label: None,
            expires_at_ms: None,
            permissions: Permissions {
                mesh: true,
                ..Permissions::default()
            },
            allowed_routes: Vec::new(),
            denied_routes: Vec::new(),
        }
    }

    pub fn validate(&self, now_ms: u64) -> Result<(), ValidationError> {
        if self.r#type != TRUST_GRANT_TYPE {
            return Err(ValidationError::UnsupportedType(self.r#type.clone()));
        }
        if self.version != VERSION_1 {
            return Err(ValidationError::UnsupportedVersion(self.version));
        }
        if self.expires_at_ms.is_some_and(|expiry| expiry <= now_ms) {
            return Err(ValidationError::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_key_must_decode_to_32_bytes() {
        let valid = STANDARD.encode([7u8; 32]);
        assert!(WireGuardPublicKey::parse(valid).is_ok());
        assert_eq!(
            WireGuardPublicKey::parse(STANDARD.encode([7u8; 31])),
            Err(ValidationError::InvalidWireGuardKey)
        );
    }

    #[test]
    fn trust_grant_rejects_expired() {
        let subject =
            PubkyId::parse("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo").unwrap();
        let mut grant = TrustGrant::mesh_only(subject);
        grant.expires_at_ms = Some(10);
        assert_eq!(grant.validate(10), Err(ValidationError::Expired));
    }
}
