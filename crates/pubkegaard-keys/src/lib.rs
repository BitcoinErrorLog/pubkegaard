use base64::{engine::general_purpose::STANDARD, Engine as _};
use pubkegaard_types::{NoiseControlPublicKey, WireGuardPublicKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBKEGAARD_SESSION_SCOPE: &str = "/pub/pubkegaard/";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyRole {
    PubkyRootIdentity,
    NoiseControl,
    WireGuardTransport,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedKeyPair {
    pub role: KeyRole,
    pub private_key_base64: String,
    pub public_key_base64: String,
}

impl GeneratedKeyPair {
    pub fn public_noise_control_key(&self) -> Result<NoiseControlPublicKey, KeyError> {
        if self.role != KeyRole::NoiseControl {
            return Err(KeyError::WrongRole);
        }
        NoiseControlPublicKey::parse(self.public_key_base64.clone())
            .map_err(KeyError::InvalidControlKey)
    }

    pub fn public_wireguard_key(&self) -> Result<WireGuardPublicKey, KeyError> {
        if self.role != KeyRole::WireGuardTransport {
            return Err(KeyError::WrongRole);
        }
        WireGuardPublicKey::parse(self.public_key_base64.clone())
            .map_err(KeyError::InvalidWireGuardKey)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlPlaneProfile {
    pub identity: String,
    pub noise_control_public_key: NoiseControlPublicKey,
    pub wireguard_public_key: WireGuardPublicKey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SessionScope {
    pub path_prefix: String,
    pub read: bool,
    pub write: bool,
}

impl SessionScope {
    pub fn pubkegaard_read_write() -> Self {
        Self {
            path_prefix: PUBKEGAARD_SESSION_SCOPE.to_string(),
            read: true,
            write: true,
        }
    }

    pub fn is_sufficient_for_discovery(&self) -> bool {
        self.path_prefix == PUBKEGAARD_SESSION_SCOPE && self.read && self.write
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("key role does not match requested operation")]
    WrongRole,
    #[error("invalid control key: {0}")]
    InvalidControlKey(pubkegaard_types::ValidationError),
    #[error("invalid WireGuard key: {0}")]
    InvalidWireGuardKey(pubkegaard_types::ValidationError),
}

pub fn generate_noise_control_key() -> GeneratedKeyPair {
    generate_x25519_key(KeyRole::NoiseControl)
}

pub fn generate_wireguard_transport_key() -> GeneratedKeyPair {
    generate_x25519_key(KeyRole::WireGuardTransport)
}

pub fn generate_pubky_root_identity_key() -> GeneratedKeyPair {
    let keypair = pkarr::Keypair::random();
    GeneratedKeyPair {
        role: KeyRole::PubkyRootIdentity,
        private_key_base64: STANDARD.encode(keypair.secret_key()),
        public_key_base64: keypair.public_key().to_string(),
    }
}

fn generate_x25519_key(role: KeyRole) -> GeneratedKeyPair {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    GeneratedKeyPair {
        role,
        private_key_base64: STANDARD.encode(secret.to_bytes()),
        public_key_base64: STANDARD.encode(public.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_control_key_is_valid() {
        let key = generate_noise_control_key();
        assert_eq!(key.role, KeyRole::NoiseControl);
        assert!(key.public_noise_control_key().is_ok());
    }

    #[test]
    fn generated_wireguard_key_is_valid() {
        let key = generate_wireguard_transport_key();
        assert_eq!(key.role, KeyRole::WireGuardTransport);
        assert!(key.public_wireguard_key().is_ok());
    }

    #[test]
    fn generated_pubky_root_identity_is_valid_pubky_id() {
        let key = generate_pubky_root_identity_key();
        assert_eq!(key.role, KeyRole::PubkyRootIdentity);
        assert!(pubkegaard_types::PubkyId::parse(key.public_key_base64).is_ok());
    }

    #[test]
    fn pubkegaard_scope_requires_read_write() {
        let scope = SessionScope::pubkegaard_read_write();
        assert!(scope.is_sufficient_for_discovery());
    }
}
