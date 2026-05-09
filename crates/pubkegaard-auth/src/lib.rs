use pubkegaard_keys::SessionScope;
use pubkegaard_types::PubkyId;
use serde::{Deserialize, Serialize};
use url::Url;

pub const SERVICE_NAME: &str = "org.bitcoinerrorlog.pubkegaard.session";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingAuthRequest {
    pub relay_url: String,
    pub callback_url: String,
    pub requested_scope: SessionScope,
}

impl RingAuthRequest {
    pub fn new(
        relay_url: impl Into<String>,
        callback_url: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let request = Self {
            relay_url: relay_url.into(),
            callback_url: callback_url.into(),
            requested_scope: SessionScope::pubkegaard_read_write(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), AuthError> {
        let relay = Url::parse(&self.relay_url).map_err(|_| AuthError::InvalidUrl("relay_url"))?;
        if relay.scheme() != "https" {
            return Err(AuthError::InsecureRelay);
        }
        let callback =
            Url::parse(&self.callback_url).map_err(|_| AuthError::InvalidUrl("callback_url"))?;
        if callback.scheme() != "pubkegaard" {
            return Err(AuthError::InvalidCallbackScheme);
        }
        if !self.requested_scope.is_sufficient_for_discovery() {
            return Err(AuthError::InsufficientScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HomeserverSession {
    pub identity: PubkyId,
    pub homeserver_url: String,
    pub token: String,
    pub scope: SessionScope,
}

impl HomeserverSession {
    pub fn validate(&self) -> Result<(), AuthError> {
        let homeserver = Url::parse(&self.homeserver_url)
            .map_err(|_| AuthError::InvalidUrl("homeserver_url"))?;
        if homeserver.scheme() != "https" {
            return Err(AuthError::InsecureHomeserver);
        }
        if self.token.trim().is_empty() {
            return Err(AuthError::MissingToken);
        }
        if !self.scope.is_sufficient_for_discovery() {
            return Err(AuthError::InsufficientScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SessionVault {
    service: String,
}

impl SessionVault {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn pubkegaard() -> Self {
        Self::new(SERVICE_NAME)
    }

    pub fn store(&self, session: &HomeserverSession) -> Result<(), AuthError> {
        session.validate()?;
        let payload = serde_json::to_string(session).map_err(AuthError::Serialize)?;
        keyring::Entry::new(&self.service, session.identity.as_str())?
            .set_password(&payload)
            .map_err(AuthError::Keyring)
    }

    pub fn load(&self, identity: &PubkyId) -> Result<HomeserverSession, AuthError> {
        let payload = keyring::Entry::new(&self.service, identity.as_str())?
            .get_password()
            .map_err(AuthError::Keyring)?;
        serde_json::from_str(&payload).map_err(AuthError::Deserialize)
    }

    pub fn delete(&self, identity: &PubkyId) -> Result<(), AuthError> {
        keyring::Entry::new(&self.service, identity.as_str())?
            .delete_credential()
            .map_err(AuthError::Keyring)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid URL field: {0}")]
    InvalidUrl(&'static str),
    #[error("Ring auth relay must use HTTPS")]
    InsecureRelay,
    #[error("homeserver must use HTTPS")]
    InsecureHomeserver,
    #[error("callback URL must use pubkegaard scheme")]
    InvalidCallbackScheme,
    #[error("session token is required")]
    MissingToken,
    #[error("session scope does not include read/write access to /pub/pubkegaard/")]
    InsufficientScope,
    #[error("failed to serialize session: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to deserialize session: {0}")]
    Deserialize(serde_json::Error),
    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_request_requires_https_relay() {
        let request = RingAuthRequest {
            relay_url: "http://relay.example".to_string(),
            callback_url: "pubkegaard://auth/callback".to_string(),
            requested_scope: SessionScope::pubkegaard_read_write(),
        };
        assert!(matches!(request.validate(), Err(AuthError::InsecureRelay)));
    }

    #[test]
    fn ring_request_accepts_pubkegaard_scope() {
        let request =
            RingAuthRequest::new("https://relay.example", "pubkegaard://auth/callback").unwrap();
        assert!(request.requested_scope.is_sufficient_for_discovery());
    }
}
