use ipnet::IpNet;
use pubkegaard_types::{Device, Endpoint, WireGuardPublicKey};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireGuardError {
    #[error("peer has no allowed IPs")]
    NoAllowedIps,
    #[error("peer has no endpoint")]
    NoEndpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerConfig {
    pub public_key: WireGuardPublicKey,
    pub allowed_ips: Vec<IpNet>,
    pub endpoint: Endpoint,
    pub persistent_keepalive_seconds: u16,
}

impl PeerConfig {
    pub fn mesh_from_device(device: &Device) -> Result<Self, WireGuardError> {
        let allowed_ips = device.addresses.clone();
        if allowed_ips.is_empty() {
            return Err(WireGuardError::NoAllowedIps);
        }
        let endpoint = best_endpoint(&device.endpoints).ok_or(WireGuardError::NoEndpoint)?;
        Ok(Self {
            public_key: device.wg_public_key.clone(),
            allowed_ips,
            endpoint,
            persistent_keepalive_seconds: 25,
        })
    }

    pub fn render_peer_section(&self) -> String {
        let allowed_ips = self
            .allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "[Peer]\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {}:{}\nPersistentKeepalive = {}\n",
            self.public_key.as_base64(),
            allowed_ips,
            self.endpoint.host,
            self.endpoint.port,
            self.persistent_keepalive_seconds
        )
    }
}

pub fn best_endpoint(endpoints: &[Endpoint]) -> Option<Endpoint> {
    endpoints
        .iter()
        .min_by_key(|endpoint| endpoint.priority)
        .cloned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceConfig {
    pub name: String,
    pub addresses: Vec<IpNet>,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerConfig>,
}

impl InterfaceConfig {
    pub fn render(&self) -> String {
        let addresses = self
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut output = format!("[Interface]\nAddress = {}\n", addresses);
        if let Some(port) = self.listen_port {
            output.push_str(&format!("ListenPort = {}\n", port));
        }
        for peer in &self.peers {
            output.push('\n');
            output.push_str(&peer.render_peer_section());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubkegaard_types::{Permissions, Route};

    #[test]
    fn renders_mesh_peer() {
        let key =
            WireGuardPublicKey::parse("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=").unwrap();
        let device = Device {
            device_id: "dev1".into(),
            wg_public_key: key,
            addresses: vec!["100.88.1.2/32".parse().unwrap()],
            endpoints: vec![Endpoint {
                host: "203.0.113.4".into(),
                port: 51820,
                priority: 10,
            }],
            routes: Vec::<Route>::new(),
            capabilities: Permissions {
                mesh: true,
                ..Permissions::default()
            },
        };
        let rendered = PeerConfig::mesh_from_device(&device)
            .unwrap()
            .render_peer_section();
        assert!(rendered.contains("AllowedIPs = 100.88.1.2/32"));
        assert!(rendered.contains("Endpoint = 203.0.113.4:51820"));
    }
}
