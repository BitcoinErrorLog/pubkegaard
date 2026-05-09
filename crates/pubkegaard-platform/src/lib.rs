use ipnet::IpNet;
use pubkegaard_firewall::FirewallPlan;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PlatformKind {
    Linux,
    Macos,
    Windows,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NetworkOperation {
    VerifyBackend,
    StartInterface,
    StopInterface,
    UpdateRoutes,
    UpdateDns,
    SetKillSwitch,
    RevokePeer,
    EmergencyStop,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkStep {
    pub operation: NetworkOperation,
    pub description: String,
    pub command_preview: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkPlan {
    pub steps: Vec<NetworkStep>,
    pub rollback: Vec<NetworkStep>,
}

pub trait PlatformNetwork {
    fn kind(&self) -> PlatformKind;
    fn verify_backend(&self) -> Result<NetworkPlan, PlatformError>;
    fn start_interface(&self, interface: &str) -> Result<NetworkPlan, PlatformError>;
    fn stop_interface(&self, interface: &str) -> Result<NetworkPlan, PlatformError>;
    fn revoke_peer(&self, interface: &str, peer: IpNet) -> Result<NetworkPlan, PlatformError>;
    fn emergency_stop(&self, interface: &str) -> Result<NetworkPlan, PlatformError>;
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum PlatformError {
    #[error("{0:?} adapter is not implemented yet")]
    Unsupported(PlatformKind),
}

#[derive(Clone, Debug, Default)]
pub struct LinuxNetworkAdapter;

impl PlatformNetwork for LinuxNetworkAdapter {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Linux
    }

    fn verify_backend(&self) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![
                step(
                    NetworkOperation::VerifyBackend,
                    "Verify kernel WireGuard tooling",
                    Some("wg --version".to_string()),
                ),
                step(
                    NetworkOperation::VerifyBackend,
                    "Verify nftables is available",
                    Some("nft --version".to_string()),
                ),
            ],
            rollback: Vec::new(),
        })
    }

    fn start_interface(&self, interface: &str) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![step(
                NetworkOperation::StartInterface,
                format!("Start WireGuard interface {interface}"),
                Some(format!("wg-quick up {interface}")),
            )],
            rollback: vec![step(
                NetworkOperation::StopInterface,
                format!("Stop WireGuard interface {interface}"),
                Some(format!("wg-quick down {interface}")),
            )],
        })
    }

    fn stop_interface(&self, interface: &str) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![step(
                NetworkOperation::StopInterface,
                format!("Stop WireGuard interface {interface}"),
                Some(format!("wg-quick down {interface}")),
            )],
            rollback: Vec::new(),
        })
    }

    fn revoke_peer(&self, interface: &str, peer: IpNet) -> Result<NetworkPlan, PlatformError> {
        let firewall = FirewallPlan::mesh_peer(interface, peer);
        Ok(NetworkPlan {
            steps: vec![
                step(
                    NetworkOperation::RevokePeer,
                    format!("Remove WireGuard peer routes for {peer}"),
                    Some(format!("wg set {interface} peer <peer-public-key> remove")),
                ),
                step(
                    NetworkOperation::RevokePeer,
                    "Apply nftables rollback for revoked peer",
                    Some(
                        firewall
                            .rollback
                            .iter()
                            .map(|action| format!("{action:?}"))
                            .collect::<Vec<_>>()
                            .join("; "),
                    ),
                ),
            ],
            rollback: Vec::new(),
        })
    }

    fn emergency_stop(&self, interface: &str) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![
                step(
                    NetworkOperation::SetKillSwitch,
                    "Disable forwarding and risky Pubkegaard routes",
                    Some("nft flush table inet pubkegaard".to_string()),
                ),
                step(
                    NetworkOperation::StopInterface,
                    format!("Stop WireGuard interface {interface}"),
                    Some(format!("wg-quick down {interface}")),
                ),
                step(
                    NetworkOperation::UpdateDns,
                    "Restore system DNS outside Pubkegaard control",
                    None,
                ),
            ],
            rollback: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MacosWireGuardToolsAdapter;

impl PlatformNetwork for MacosWireGuardToolsAdapter {
    fn kind(&self) -> PlatformKind {
        PlatformKind::Macos
    }

    fn verify_backend(&self) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![
                step(
                    NetworkOperation::VerifyBackend,
                    "Verify wg is installed",
                    Some("command -v wg".to_string()),
                ),
                step(
                    NetworkOperation::VerifyBackend,
                    "Verify wg-quick is installed",
                    Some("command -v wg-quick".to_string()),
                ),
            ],
            rollback: Vec::new(),
        })
    }

    fn start_interface(&self, interface: &str) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![step(
                NetworkOperation::StartInterface,
                format!("Start WireGuard config {interface} with administrator privileges"),
                Some(format!("wg-quick up {interface}")),
            )],
            rollback: vec![step(
                NetworkOperation::StopInterface,
                format!("Stop WireGuard config {interface}"),
                Some(format!("wg-quick down {interface}")),
            )],
        })
    }

    fn stop_interface(&self, interface: &str) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![step(
                NetworkOperation::StopInterface,
                format!("Stop WireGuard config {interface}"),
                Some(format!("wg-quick down {interface}")),
            )],
            rollback: Vec::new(),
        })
    }

    fn revoke_peer(&self, interface: &str, peer: IpNet) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![step(
                NetworkOperation::RevokePeer,
                format!("Remove peer route {peer} and restart {interface}"),
                Some(format!(
                    "wg-quick down {interface}; wg-quick up {interface}"
                )),
            )],
            rollback: Vec::new(),
        })
    }

    fn emergency_stop(&self, interface: &str) -> Result<NetworkPlan, PlatformError> {
        Ok(NetworkPlan {
            steps: vec![step(
                NetworkOperation::EmergencyStop,
                format!("Stop {interface} and remove Pubkegaard routes"),
                Some(format!("wg-quick down {interface}")),
            )],
            rollback: Vec::new(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct PlannedAdapter {
    kind: PlatformKind,
}

impl PlannedAdapter {
    pub fn macos() -> Self {
        Self {
            kind: PlatformKind::Macos,
        }
    }

    pub fn windows() -> Self {
        Self {
            kind: PlatformKind::Windows,
        }
    }
}

impl PlatformNetwork for PlannedAdapter {
    fn kind(&self) -> PlatformKind {
        self.kind
    }

    fn verify_backend(&self) -> Result<NetworkPlan, PlatformError> {
        Err(PlatformError::Unsupported(self.kind))
    }

    fn start_interface(&self, _interface: &str) -> Result<NetworkPlan, PlatformError> {
        Err(PlatformError::Unsupported(self.kind))
    }

    fn stop_interface(&self, _interface: &str) -> Result<NetworkPlan, PlatformError> {
        Err(PlatformError::Unsupported(self.kind))
    }

    fn revoke_peer(&self, _interface: &str, _peer: IpNet) -> Result<NetworkPlan, PlatformError> {
        Err(PlatformError::Unsupported(self.kind))
    }

    fn emergency_stop(&self, _interface: &str) -> Result<NetworkPlan, PlatformError> {
        Err(PlatformError::Unsupported(self.kind))
    }
}

fn step(
    operation: NetworkOperation,
    description: impl Into<String>,
    command_preview: Option<String>,
) -> NetworkStep {
    NetworkStep {
        operation,
        description: description.into(),
        command_preview: command_preview.map(Into::into),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_revoke_plan_has_steps() {
        let plan = LinuxNetworkAdapter
            .revoke_peer("pkg0", "100.88.1.2/32".parse().unwrap())
            .unwrap();
        assert_eq!(plan.steps.len(), 2);
    }

    #[test]
    fn macos_wireguard_tools_adapter_plans_backend_checks() {
        let plan = MacosWireGuardToolsAdapter.verify_backend().unwrap();
        assert_eq!(plan.steps.len(), 2);
    }
}
