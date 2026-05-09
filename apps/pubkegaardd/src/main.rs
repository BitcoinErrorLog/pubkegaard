use std::{fs, net::IpAddr, path::PathBuf};

use clap::{Parser, Subcommand};
use pubkegaard_firewall::FirewallPlan;
use pubkegaard_policy::EffectivePolicy;
use pubkegaard_types::{DiscoveryDocument, PubkyId, RouteKind, TrustGrant};
use pubkegaard_wireguard::{InterfaceConfig, PeerConfig};

#[derive(Debug, Parser)]
#[command(name = "pubkegaardd")]
#[command(about = "Pubkegaard controller daemon utilities")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status,
    PlanMesh {
        identity: String,
        discovery_json: PathBuf,
    },
    Revoke {
        identity: String,
        peer_ip: IpAddr,
    },
    ExitGate,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Status => {
            println!(
                "{}",
                serde_json::json!({
                    "state": "ready",
                    "transport": "wireguard",
                    "interface": "pkg0",
                    "relay": "beta_track",
                    "exit": "gated"
                })
            );
        }
        Command::PlanMesh {
            identity,
            discovery_json,
        } => {
            let identity = PubkyId::parse(identity)?;
            let bytes = fs::read(discovery_json)?;
            let document: DiscoveryDocument = serde_json::from_slice(&bytes)?;
            document.validate(&identity, 0, None)?;
            let grant = TrustGrant::mesh_only(identity);
            let policy = EffectivePolicy::compile(grant, 0)?;
            let mut peers = Vec::new();
            for device in &document.devices {
                let mesh_routes = device
                    .routes
                    .iter()
                    .filter(|route| matches!(route.kind, RouteKind::Mesh))
                    .collect::<Vec<_>>();
                let _accepted = policy.authorize_routes(mesh_routes)?;
                peers.push(PeerConfig::mesh_from_device(device)?);
            }
            let wg = InterfaceConfig {
                name: "pkg0".into(),
                addresses: Vec::new(),
                listen_port: Some(51820),
                peers,
            };
            println!("{}", wg.render());
        }
        Command::Revoke { identity, peer_ip } => {
            let identity = PubkyId::parse(identity)?;
            let peer = format!("{}/32", peer_ip).parse()?;
            let plan = FirewallPlan::mesh_peer("pkg0", peer);
            println!(
                "{}",
                serde_json::json!({
                    "revoked": identity,
                    "rollback": plan.rollback.iter().map(|action| format!("{action:?}")).collect::<Vec<_>>()
                })
            );
        }
        Command::ExitGate => {
            println!(
                "{}",
                serde_json::json!({
                    "exit_enabled": false,
                    "required": [
                        "endpoint_route_preservation",
                        "dns_leak_protection",
                        "kill_switch",
                        "firewall_rollback",
                        "private_range_blocklist",
                        "per_peer_limits",
                        "operator_emergency_stop"
                    ]
                })
            );
        }
    }
    Ok(())
}
