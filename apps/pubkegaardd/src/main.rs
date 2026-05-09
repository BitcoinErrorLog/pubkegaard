use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, TcpListener, TcpStream},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use pubkegaard_firewall::FirewallPlan;
use pubkegaard_platform::{LinuxNetworkAdapter, PlatformNetwork};
use pubkegaard_policy::EffectivePolicy;
use pubkegaard_types::{DiscoveryDocument, PubkyId, RouteKind, TrustGrant};
use pubkegaard_wireguard::{InterfaceConfig, PeerConfig};
use serde::Deserialize;

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
    Serve {
        #[arg(long, default_value = "127.0.0.1:8765")]
        bind: String,
        #[arg(long)]
        token_file: PathBuf,
    },
    PlanMesh {
        identity: String,
        discovery_json: PathBuf,
    },
    Revoke {
        identity: String,
        peer_ip: IpAddr,
    },
    ExitGate,
    EmergencyStop {
        #[arg(long, default_value = "pkg0")]
        interface: String,
    },
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
        Command::Serve { bind, token_file } => {
            let token = fs::read_to_string(token_file)?.trim().to_string();
            serve(&bind, &token)?;
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
        Command::EmergencyStop { interface } => {
            let plan = LinuxNetworkAdapter.emergency_stop(&interface)?;
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AuthorizedRequest {
    token: String,
    action: DaemonAction,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DaemonAction {
    Status,
    EmergencyStop { interface: String },
    RevokePeer { interface: String, peer: IpAddr },
}

fn serve(bind: &str, token: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_client(stream, token)?,
            Err(error) => eprintln!("failed to accept daemon client: {error}"),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, expected_token: &str) -> anyhow::Result<()> {
    let mut buffer = String::new();
    stream.read_to_string(&mut buffer)?;
    let request: AuthorizedRequest = serde_json::from_str(&buffer)?;
    if request.token != expected_token {
        stream.write_all(br#"{"error":"unauthorized"}"#)?;
        return Ok(());
    }

    let response = match request.action {
        DaemonAction::Status => serde_json::json!({
            "state": "ready",
            "transport": "wireguard",
            "interface": "pkg0",
            "relay": "beta_track",
            "exit": "gated"
        }),
        DaemonAction::EmergencyStop { interface } => {
            serde_json::to_value(LinuxNetworkAdapter.emergency_stop(&interface)?)?
        }
        DaemonAction::RevokePeer { interface, peer } => {
            let peer = format!("{peer}/32").parse()?;
            serde_json::to_value(LinuxNetworkAdapter.revoke_peer(&interface, peer)?)?
        }
    };

    stream.write_all(serde_json::to_string(&response)?.as_bytes())?;
    Ok(())
}
