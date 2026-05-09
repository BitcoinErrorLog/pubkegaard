use std::{fs, path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand};
use pubkegaard_discovery::CompactPointer;
use pubkegaard_keys::{generate_noise_control_key, generate_wireguard_transport_key, SessionScope};
use pubkegaard_types::{PubkyId, TrustGrant};

#[derive(Debug, Parser)]
#[command(name = "pubkegaard")]
#[command(about = "CLI for Pubkegaard trusted-peer WireGuard networks")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        identity: String,
    },
    Resolve {
        pointer: String,
    },
    PublishPointer {
        identity: String,
        discovery_json: PathBuf,
    },
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    Keys {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Allow {
        #[command(subcommand)]
        command: AllowCommand,
    },
    Deny {
        identity: String,
    },
    Status,
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    Add { identity: String },
    Remove { identity: String },
    Show { identity: String },
    List,
}

#[derive(Debug, Subcommand)]
enum AllowCommand {
    Mesh { identity: String },
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    GenerateDevice,
    SessionScope,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Init { identity } => {
            let identity = PubkyId::parse(identity)?;
            println!("initialized identity {}", identity);
            println!("discovery path {}", identity.discovery_uri());
        }
        Command::Resolve { pointer } => {
            let pointer = CompactPointer::from_str(&pointer)?;
            println!(
                "{}",
                serde_json::json!({
                    "document_uri": pointer.document_uri,
                    "hash": format!("b3:{}", pointer.blake3_hex),
                    "sequence": pointer.sequence,
                    "expires_at_ms": pointer.expires_at_ms,
                })
            );
        }
        Command::PublishPointer {
            identity,
            discovery_json,
        } => {
            let identity = PubkyId::parse(identity)?;
            let bytes = fs::read(discovery_json)?;
            let document = serde_json::from_slice(&bytes)?;
            let pointer = pubkegaard_discovery::pointer_for(&identity, &document)?;
            println!("{}", pointer.render());
        }
        Command::Peer { command } => match command {
            PeerCommand::Add { identity } => {
                let identity = PubkyId::parse(identity)?;
                println!("peer {} added to local candidate set", identity);
            }
            PeerCommand::Remove { identity } => {
                let identity = PubkyId::parse(identity)?;
                println!("peer {} removed from local candidate set", identity);
            }
            PeerCommand::Show { identity } => {
                let identity = PubkyId::parse(identity)?;
                println!("peer {}", identity);
            }
            PeerCommand::List => println!("[]"),
        },
        Command::Keys { command } => match command {
            KeyCommand::GenerateDevice => {
                let control = generate_noise_control_key();
                let wireguard = generate_wireguard_transport_key();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "noise_control_public_key": control.public_key_base64,
                        "wireguard_public_key": wireguard.public_key_base64,
                        "private_keys": {
                            "storage": "store private_key_base64 fields in the OS key vault, not in discovery"
                        }
                    }))?
                );
            }
            KeyCommand::SessionScope => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&SessionScope::pubkegaard_read_write())?
                );
            }
        },
        Command::Allow { command } => match command {
            AllowCommand::Mesh { identity } => {
                let identity = PubkyId::parse(identity)?;
                let grant = TrustGrant::mesh_only(identity);
                println!("{}", serde_json::to_string_pretty(&grant)?);
            }
        },
        Command::Deny { identity } => {
            let identity = PubkyId::parse(identity)?;
            println!("all permissions denied for {}", identity);
        }
        Command::Status => {
            println!(
                "{}",
                serde_json::json!({
                    "daemon": "not_connected",
                    "mesh": "available",
                    "relay": "disabled_until_beta",
                    "exit": "disabled_until_gate"
                })
            );
        }
    }
    Ok(())
}
