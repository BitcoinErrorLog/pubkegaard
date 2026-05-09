use clap::{Parser, Subcommand};
use pubkegaard_types::PubkyId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(name = "pubkegaard-relay")]
#[command(about = "Pubkegaard relay session validator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ValidateRequest { request_json: String, now_ms: u64 },
    Limits,
}

#[derive(Debug, Deserialize, Serialize)]
struct RelayRequest {
    version: u16,
    from: PubkyId,
    to: PubkyId,
    relay: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    nonce: String,
    max_bytes: u64,
}

impl RelayRequest {
    fn validate(&self, now_ms: u64) -> anyhow::Result<()> {
        anyhow::ensure!(self.version == 1, "unsupported relay request version");
        anyhow::ensure!(self.expires_at_ms > now_ms, "relay request expired");
        anyhow::ensure!(
            self.created_at_ms <= now_ms + 300_000,
            "relay request is too far in the future"
        );
        anyhow::ensure!(!self.nonce.trim().is_empty(), "relay nonce is required");
        anyhow::ensure!(
            self.max_bytes > 0,
            "relay max_bytes must be greater than zero"
        );
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::ValidateRequest {
            request_json,
            now_ms,
        } => {
            let request: RelayRequest = serde_json::from_str(&request_json)?;
            request.validate(now_ms)?;
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "from": request.from,
                    "to": request.to,
                    "max_bytes": request.max_bytes
                })
            );
        }
        Command::Limits => {
            println!(
                "{}",
                serde_json::json!({
                    "max_sessions_per_identity": 8,
                    "default_max_bytes": 1073741824u64,
                    "logs_inner_packets": false
                })
            );
        }
    }
    Ok(())
}
