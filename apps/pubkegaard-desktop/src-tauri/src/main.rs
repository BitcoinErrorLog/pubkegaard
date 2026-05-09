use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireGuardState {
    NotConfigured,
    Stopped,
    Running,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SessionMode {
    None,
    RingSession,
    LocalKeys,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionState {
    Resolving,
    Direct,
    Relayed,
    Degraded,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PeerPreset {
    Mesh,
    RelayClient,
    RelayServer,
    ExitClient,
    ExitServer,
    LanShare,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Peer {
    identity: String,
    label: Option<String>,
    preset: PeerPreset,
    connection_state: ConnectionState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppState {
    identity: Option<String>,
    device_label: String,
    noise_control_public_key: Option<String>,
    wireguard_public_key: Option<String>,
    discovery_published: bool,
    wireguard_state: WireGuardState,
    session_mode: SessionMode,
    peers: Vec<Peer>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RingAuthPreview {
    relay_url: String,
    callback_url: String,
    scope_path: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            identity: None,
            device_label: "This device".to_string(),
            noise_control_public_key: None,
            wireguard_public_key: None,
            discovery_published: false,
            wireguard_state: WireGuardState::NotConfigured,
            session_mode: SessionMode::None,
            peers: Vec::new(),
            warnings: vec!["Onboarding has not completed.".to_string()],
        }
    }
}

#[tauri::command]
fn load_state() -> Result<AppState, String> {
    read_state().map_err(|error| error.to_string())
}

#[tauri::command]
fn complete_onboarding(mode: SessionMode) -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    if mode == SessionMode::None {
        return Err("onboarding mode cannot be none".to_string());
    }
    let noise_control = pubkegaard_keys::generate_noise_control_key();
    let wireguard = pubkegaard_keys::generate_wireguard_transport_key();
    store_secret(
        "noise-control-private-key",
        &noise_control.private_key_base64,
    )
    .map_err(|error| error.to_string())?;
    store_secret("wireguard-private-key", &wireguard.private_key_base64)
        .map_err(|error| error.to_string())?;
    state.noise_control_public_key = Some(noise_control.public_key_base64);
    state.wireguard_public_key = Some(wireguard.public_key_base64);
    state.session_mode = mode;
    state.discovery_published = false;
    state.wireguard_state = WireGuardState::Stopped;
    state.warnings = match state.session_mode {
        SessionMode::LocalKeys => vec![
            "Root identity binding is required before public discovery is trusted by peers.".to_string(),
        ],
        SessionMode::RingSession => vec![
            "Ring session can write discovery, but PKARR-bound control-key authorization may still be required.".to_string(),
        ],
        SessionMode::None => vec!["Onboarding has not completed.".to_string()],
    };
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn add_peer(identity: String, preset: PeerPreset) -> Result<AppState, String> {
    let trimmed = identity.trim();
    if trimmed.is_empty() {
        return Err("peer identity is required".to_string());
    }
    let mut state = read_state().map_err(|error| error.to_string())?;
    if state.peers.iter().any(|peer| peer.identity == trimmed) {
        return Err("peer already exists".to_string());
    }
    state.peers.push(Peer {
        identity: trimmed.to_string(),
        label: None,
        preset,
        connection_state: ConnectionState::Resolving,
    });
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn remove_peer(identity: String) -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    state.peers.retain(|peer| peer.identity != identity);
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn emergency_stop() -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    state.wireguard_state = WireGuardState::Stopped;
    for peer in &mut state.peers {
        if matches!(
            peer.preset,
            PeerPreset::RelayServer
                | PeerPreset::ExitClient
                | PeerPreset::ExitServer
                | PeerPreset::LanShare
        ) {
            peer.connection_state = ConnectionState::Stopped;
        }
    }
    state.warnings = vec![
        "Emergency stop removed risky active network state. Review peers before restarting."
            .to_string(),
    ];
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn start_ring_auth(relay_url: String) -> Result<RingAuthPreview, String> {
    let request = pubkegaard_auth::RingAuthRequest::new(relay_url, "pubkegaard://auth/callback")
        .map_err(|error| error.to_string())?;
    Ok(RingAuthPreview {
        relay_url: request.relay_url,
        callback_url: request.callback_url,
        scope_path: request.requested_scope.path_prefix,
    })
}

#[tauri::command]
fn store_ring_session(
    identity: String,
    homeserver_url: String,
    token: String,
) -> Result<AppState, String> {
    let identity = pubkegaard_types::PubkyId::parse(identity).map_err(|error| error.to_string())?;
    let session = pubkegaard_auth::HomeserverSession {
        identity: identity.clone(),
        homeserver_url,
        token,
        scope: pubkegaard_keys::SessionScope::pubkegaard_read_write(),
    };
    pubkegaard_auth::SessionVault::pubkegaard()
        .store(&session)
        .map_err(|error| error.to_string())?;
    let mut state = read_state().map_err(|error| error.to_string())?;
    state.identity = Some(identity.to_string());
    state.session_mode = SessionMode::RingSession;
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

fn warnings_for(state: &AppState) -> Vec<String> {
    let mut warnings = Vec::new();
    if state.session_mode == SessionMode::RingSession {
        warnings.push("Ring session mode cannot replace root/binding authorization.".to_string());
    }
    if state.peers.iter().any(|peer| {
        matches!(
            peer.preset,
            PeerPreset::RelayServer
                | PeerPreset::ExitClient
                | PeerPreset::ExitServer
                | PeerPreset::LanShare
        )
    }) {
        warnings.push("Risky relay, exit, or LAN sharing permission is active.".to_string());
    }
    warnings
}

fn state_path() -> Result<PathBuf, io::Error> {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join(".pubkegaard");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("desktop-state.json"))
}

fn read_state() -> Result<AppState, io::Error> {
    let path = state_path()?;
    if !Path::new(&path).exists() {
        return Ok(AppState::default());
    }
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn write_state(state: &AppState) -> Result<(), io::Error> {
    let bytes = serde_json::to_vec_pretty(state).map_err(io::Error::other)?;
    fs::write(state_path()?, bytes)
}

fn store_secret(account: &str, secret: &str) -> keyring::Result<()> {
    keyring::Entry::new("org.bitcoinerrorlog.pubkegaard", account)?.set_password(secret)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_state,
            complete_onboarding,
            add_peer,
            remove_peer,
            emergency_stop,
            start_ring_auth,
            store_ring_session
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Pubkegaard desktop app");
}
