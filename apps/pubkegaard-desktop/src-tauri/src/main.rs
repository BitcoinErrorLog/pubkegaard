use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
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
    wireguard_public_key: String,
    address: String,
    endpoint_host: Option<String>,
    endpoint_port: u16,
    connection_state: ConnectionState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct AppState {
    identity: Option<String>,
    device_label: String,
    noise_control_public_key: Option<String>,
    wireguard_public_key: Option<String>,
    local_address: Option<String>,
    listen_port: u16,
    endpoint_host: Option<String>,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerProfile {
    version: u16,
    identity: String,
    device_label: String,
    noise_control_public_key: String,
    wireguard_public_key: String,
    address: String,
    endpoint_host: Option<String>,
    endpoint_port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolStatus {
    wg: bool,
    wg_quick: bool,
    details: String,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            identity: None,
            device_label: "This device".to_string(),
            noise_control_public_key: None,
            wireguard_public_key: None,
            local_address: None,
            listen_port: 51820,
            endpoint_host: None,
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
    let root_identity = pubkegaard_keys::generate_pubky_root_identity_key();
    let noise_control = pubkegaard_keys::generate_noise_control_key();
    let wireguard = pubkegaard_keys::generate_wireguard_transport_key();
    store_secret("pubky-root-private-key", &root_identity.private_key_base64)
        .map_err(|error| error.to_string())?;
    store_secret(
        "noise-control-private-key",
        &noise_control.private_key_base64,
    )
    .map_err(|error| error.to_string())?;
    store_secret("wireguard-private-key", &wireguard.private_key_base64)
        .map_err(|error| error.to_string())?;
    state.identity = Some(root_identity.public_key_base64);
    state.local_address = state
        .identity
        .as_ref()
        .map(|identity| overlay_address_for(identity));
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
fn import_peer_profile(profile_json: String, preset: PeerPreset) -> Result<AppState, String> {
    let profile: PeerProfile =
        serde_json::from_str(profile_json.trim()).map_err(|error| error.to_string())?;
    validate_peer_profile(&profile)?;
    let mut state = read_state().map_err(|error| error.to_string())?;
    if state
        .peers
        .iter()
        .any(|peer| peer.identity == profile.identity)
    {
        return Err("peer already exists".to_string());
    }
    state.peers.push(Peer {
        identity: profile.identity,
        label: Some(profile.device_label),
        preset,
        wireguard_public_key: profile.wireguard_public_key,
        address: profile.address,
        endpoint_host: profile.endpoint_host,
        endpoint_port: profile.endpoint_port,
        connection_state: ConnectionState::Stopped,
    });
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn export_peer_profile(
    endpoint_host: Option<String>,
    endpoint_port: u16,
) -> Result<String, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    let identity = state
        .identity
        .clone()
        .ok_or("complete onboarding before exporting a peer profile")?;
    let noise_control_public_key = state
        .noise_control_public_key
        .clone()
        .ok_or("missing noise control key")?;
    let wireguard_public_key = state
        .wireguard_public_key
        .clone()
        .ok_or("missing WireGuard public key")?;
    let address = state
        .local_address
        .clone()
        .ok_or("missing local overlay address")?;
    let endpoint_host = endpoint_host.and_then(|host| {
        let trimmed = host.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    state.endpoint_host = endpoint_host.clone();
    state.listen_port = endpoint_port;
    write_state(&state).map_err(|error| error.to_string())?;
    let profile = PeerProfile {
        version: 1,
        identity,
        device_label: state.device_label,
        noise_control_public_key,
        wireguard_public_key,
        address,
        endpoint_host,
        endpoint_port,
    };
    serde_json::to_string_pretty(&profile).map_err(|error| error.to_string())
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
    let _ = run_wg_quick_down();
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
fn verify_wireguard_tools() -> ToolStatus {
    let wg = command_exists("wg");
    let wg_quick = command_exists("wg-quick");
    let details = match (wg, wg_quick) {
        (true, true) => "WireGuard tools are installed.".to_string(),
        (false, false) => "Install WireGuard tools first: brew install wireguard-tools".to_string(),
        (false, true) => "Missing wg. Install or repair wireguard-tools.".to_string(),
        (true, false) => "Missing wg-quick. Install or repair wireguard-tools.".to_string(),
    };
    ToolStatus {
        wg,
        wg_quick,
        details,
    }
}

#[tauri::command]
fn apply_wireguard() -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    ensure_ready_for_wireguard(&state)?;
    let config = render_wireguard_config(&state)?;
    let path = wireguard_config_path().map_err(|error| error.to_string())?;
    fs::write(&path, config).map_err(|error| error.to_string())?;
    run_wg_quick_up(&path)?;
    state.wireguard_state = WireGuardState::Running;
    for peer in &mut state.peers {
        peer.connection_state = ConnectionState::Direct;
    }
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn stop_wireguard() -> Result<AppState, String> {
    run_wg_quick_down()?;
    let mut state = read_state().map_err(|error| error.to_string())?;
    state.wireguard_state = WireGuardState::Stopped;
    for peer in &mut state.peers {
        peer.connection_state = ConnectionState::Stopped;
    }
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
    if !verify_wireguard_tools().wg_quick {
        warnings.push(
            "WireGuard tools are not installed. Run: brew install wireguard-tools".to_string(),
        );
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

fn validate_peer_profile(profile: &PeerProfile) -> Result<(), String> {
    if profile.version != 1 {
        return Err("unsupported peer profile version".to_string());
    }
    pubkegaard_types::PubkyId::parse(&profile.identity).map_err(|error| error.to_string())?;
    pubkegaard_types::NoiseControlPublicKey::parse(profile.noise_control_public_key.clone())
        .map_err(|error| error.to_string())?;
    pubkegaard_types::WireGuardPublicKey::parse(profile.wireguard_public_key.clone())
        .map_err(|error| error.to_string())?;
    profile
        .address
        .parse::<ipnet::IpNet>()
        .map_err(|error| error.to_string())?;
    if profile.endpoint_port == 0 {
        return Err("endpoint port is required".to_string());
    }
    Ok(())
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

fn load_secret(account: &str) -> Result<String, String> {
    keyring::Entry::new("org.bitcoinerrorlog.pubkegaard", account)
        .map_err(|error| error.to_string())?
        .get_password()
        .map_err(|error| error.to_string())
}

fn overlay_address_for(identity: &str) -> String {
    let hash = blake3::hash(identity.as_bytes());
    let bytes = hash.as_bytes();
    let host = match bytes[1] {
        0 => 1,
        255 => 254,
        value => value,
    };
    format!("100.88.{}.{host}/32", bytes[0])
}

fn ensure_ready_for_wireguard(state: &AppState) -> Result<(), String> {
    let tools = verify_wireguard_tools();
    if !tools.wg || !tools.wg_quick {
        return Err(tools.details);
    }
    if state.local_address.is_none() {
        return Err("complete onboarding before applying WireGuard".to_string());
    }
    if state.peers.is_empty() {
        return Err("import at least one peer profile before applying WireGuard".to_string());
    }
    Ok(())
}

fn render_wireguard_config(state: &AppState) -> Result<String, String> {
    let private_key = load_secret("wireguard-private-key")?;
    let address = state
        .local_address
        .as_ref()
        .ok_or("missing local overlay address")?;
    let mut config = format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = {address}\nListenPort = {}\n",
        state.listen_port
    );
    for peer in &state.peers {
        config.push_str("\n[Peer]\n");
        config.push_str(&format!("PublicKey = {}\n", peer.wireguard_public_key));
        config.push_str(&format!("AllowedIPs = {}\n", peer.address));
        if let Some(host) = &peer.endpoint_host {
            config.push_str(&format!("Endpoint = {}:{}\n", host, peer.endpoint_port));
        }
        config.push_str("PersistentKeepalive = 25\n");
    }
    Ok(config)
}

fn wireguard_config_path() -> Result<PathBuf, io::Error> {
    let dir = state_path()?
        .parent()
        .ok_or_else(|| io::Error::other("invalid state path"))?
        .to_path_buf();
    Ok(dir.join("pubkegaard.conf"))
}

fn run_wg_quick_up(path: &Path) -> Result<(), String> {
    run_admin_shell(&format!(
        "wg-quick down {} >/dev/null 2>&1 || true; wg-quick up {}",
        shell_quote(path),
        shell_quote(path)
    ))
}

fn run_wg_quick_down() -> Result<(), String> {
    match wireguard_config_path() {
        Ok(path) if path.exists() => run_admin_shell(&format!(
            "wg-quick down {} >/dev/null 2>&1 || true",
            shell_quote(&path)
        )),
        _ => Ok(()),
    }
}

fn command_exists(command: &str) -> bool {
    Command::new("sh")
        .arg("-lc")
        .arg(format!("command -v {command} >/dev/null 2>&1"))
        .status()
        .is_ok_and(|status| status.success())
}

fn run_admin_shell(script: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let escaped = script.replace('\\', "\\\\").replace('"', "\\\"");
        let status = Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "do shell script \"{escaped}\" with administrator privileges"
            ))
            .status()
            .map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("administrator command failed with status {status}"))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let status = Command::new("sh")
            .arg("-lc")
            .arg(script)
            .status()
            .map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("command failed with status {status}"))
        }
    }
}

fn shell_quote(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_state,
            complete_onboarding,
            import_peer_profile,
            export_peer_profile,
            remove_peer,
            emergency_stop,
            verify_wireguard_tools,
            apply_wireguard,
            stop_wireguard,
            start_ring_auth,
            store_ring_session
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Pubkegaard desktop app");
}
