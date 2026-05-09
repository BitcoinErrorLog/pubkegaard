use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use simple_dns::rdata::RData;

const BORINGTUN_INTERFACE: &str = "utun88";
const BORINGTUN_SOCKET: &str = "/var/run/wireguard/utun88.sock";

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
    homeserver_url: Option<String>,
    pkarr_pointer: Option<String>,
    discovery_published: bool,
    wireguard_state: WireGuardState,
    #[serde(default)]
    wireguard_backend_pid: Option<u32>,
    #[serde(default)]
    wireguard_interface: Option<String>,
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
    bundled_backend: bool,
    details: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveryPublishResult {
    document_url: String,
    pkarr_pointer: String,
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
            homeserver_url: None,
            pkarr_pointer: None,
            discovery_published: false,
            wireguard_state: WireGuardState::NotConfigured,
            wireguard_backend_pid: None,
            wireguard_interface: None,
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
fn configure_homeserver(homeserver_url: String, session_token: String) -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    let identity = state
        .identity
        .clone()
        .ok_or("complete onboarding before configuring homeserver")?;
    let url = normalize_homeserver_url(&homeserver_url)?;
    if session_token.trim().is_empty() {
        return Err("session token is required".to_string());
    }
    store_secret("homeserver-session-token", session_token.trim())
        .map_err(|error| error.to_string())?;
    state.homeserver_url = Some(url);
    state.session_mode = SessionMode::LocalKeys;
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    let _ = identity;
    Ok(state)
}

#[tauri::command]
fn publish_discovery() -> Result<DiscoveryPublishResult, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    let document = discovery_document_from_state(&state)?;
    let homeserver_url = state
        .homeserver_url
        .clone()
        .ok_or("configure homeserver before publishing discovery")?;
    let identity = state.identity.clone().ok_or("missing Pubky identity")?;
    let token = load_secret("homeserver-session-token")?;
    let document_url = format!(
        "{}/pub/pubkegaard/v1/discovery.json",
        homeserver_url.trim_end_matches('/')
    );
    let body = serde_json::to_vec_pretty(&document).map_err(|error| error.to_string())?;
    let response = reqwest::blocking::Client::new()
        .put(&document_url)
        .header(reqwest::header::COOKIE, format!("{identity}={token}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "homeserver publish failed with {}",
            response.status()
        ));
    }

    let pointer = pubkegaard_discovery::CompactPointer::new(
        document_url.clone(),
        document.hash_hex().map_err(|error| error.to_string())?,
        document.sequence,
        document.expires_at_ms,
    );
    let pointer_text = pointer.render();
    publish_pkarr_pointer(&pointer_text)?;
    state.pkarr_pointer = Some(pointer_text.clone());
    state.discovery_published = true;
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(DiscoveryPublishResult {
        document_url,
        pkarr_pointer: pointer_text,
    })
}

#[tauri::command]
fn add_peer_by_pubky(identity: String, preset: PeerPreset) -> Result<AppState, String> {
    let identity = pubkegaard_types::PubkyId::parse(identity).map_err(|error| error.to_string())?;
    let document = resolve_peer_discovery(&identity)?;
    let device = document
        .devices
        .first()
        .ok_or("resolved discovery document has no devices")?;
    let endpoint = device.endpoints.first();
    let mut state = read_state().map_err(|error| error.to_string())?;
    if state
        .peers
        .iter()
        .any(|peer| peer.identity == identity.as_str())
    {
        return Err("peer already exists".to_string());
    }
    state.peers.push(Peer {
        identity: identity.to_string(),
        label: Some(device.device_id.clone()),
        preset,
        wireguard_public_key: device.wg_public_key.as_base64().to_string(),
        address: device
            .addresses
            .first()
            .ok_or("peer has no overlay address")?
            .to_string(),
        endpoint_host: endpoint.map(|endpoint| endpoint.host.clone()),
        endpoint_port: endpoint.map(|endpoint| endpoint.port).unwrap_or(51820),
        connection_state: ConnectionState::Stopped,
    });
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn remove_peer(identity: String) -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    let removed_routes = state
        .peers
        .iter()
        .filter(|peer| peer.identity == identity)
        .map(|peer| peer.address.clone())
        .collect::<Vec<_>>();
    state.peers.retain(|peer| peer.identity != identity);
    if state.wireguard_state == WireGuardState::Running {
        for route in removed_routes {
            let _ = remove_peer_route(&route);
        }
        if state.peers.is_empty() {
            let _ = stop_bundled_wireguard_backend();
            state.wireguard_state = WireGuardState::Stopped;
            state.wireguard_backend_pid = None;
            state.wireguard_interface = None;
        } else {
            configure_bundled_wireguard(&state)?;
        }
    }
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn emergency_stop() -> Result<AppState, String> {
    let _ = stop_bundled_wireguard_backend();
    let mut state = read_state().map_err(|error| error.to_string())?;
    state.wireguard_state = WireGuardState::Stopped;
    state.wireguard_backend_pid = None;
    state.wireguard_interface = None;
    for peer in &mut state.peers {
        let _ = remove_peer_route(&peer.address);
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
    let bundled_backend = bundled_wireguard_backend_path().is_ok();
    let details = if bundled_backend {
        "Bundled WireGuard backend is available.".to_string()
    } else {
        "Bundled WireGuard backend is missing from the app bundle.".to_string()
    };
    ToolStatus {
        bundled_backend,
        details,
    }
}

#[tauri::command]
fn apply_wireguard() -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    ensure_ready_for_wireguard(&state)?;
    stop_bundled_wireguard_backend()?;
    start_bundled_wireguard_backend()?;
    configure_bundled_wireguard(&state)?;
    configure_interface_address(&state)?;
    configure_peer_routes(&state)?;
    state.wireguard_state = WireGuardState::Running;
    state.wireguard_backend_pid = boringtun_pid();
    state.wireguard_interface = Some(BORINGTUN_INTERFACE.to_string());
    for peer in &mut state.peers {
        peer.connection_state = ConnectionState::Direct;
    }
    state.warnings = warnings_for(&state);
    write_state(&state).map_err(|error| error.to_string())?;
    Ok(state)
}

#[tauri::command]
fn stop_wireguard() -> Result<AppState, String> {
    let mut state = read_state().map_err(|error| error.to_string())?;
    for peer in &state.peers {
        let _ = remove_peer_route(&peer.address);
    }
    stop_bundled_wireguard_backend()?;
    state.wireguard_state = WireGuardState::Stopped;
    state.wireguard_backend_pid = None;
    state.wireguard_interface = None;
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
    if state.homeserver_url.is_none() {
        warnings.push(
            "Homeserver session is not configured; discovery cannot be published.".to_string(),
        );
    }
    if !state.discovery_published {
        warnings.push("Discovery has not been published to homeserver/PKARR yet.".to_string());
    }
    if !verify_wireguard_tools().bundled_backend {
        warnings.push("Bundled WireGuard backend is missing from the app bundle.".to_string());
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

fn discovery_document_from_state(
    state: &AppState,
) -> Result<pubkegaard_types::DiscoveryDocument, String> {
    let identity =
        pubkegaard_types::PubkyId::parse(state.identity.clone().ok_or("missing Pubky identity")?)
            .map_err(|error| error.to_string())?;
    let noise_control_key = pubkegaard_types::NoiseControlPublicKey::parse(
        state
            .noise_control_public_key
            .clone()
            .ok_or("missing noise control key")?,
    )
    .map_err(|error| error.to_string())?;
    let wg_public_key = pubkegaard_types::WireGuardPublicKey::parse(
        state
            .wireguard_public_key
            .clone()
            .ok_or("missing WireGuard public key")?,
    )
    .map_err(|error| error.to_string())?;
    let address = state
        .local_address
        .clone()
        .ok_or("missing local overlay address")?
        .parse()
        .map_err(|error| format!("invalid local address: {error}"))?;
    let mut endpoints = Vec::new();
    if let Some(host) = &state.endpoint_host {
        endpoints.push(pubkegaard_types::Endpoint {
            host: host.clone(),
            port: state.listen_port,
            priority: 10,
        });
    }
    let now = now_ms()?;
    Ok(pubkegaard_types::DiscoveryDocument {
        r#type: pubkegaard_types::DISCOVERY_TYPE.to_string(),
        version: pubkegaard_types::VERSION_1,
        identity,
        sequence: now,
        created_at_ms: now,
        expires_at_ms: now + 86_400_000,
        devices: vec![pubkegaard_types::Device {
            device_id: state.device_label.clone(),
            noise_control_key,
            wg_public_key,
            addresses: vec![address],
            endpoints,
            routes: Vec::new(),
            capabilities: pubkegaard_types::Permissions {
                mesh: true,
                ..pubkegaard_types::Permissions::default()
            },
        }],
    })
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

fn publish_pkarr_pointer(pointer_text: &str) -> Result<(), String> {
    let keypair = load_pubky_keypair()?;
    let existing: Option<pkarr::SignedPacket> = tauri::async_runtime::block_on(async {
        let client = pkarr::Client::builder()
            .build()
            .map_err(|error| error.to_string())?;
        Ok::<Option<pkarr::SignedPacket>, String>(
            client.resolve_most_recent(&keypair.public_key()).await,
        )
    })?;
    let mut builder = pkarr::SignedPacket::builder();
    if let Some(existing) = &existing {
        for record in existing.all_resource_records() {
            let name = record.name.to_string();
            if !name.starts_with("_pubkegaard.") {
                builder = builder.record(record.clone());
            }
        }
    }
    let signed = builder
        .txt(
            "_pubkegaard"
                .try_into()
                .map_err(|error| format!("{error}"))?,
            pointer_text
                .try_into()
                .map_err(|error| format!("{error}"))?,
            300,
        )
        .sign(&keypair)
        .map_err(|error| error.to_string())?;
    tauri::async_runtime::block_on(async {
        pkarr::Client::builder()
            .build()
            .map_err(|error| error.to_string())?
            .publish(&signed, existing.map(|packet| packet.timestamp()))
            .await
            .map_err(|error| error.to_string())
    })
}

fn resolve_peer_discovery(
    identity: &pubkegaard_types::PubkyId,
) -> Result<pubkegaard_types::DiscoveryDocument, String> {
    let public_key =
        pkarr::PublicKey::try_from(identity.as_str()).map_err(|error| error.to_string())?;
    let packet = tauri::async_runtime::block_on(async {
        pkarr::Client::builder()
            .build()
            .map_err(|error| error.to_string())?
            .resolve_most_recent(&public_key)
            .await
            .ok_or_else(|| "no PKARR packet found for peer".to_string())
    })?;
    let pointer_text = packet
        .fresh_resource_records("_pubkegaard")
        .find_map(|record| match &record.rdata {
            RData::TXT(txt) => txt
                .attributes()
                .get("v")
                .and(Some(record))
                .map(|_| txt_to_pointer(txt)),
            _ => None,
        })
        .flatten()
        .ok_or("peer has no fresh _pubkegaard TXT pointer")?;
    let pointer = pointer_text
        .parse::<pubkegaard_discovery::CompactPointer>()
        .map_err(|error| error.to_string())?;
    let bytes = reqwest::blocking::get(&pointer.document_uri)
        .map_err(|error| error.to_string())?
        .bytes()
        .map_err(|error| error.to_string())?;
    pubkegaard_discovery::verify_document_bytes(&pointer, &bytes, identity, now_ms()?, None)
        .map_err(|error| error.to_string())
}

fn txt_to_pointer(txt: &simple_dns::rdata::TXT<'_>) -> Option<String> {
    let attrs = txt.attributes();
    let version = attrs.get("v")?.as_ref()?;
    let doc = attrs.get("doc")?.as_ref()?;
    let hash = attrs.get("h")?.as_ref()?;
    let sequence = attrs.get("seq")?.as_ref()?;
    let expiry = attrs.get("exp")?.as_ref()?;
    Some(format!(
        "v={version};doc={doc};h={hash};seq={sequence};exp={expiry}"
    ))
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

fn load_pubky_keypair() -> Result<pkarr::Keypair, String> {
    let secret = STANDARD
        .decode(load_secret("pubky-root-private-key")?)
        .map_err(|error| error.to_string())?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| "invalid stored Pubky root key".to_string())?;
    Ok(pkarr::Keypair::from_secret_key(&secret))
}

fn normalize_homeserver_url(input: &str) -> Result<String, String> {
    let trimmed = input.trim().trim_end_matches('/');
    if !trimmed.starts_with("https://") {
        return Err("homeserver URL must start with https://".to_string());
    }
    Ok(trimmed.to_string())
}

fn now_ms() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis() as u64)
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
    if !tools.bundled_backend {
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

fn bundled_wireguard_backend_path() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("PUBKEGAARD_BORINGTUN_PATH").map(PathBuf::from) {
        if path.exists() {
            return Ok(path);
        }
    }

    let binary_name = bundled_wireguard_binary_name();
    let candidates = [
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|parent| parent.join("boringtun-cli"))),
        std::env::current_exe().ok().and_then(|path| {
            path.parent()
                .and_then(|macos| macos.parent())
                .map(|contents| {
                    contents
                        .join("Resources")
                        .join("boringtun-cli-aarch64-apple-darwin")
                })
        }),
        Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("binaries")
                .join("boringtun-cli-aarch64-apple-darwin"),
        ),
        Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("binaries")
                .join(binary_name),
        ),
    ];

    candidates
        .into_iter()
        .flatten()
        .find(|path| path.exists())
        .ok_or_else(|| "bundled WireGuard backend not found".to_string())
}

fn bundled_wireguard_binary_name() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "boringtun-cli-aarch64-apple-darwin"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "boringtun-cli-x86_64-apple-darwin"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "boringtun-cli"
    }
}

fn start_bundled_wireguard_backend() -> Result<(), String> {
    let backend = bundled_wireguard_backend_path()?;
    let log = state_path()
        .map_err(|error| error.to_string())?
        .parent()
        .ok_or_else(|| "invalid state path".to_string())?
        .join("boringtun.log");
    let user = std::env::var("USER").unwrap_or_else(|_| "nobody".to_string());
    let script = format!(
        "mkdir -p /var/run/wireguard; rm -f {socket}; USER={user} {backend} --log {log} {interface}; for i in 1 2 3 4 5 6 7 8 9 10; do if [ -S {socket} ]; then chmod 666 {socket}; exit 0; fi; sleep 0.1; done; exit 1",
        socket = BORINGTUN_SOCKET,
        user = shell_quote_text(&user),
        backend = shell_quote(&backend),
        log = shell_quote(&log),
        interface = BORINGTUN_INTERFACE
    );
    run_admin_shell(&script)?;
    wait_for_uapi_socket()
}

fn stop_bundled_wireguard_backend() -> Result<(), String> {
    run_admin_shell(&format!(
        "pkill -f {} >/dev/null 2>&1 || true; rm -f {}",
        shell_quote_text(&format!("boringtun-cli.*{BORINGTUN_INTERFACE}")),
        BORINGTUN_SOCKET
    ))
}

fn configure_bundled_wireguard(state: &AppState) -> Result<(), String> {
    let private_key = load_secret("wireguard-private-key")?;
    let command = render_wireguard_uapi_set(state, &private_key)?;
    send_wireguard_uapi(&command)
}

fn wait_for_uapi_socket() -> Result<(), String> {
    let socket = Path::new(BORINGTUN_SOCKET);
    for _ in 0..50 {
        if socket.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("bundled WireGuard backend did not expose its UAPI socket".to_string())
}

fn send_wireguard_uapi(command: &str) -> Result<(), String> {
    let mut stream = UnixStream::connect(BORINGTUN_SOCKET).map_err(|error| error.to_string())?;
    stream
        .write_all(command.as_bytes())
        .map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    while reader
        .read_line(&mut line)
        .map_err(|error| error.to_string())?
        > 0
    {
        if let Some(errno) = line.strip_prefix("errno=") {
            let errno = errno.trim();
            if errno == "0" {
                return Ok(());
            }
            return Err(format!(
                "bundled WireGuard backend rejected config with errno {errno}"
            ));
        }
        line.clear();
    }
    Err("bundled WireGuard backend did not return UAPI status".to_string())
}

fn render_wireguard_uapi_set(state: &AppState, private_key_base64: &str) -> Result<String, String> {
    let mut command = format!(
        "set=1\nprivate_key={}\nlisten_port={}\nreplace_peers=true\n",
        base64_key_to_hex(private_key_base64)?,
        state.listen_port
    );
    for peer in &state.peers {
        command.push_str(&format!(
            "public_key={}\n",
            base64_key_to_hex(&peer.wireguard_public_key)?
        ));
        command.push_str("replace_allowed_ips=true\n");
        command.push_str(&format!("allowed_ip={}\n", peer.address));
        if let Some(endpoint) = peer_endpoint(peer)? {
            command.push_str(&format!("endpoint={endpoint}\n"));
        }
        command.push_str("persistent_keepalive_interval=25\n");
    }
    command.push('\n');
    Ok(command)
}

fn base64_key_to_hex(key: &str) -> Result<String, String> {
    let bytes = STANDARD.decode(key).map_err(|error| error.to_string())?;
    if bytes.len() != 32 {
        return Err("WireGuard keys must be 32 bytes".to_string());
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn peer_endpoint(peer: &Peer) -> Result<Option<SocketAddr>, String> {
    let Some(host) = &peer.endpoint_host else {
        return Ok(None);
    };
    (host.as_str(), peer.endpoint_port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve peer endpoint {host}: {error}"))?
        .next()
        .ok_or_else(|| format!("peer endpoint {host} resolved to no addresses"))
        .map(Some)
}

fn configure_interface_address(state: &AppState) -> Result<(), String> {
    let address = state
        .local_address
        .as_ref()
        .ok_or_else(|| "missing local overlay address".to_string())?
        .parse::<ipnet::IpNet>()
        .map_err(|error| error.to_string())?;
    let ip = match address.addr() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err(
                "macOS bundled backend currently supports IPv4 overlay addresses".to_string(),
            )
        }
    };
    run_admin_shell(&format!(
        "ifconfig {interface} inet {ip} {ip} netmask 255.255.255.255 mtu 1420 up",
        interface = BORINGTUN_INTERFACE
    ))
}

fn configure_peer_routes(state: &AppState) -> Result<(), String> {
    for peer in &state.peers {
        add_peer_route(&peer.address)?;
    }
    Ok(())
}

fn add_peer_route(address: &str) -> Result<(), String> {
    let ip = route_ip(address)?;
    run_admin_shell(&format!(
        "route -n delete -host {ip} >/dev/null 2>&1 || true; route -n add -host {ip} -interface {interface}",
        interface = BORINGTUN_INTERFACE
    ))
}

fn remove_peer_route(address: &str) -> Result<(), String> {
    let ip = route_ip(address)?;
    run_admin_shell(&format!(
        "route -n delete -host {ip} >/dev/null 2>&1 || true"
    ))
}

fn route_ip(address: &str) -> Result<Ipv4Addr, String> {
    match address
        .parse::<ipnet::IpNet>()
        .map_err(|error| error.to_string())?
        .addr()
    {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => {
            Err("macOS bundled backend currently supports IPv4 peer routes".to_string())
        }
    }
}

fn boringtun_pid() -> Option<u32> {
    let output = Command::new("pgrep")
        .arg("-f")
        .arg(format!("boringtun-cli.*{BORINGTUN_INTERFACE}"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.trim().parse::<u32>().ok())
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
    shell_quote_text(&value)
}

fn shell_quote_text(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        AppState {
            identity: Some("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo".to_string()),
            device_label: "test-mac".to_string(),
            noise_control_public_key: Some(
                "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=".to_string(),
            ),
            wireguard_public_key: Some("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_string()),
            local_address: Some("100.88.1.10/32".to_string()),
            listen_port: 51820,
            endpoint_host: Some("198.51.100.7".to_string()),
            homeserver_url: Some("https://homeserver.example".to_string()),
            pkarr_pointer: None,
            discovery_published: false,
            wireguard_state: WireGuardState::Stopped,
            wireguard_backend_pid: None,
            wireguard_interface: None,
            session_mode: SessionMode::LocalKeys,
            peers: vec![Peer {
                identity: "8ys9xm3n8s5kr41iiqt91jpan1sphgj9jf88ks9nujmbfkcpq6mo".to_string(),
                label: Some("peer-mac".to_string()),
                preset: PeerPreset::Mesh,
                wireguard_public_key: "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=".to_string(),
                address: "100.88.2.20/32".to_string(),
                endpoint_host: Some("203.0.113.20".to_string()),
                endpoint_port: 51820,
                connection_state: ConnectionState::Stopped,
            }],
            warnings: Vec::new(),
        }
    }

    #[test]
    fn discovery_document_contains_control_and_wireguard_keys() {
        let document = discovery_document_from_state(&test_state()).unwrap();
        let device = &document.devices[0];
        assert_eq!(
            document.identity.as_str(),
            "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"
        );
        assert_eq!(device.device_id, "test-mac");
        assert_eq!(
            device.noise_control_key.as_base64(),
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="
        );
        assert_eq!(
            device.wg_public_key.as_base64(),
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
        );
        assert_eq!(device.endpoints[0].host, "198.51.100.7");
    }

    #[test]
    fn wireguard_uapi_set_renders_bundled_backend_config() {
        let config = render_wireguard_uapi_set(
            &test_state(),
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        )
        .unwrap();
        assert!(config.starts_with("set=1\n"));
        assert!(config.contains(
            "private_key=0101010101010101010101010101010101010101010101010101010101010101"
        ));
        assert!(config.contains("listen_port=51820"));
        assert!(config.contains("replace_peers=true"));
        assert!(config.contains(
            "public_key=0808080808080808080808080808080808080808080808080808080808080808"
        ));
        assert!(config.contains("allowed_ip=100.88.2.20/32"));
        assert!(config.ends_with('\n'));
    }

    #[test]
    fn peer_profile_validation_rejects_bad_pubky_identity() {
        let profile = PeerProfile {
            version: 1,
            identity: "not-a-pubky".to_string(),
            device_label: "peer".to_string(),
            noise_control_public_key: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=".to_string(),
            wireguard_public_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_string(),
            address: "100.88.2.20/32".to_string(),
            endpoint_host: None,
            endpoint_port: 51820,
        };
        assert!(validate_peer_profile(&profile).is_err());
    }

    #[test]
    fn txt_pointer_round_trip_parses_pkarr_payload() {
        let txt = simple_dns::rdata::TXT::new()
            .with_string("v=pkg1")
            .unwrap()
            .with_string("doc=https://homeserver.example/pub/pubkegaard/v1/discovery.json")
            .unwrap()
            .with_string("h=b3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap()
            .with_string("seq=7")
            .unwrap()
            .with_string("exp=99")
            .unwrap();
        assert_eq!(
            txt_to_pointer(&txt).unwrap(),
            "v=pkg1;doc=https://homeserver.example/pub/pubkegaard/v1/discovery.json;h=b3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;seq=7;exp=99"
        );
    }

    #[test]
    fn shell_quote_handles_single_quotes() {
        assert_eq!(
            shell_quote(Path::new("/tmp/pubke'gaard.conf")),
            "'/tmp/pubke'\\''gaard.conf'"
        );
    }

    #[test]
    fn route_ip_rejects_ipv6_routes_for_macos_backend() {
        assert!(route_ip("fd00::1/128").is_err());
    }

    #[test]
    fn user_docs_do_not_require_external_wireguard_tools_on_macos() {
        let readme = include_str!("../../../../README.md");
        let macos_doc = include_str!("../../../../docs/macos-two-peer-dev.md");
        let preflight = include_str!("../../../../scripts/macos-two-peer-preflight.sh");
        for text in [readme, macos_doc, preflight] {
            assert!(!text.contains("brew install wireguard-tools"));
            assert!(!text.contains("wg-quick"));
        }
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            load_state,
            complete_onboarding,
            import_peer_profile,
            export_peer_profile,
            configure_homeserver,
            publish_discovery,
            add_peer_by_pubky,
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
