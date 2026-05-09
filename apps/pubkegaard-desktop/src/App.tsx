import { useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

type AppState = {
  identity: string | null;
  deviceLabel: string;
  noiseControlPublicKey: string | null;
  wireguardPublicKey: string | null;
  localAddress: string | null;
  listenPort: number;
  endpointHost: string | null;
  homeserverUrl: string | null;
  pkarrPointer: string | null;
  discoveryPublished: boolean;
  wireguardState: 'not_configured' | 'stopped' | 'running';
  sessionMode: 'none' | 'ring_session' | 'local_keys';
  peers: Peer[];
  warnings: string[];
};

type Peer = {
  identity: string;
  label: string | null;
  preset: PeerPreset;
  wireguardPublicKey: string;
  address: string;
  endpointHost: string | null;
  endpointPort: number;
  connectionState: 'resolving' | 'direct' | 'relayed' | 'degraded' | 'stopped';
};

type PeerPreset = 'mesh' | 'relay_client' | 'relay_server' | 'exit_client' | 'exit_server' | 'lan_share';

const presetLabels: Record<PeerPreset, string> = {
  mesh: 'Private mesh only',
  relay_client: 'Use this peer as relay',
  relay_server: 'Let this peer relay encrypted packets through me',
  exit_client: 'Use this peer as VPN exit',
  exit_server: 'Let this peer use me as VPN exit',
  lan_share: 'Share selected LAN routes',
};

const initialState: AppState = {
  identity: null,
  deviceLabel: 'This device',
  noiseControlPublicKey: null,
  wireguardPublicKey: null,
  localAddress: null,
  listenPort: 51820,
  endpointHost: null,
  homeserverUrl: null,
  pkarrPointer: null,
  discoveryPublished: false,
  wireguardState: 'not_configured',
  sessionMode: 'none',
  peers: [],
  warnings: ['Onboarding has not completed.'],
};

export function App() {
  const [appState, setAppState] = useState<AppState>(initialState);
  const [activeView, setActiveView] = useState<'onboarding' | 'dashboard' | 'peers' | 'network' | 'safety' | 'settings'>('onboarding');
  const [peerProfileJson, setPeerProfileJson] = useState('');
  const [peerPubky, setPeerPubky] = useState('');
  const [exportedProfile, setExportedProfile] = useState('');
  const [endpointHost, setEndpointHost] = useState('');
  const [endpointPort, setEndpointPort] = useState(51820);
  const [homeserverUrl, setHomeserverUrl] = useState('');
  const [sessionToken, setSessionToken] = useState('');
  const [publishedPointer, setPublishedPointer] = useState('');
  const [peerPreset, setPeerPreset] = useState<PeerPreset>('mesh');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadState();
  }, []);

  const riskyActive = useMemo(
    () => appState.peers.some((peer) => peer.preset === 'relay_server' || peer.preset === 'exit_client' || peer.preset === 'exit_server' || peer.preset === 'lan_share'),
    [appState.peers],
  );

  async function loadState() {
    setError(null);
    try {
      setAppState(await invoke<AppState>('load_state'));
    } catch (err) {
      setError(String(err));
    }
  }

  async function completeOnboarding(mode: AppState['sessionMode']) {
    setError(null);
    try {
      const next = await invoke<AppState>('complete_onboarding', { mode });
      setAppState(next);
      setActiveView('dashboard');
    } catch (err) {
      setError(String(err));
    }
  }

  async function importPeerProfile() {
    if (!peerProfileJson.trim()) return;
    setError(null);
    try {
      const next = await invoke<AppState>('import_peer_profile', {
        profileJson: peerProfileJson.trim(),
        preset: peerPreset,
      });
      setAppState(next);
      setPeerProfileJson('');
    } catch (err) {
      setError(String(err));
    }
  }

  async function addPeerByPubky() {
    if (!peerPubky.trim()) return;
    setError(null);
    try {
      const next = await invoke<AppState>('add_peer_by_pubky', {
        identity: peerPubky.trim(),
        preset: peerPreset,
      });
      setAppState(next);
      setPeerPubky('');
    } catch (err) {
      setError(String(err));
    }
  }

  async function exportPeerProfile() {
    setError(null);
    try {
      const profile = await invoke<string>('export_peer_profile', {
        endpointHost: endpointHost.trim() || null,
        endpointPort,
      });
      setExportedProfile(profile);
      await loadState();
    } catch (err) {
      setError(String(err));
    }
  }

  async function configureHomeserver() {
    setError(null);
    try {
      setAppState(await invoke<AppState>('configure_homeserver', {
        homeserverUrl,
        sessionToken,
      }));
      setSessionToken('');
    } catch (err) {
      setError(String(err));
    }
  }

  async function publishDiscovery() {
    setError(null);
    try {
      const result = await invoke<{ documentUrl: string; pkarrPointer: string }>('publish_discovery');
      setPublishedPointer(result.pkarrPointer);
      await loadState();
    } catch (err) {
      setError(String(err));
    }
  }

  async function removePeer(identity: string) {
    setError(null);
    try {
      setAppState(await invoke<AppState>('remove_peer', { identity }));
    } catch (err) {
      setError(String(err));
    }
  }

  async function emergencyStop() {
    setError(null);
    try {
      setAppState(await invoke<AppState>('emergency_stop'));
      setActiveView('dashboard');
    } catch (err) {
      setError(String(err));
    }
  }

  async function applyWireGuard() {
    setError(null);
    try {
      setAppState(await invoke<AppState>('apply_wireguard'));
      setActiveView('network');
    } catch (err) {
      setError(String(err));
    }
  }

  async function stopWireGuard() {
    setError(null);
    try {
      setAppState(await invoke<AppState>('stop_wireguard'));
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <h1>Pubkegaard</h1>
        <button onClick={() => setActiveView('onboarding')}>Onboarding</button>
        <button onClick={() => setActiveView('dashboard')}>Dashboard</button>
        <button onClick={() => setActiveView('peers')}>Peers</button>
        <button onClick={() => setActiveView('network')}>Network</button>
        <button onClick={() => setActiveView('safety')}>Safety</button>
        <button onClick={() => setActiveView('settings')}>Settings</button>
        {riskyActive && <button className="danger" onClick={emergencyStop}>Emergency stop</button>}
      </aside>

      <section className="content">
        {error && <div className="error">{error}</div>}
        {activeView === 'onboarding' && <Onboarding onComplete={completeOnboarding} />}
        {activeView === 'dashboard' && <Dashboard appState={appState} />}
        {activeView === 'peers' && (
          <Peers
            appState={appState}
            peerProfileJson={peerProfileJson}
            peerPreset={peerPreset}
            exportedProfile={exportedProfile}
            endpointHost={endpointHost}
            endpointPort={endpointPort}
            peerPubky={peerPubky}
            onPeerProfileJsonChange={setPeerProfileJson}
            onPeerPubkyChange={setPeerPubky}
            onPeerPresetChange={setPeerPreset}
            onEndpointHostChange={setEndpointHost}
            onEndpointPortChange={setEndpointPort}
            onExportPeerProfile={exportPeerProfile}
            onImportPeerProfile={importPeerProfile}
            onAddPeerByPubky={addPeerByPubky}
            onRemovePeer={removePeer}
          />
        )}
        {activeView === 'network' && (
          <NetworkView
            appState={appState}
            onApplyWireGuard={applyWireGuard}
            onStopWireGuard={stopWireGuard}
          />
        )}
        {activeView === 'safety' && <SafetyView riskyActive={riskyActive} onEmergencyStop={emergencyStop} />}
        {activeView === 'settings' && (
          <Settings
            appState={appState}
            homeserverUrl={homeserverUrl}
            sessionToken={sessionToken}
            publishedPointer={publishedPointer}
            onHomeserverUrlChange={setHomeserverUrl}
            onSessionTokenChange={setSessionToken}
            onConfigureHomeserver={configureHomeserver}
            onPublishDiscovery={publishDiscovery}
          />
        )}
      </section>
    </main>
  );
}

function Onboarding({ onComplete }: { onComplete: (mode: AppState['sessionMode']) => Promise<void> }) {
  return (
    <section>
      <h2>Connect trusted Pubky peers over WireGuard</h2>
      <p>Pubkegaard creates a local control key and a WireGuard transport key, then publishes a discovery record for peers you approve.</p>
      <div className="card-grid">
        <button className="card" onClick={() => onComplete('local_keys')}>
          <strong>Create local Pubkegaard keys</strong>
          <span>Full mode with binding, discovery, revoke, and mesh support.</span>
        </button>
        <button className="card" onClick={() => onComplete('ring_session')}>
          <strong>Connect Pubky Ring session</strong>
          <span>Homeserver storage only. PKARR-bound control-key authorization may require a later approval step.</span>
        </button>
      </div>
    </section>
  );
}

function Dashboard({ appState }: { appState: AppState }) {
  return (
    <section>
      <h2>Dashboard</h2>
      <div className="status-grid">
        <Status label="Identity" value={appState.identity ?? 'Binding required'} />
        <Status label="Device" value={appState.deviceLabel} />
        <Status label="Overlay address" value={appState.localAddress ?? 'Not assigned'} />
        <Status label="Control key" value={appState.noiseControlPublicKey ? 'Generated' : 'Not generated'} />
        <Status label="WireGuard key" value={appState.wireguardPublicKey ? 'Generated' : 'Not generated'} />
        <Status label="Discovery" value={appState.discoveryPublished ? 'Published' : 'Not published'} />
        <Status label="WireGuard" value={appState.wireguardState} />
        <Status label="Peers" value={String(appState.peers.length)} />
        <Status label="Session" value={appState.sessionMode} />
        <Status label="Homeserver" value={appState.homeserverUrl ?? 'Not configured'} />
        <Status label="PKARR pointer" value={appState.pkarrPointer ? 'Published' : 'Not published'} />
      </div>
      {appState.warnings.length > 0 && (
        <div className="warning">
          <h3>Warnings</h3>
          {appState.warnings.map((warning) => <p key={warning}>{warning}</p>)}
        </div>
      )}
    </section>
  );
}

function Peers(props: {
  appState: AppState;
  peerProfileJson: string;
  peerPreset: PeerPreset;
  exportedProfile: string;
  endpointHost: string;
  endpointPort: number;
  peerPubky: string;
  onPeerProfileJsonChange: (value: string) => void;
  onPeerPubkyChange: (value: string) => void;
  onPeerPresetChange: (value: PeerPreset) => void;
  onEndpointHostChange: (value: string) => void;
  onEndpointPortChange: (value: number) => void;
  onExportPeerProfile: () => Promise<void>;
  onImportPeerProfile: () => Promise<void>;
  onAddPeerByPubky: () => Promise<void>;
  onRemovePeer: (identity: string) => Promise<void>;
}) {
  return (
    <section>
      <h2>Peers</h2>
      <div className="panel">
        <h3>Your peer profile</h3>
        <p>Share this JSON with the other Pubkegaard user. Set an endpoint if they should initiate directly to your public/LAN host.</p>
        <div className="form-row">
          <input value={props.endpointHost} placeholder="Advertised endpoint host or IP" onChange={(event) => props.onEndpointHostChange(event.target.value)} />
          <input type="number" value={props.endpointPort} min={1} max={65535} onChange={(event) => props.onEndpointPortChange(Number(event.target.value))} />
          <button onClick={props.onExportPeerProfile}>Export profile</button>
        </div>
        {props.exportedProfile && <textarea readOnly value={props.exportedProfile} />}
      </div>

      <div className="panel">
        <h3>Add peer by Pubky discovery</h3>
        <p>Paste a Pubky identity. Pubkegaard resolves its `_pubkegaard` PKARR pointer, fetches the discovery document, and imports the advertised WireGuard device.</p>
        <div className="form-row">
          <input value={props.peerPubky} placeholder="Pubky identity" onChange={(event) => props.onPeerPubkyChange(event.target.value)} />
          <select value={props.peerPreset} onChange={(event) => props.onPeerPresetChange(event.target.value as PeerPreset)}>
            {Object.entries(presetLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
          <button onClick={props.onAddPeerByPubky}>Resolve and add</button>
        </div>
      </div>

      <div className="panel">
        <h3>Add peer profile manually</h3>
        <p>Manual profile exchange remains useful when the peer has not published discovery yet.</p>
        <textarea value={props.peerProfileJson} placeholder="Paste the other user's Pubkegaard peer profile JSON" onChange={(event) => props.onPeerProfileJsonChange(event.target.value)} />
        <select value={props.peerPreset} onChange={(event) => props.onPeerPresetChange(event.target.value as PeerPreset)}>
          {Object.entries(presetLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <button onClick={props.onImportPeerProfile}>Import peer</button>
      </div>

      {props.appState.peers.map((peer) => (
        <article className="peer-card" key={peer.identity}>
          <div>
            <strong>{peer.label ?? peer.identity}</strong>
            <p>{presetLabels[peer.preset]} · {peer.connectionState}</p>
            <p>{peer.address} · {peer.endpointHost ? `${peer.endpointHost}:${peer.endpointPort}` : 'no endpoint advertised'}</p>
          </div>
          <button onClick={() => props.onRemovePeer(peer.identity)}>Revoke</button>
        </article>
      ))}
    </section>
  );
}

function NetworkView({
  appState,
  onApplyWireGuard,
  onStopWireGuard,
}: {
  appState: AppState;
  onApplyWireGuard: () => Promise<void>;
  onStopWireGuard: () => Promise<void>;
}) {
  return (
    <section>
      <h2>Network</h2>
      <p>WireGuard state: {appState.wireguardState}</p>
      <p>Local address: {appState.localAddress ?? 'not assigned'}</p>
      <div className="actions">
        <button onClick={onApplyWireGuard}>Apply WireGuard tunnel</button>
        <button onClick={onStopWireGuard}>Stop WireGuard</button>
      </div>
      {appState.peers.map((peer) => (
        <article className="peer-card" key={peer.identity}>
          <strong>{peer.identity}</strong>
          <p>Connection: {peer.connectionState}</p>
          <p>Grant: {presetLabels[peer.preset]}</p>
          <p>Allowed IP: {peer.address}</p>
        </article>
      ))}
    </section>
  );
}

function SafetyView({ riskyActive, onEmergencyStop }: { riskyActive: boolean; onEmergencyStop: () => Promise<void> }) {
  return (
    <section>
      <h2>Safety</h2>
      <p>Exit mode and LAN sharing change who can route traffic through your machine. Pubkegaard keeps those permissions explicit and revocable.</p>
      <button className="danger" disabled={!riskyActive} onClick={onEmergencyStop}>Emergency stop</button>
    </section>
  );
}

function Settings(props: {
  appState: AppState;
  homeserverUrl: string;
  sessionToken: string;
  publishedPointer: string;
  onHomeserverUrlChange: (value: string) => void;
  onSessionTokenChange: (value: string) => void;
  onConfigureHomeserver: () => Promise<void>;
  onPublishDiscovery: () => Promise<void>;
}) {
  return (
    <section>
      <h2>Settings</h2>
      <div className="panel">
        <h3>Homeserver publishing</h3>
        <p>Configure a homeserver session, then publish your discovery document and `_pubkegaard` PKARR pointer.</p>
        <div className="form-row">
          <input value={props.homeserverUrl} placeholder="https://homeserver.example" onChange={(event) => props.onHomeserverUrlChange(event.target.value)} />
          <input value={props.sessionToken} type="password" placeholder="Pubky session token" onChange={(event) => props.onSessionTokenChange(event.target.value)} />
          <button onClick={props.onConfigureHomeserver}>Save session</button>
        </div>
        <button onClick={props.onPublishDiscovery}>Publish discovery + PKARR pointer</button>
        {(props.publishedPointer || props.appState.pkarrPointer) && <textarea readOnly value={props.publishedPointer || props.appState.pkarrPointer || ''} />}
      </div>
      <Status label="Key vault" value={props.appState.sessionMode === 'local_keys' ? 'Local keys enabled' : 'Session limited'} />
      <Status label="Homeserver" value={props.appState.homeserverUrl ?? 'Not configured'} />
      <Status label="Discovery path" value="/pub/pubkegaard/v1/discovery.json" />
      <Status label="Overlay range" value="100.88.0.0/16" />
      <Status label="Kill switch" value="Required before exit release" />
    </section>
  );
}

function Status({ label, value }: { label: string; value: string }) {
  return (
    <div className="status-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
