import { useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

type AppState = {
  identity: string | null;
  deviceLabel: string;
  noiseControlPublicKey: string | null;
  wireguardPublicKey: string | null;
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
  discoveryPublished: false,
  wireguardState: 'not_configured',
  sessionMode: 'none',
  peers: [],
  warnings: ['Onboarding has not completed.'],
};

export function App() {
  const [appState, setAppState] = useState<AppState>(initialState);
  const [activeView, setActiveView] = useState<'onboarding' | 'dashboard' | 'peers' | 'network' | 'safety' | 'settings'>('onboarding');
  const [peerIdentity, setPeerIdentity] = useState('');
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

  async function addPeer() {
    if (!peerIdentity.trim()) return;
    setError(null);
    try {
      const next = await invoke<AppState>('add_peer', {
        identity: peerIdentity.trim(),
        preset: peerPreset,
      });
      setAppState(next);
      setPeerIdentity('');
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
            peerIdentity={peerIdentity}
            peerPreset={peerPreset}
            onPeerIdentityChange={setPeerIdentity}
            onPeerPresetChange={setPeerPreset}
            onAddPeer={addPeer}
            onRemovePeer={removePeer}
          />
        )}
        {activeView === 'network' && <NetworkView peers={appState.peers} wireguardState={appState.wireguardState} />}
        {activeView === 'safety' && <SafetyView riskyActive={riskyActive} onEmergencyStop={emergencyStop} />}
        {activeView === 'settings' && <Settings appState={appState} />}
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
        <Status label="Control key" value={appState.noiseControlPublicKey ? 'Generated' : 'Not generated'} />
        <Status label="WireGuard key" value={appState.wireguardPublicKey ? 'Generated' : 'Not generated'} />
        <Status label="Discovery" value={appState.discoveryPublished ? 'Published' : 'Not published'} />
        <Status label="WireGuard" value={appState.wireguardState} />
        <Status label="Peers" value={String(appState.peers.length)} />
        <Status label="Session" value={appState.sessionMode} />
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
  peerIdentity: string;
  peerPreset: PeerPreset;
  onPeerIdentityChange: (value: string) => void;
  onPeerPresetChange: (value: PeerPreset) => void;
  onAddPeer: () => Promise<void>;
  onRemovePeer: (identity: string) => Promise<void>;
}) {
  return (
    <section>
      <h2>Peers</h2>
      <div className="form-row">
        <input value={props.peerIdentity} placeholder="Pubky identity" onChange={(event) => props.onPeerIdentityChange(event.target.value)} />
        <select value={props.peerPreset} onChange={(event) => props.onPeerPresetChange(event.target.value as PeerPreset)}>
          {Object.entries(presetLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <button onClick={props.onAddPeer}>Add peer</button>
      </div>
      {props.appState.peers.map((peer) => (
        <article className="peer-card" key={peer.identity}>
          <div>
            <strong>{peer.label ?? peer.identity}</strong>
            <p>{presetLabels[peer.preset]} · {peer.connectionState}</p>
          </div>
          <button onClick={() => props.onRemovePeer(peer.identity)}>Revoke</button>
        </article>
      ))}
    </section>
  );
}

function NetworkView({ peers, wireguardState }: { peers: Peer[]; wireguardState: AppState['wireguardState'] }) {
  return (
    <section>
      <h2>Network</h2>
      <p>WireGuard state: {wireguardState}</p>
      {peers.map((peer) => (
        <article className="peer-card" key={peer.identity}>
          <strong>{peer.identity}</strong>
          <p>Connection: {peer.connectionState}</p>
          <p>Grant: {presetLabels[peer.preset]}</p>
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

function Settings({ appState }: { appState: AppState }) {
  return (
    <section>
      <h2>Settings</h2>
      <Status label="Key vault" value={appState.sessionMode === 'local_keys' ? 'Local keys enabled' : 'Session limited'} />
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
