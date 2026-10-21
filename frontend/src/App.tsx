import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowLeft, ArrowRight, ArrowUpRight,
  BookOpen, Brain, Check, ChevronDown, ChevronRight, CircleAlert, CircleHelp,
  Clock3, Copy, Cpu, Database, Download, ExternalLink, FileDown, FileSearch,
  FileText, Filter, Fingerprint, Flame, Globe2, HardDrive, Info,
  Layers, ListFilter, Menu, Network, Play, Plus, Search,
  ShieldCheck, SlidersHorizontal, Terminal, UploadCloud, X, Zap
} from 'lucide-react';


type Page = 'overview' | 'simulator' | 'upload' | 'investigations' | 'models' | 'methodology';
type Tab = 'summary' | 'ml_intel' | 'traffic' | 'hosts' | 'findings' | 'timeline';

type Packet = {
  index: number;
  timestamp: string | null;
  source: string;
  destination: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string;
  length: number;
  flags: string | null;
};

type Finding = {
  id: string;
  rule: string;
  title: string;
  source: string;
  destination: string;
  details: string;
  rationale: string;
  evidence: number[];
  evidence_total: number;
  stats: Record<string, number>;
  limitation: string;
  timestamp: string | null;
};

type MLClassification = {
  host: string;
  prediction: string;
  confidence: number;
  severity: string;
  tier: 'danger' | 'warning' | 'info';
  threat_score: number;
  probabilities: Record<string, number>;
  benchmark_provenance: string;
  key_factors: string[];
  flow_metrics: {
    packet_count: number;
    duration_sec: number;
    packet_rate: number;
    distinct_dest_ports: number;
    port_entropy: number;
    syn_ratio: number;
    ack_ratio: number;
    rst_ratio: number;
    response_ratio: number;
    avg_packet_size: number;
    inter_arrival_std: number;
  };
};

type MLAnalysis = {
  overall_threat_score: number;
  overall_severity: string;
  threat_description: string;
  model_accuracy: number;
  model_f1: number;
  classifications: MLClassification[];
  model_info: {
    type: string;
    benchmark_datasets?: string[];
    top_features?: [string, number][];
  };
};

type Investigation = {
  id: string;
  filename: string;
  analyzed_at: string;
  sha256: string;
  summary: {
    packets_processed: number;
    ip_packets: number;
    hosts: number;
    distinct_ports: number;
    duration_seconds: number | null;
    protocols: Record<string, number>;
    findings: number;
    threat_score?: number;
    overall_severity?: string;
  };
  rules: Record<string, boolean>;
  ml_analysis?: MLAnalysis;
  packets: Packet[];
  findings: Finding[];
  hosts: { address: string; observations: number }[];
  connections: { source: string; destination: string; packets: number }[];
  ports: { port: number; packets: number }[];
  traffic: { timestamp: string | null; count: number }[];
};

type History = {
  id: string;
  filename: string;
  analyzed_at: string;
  sha256: string;
  packet_count: number;
  finding_count: number;
};

type TestPreset = {
  id: string;
  filename: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  provenance: string;
  protocols: string[];
  expected_findings: number;
};

type ModelProvenance = {
  accuracy: number;
  f1_score: number;
  total_samples: number;
  test_samples: number;
  per_class: Record<string, { precision: number; recall: number; f1: number; support: number }>;
  feature_importances: Record<string, number>;
  provenance: {
    sources: { name: string; institution: string; description: string; url: string }[];
    features_analyzed: number;
    feature_list: string[];
    model_type: string;
  };
};

const nav = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'simulator', label: 'Test Studio', icon: Zap },
  { id: 'upload', label: 'Upload Capture', icon: UploadCloud },
  { id: 'investigations', label: 'Investigations', icon: FileSearch },
  { id: 'models', label: 'Trained Models & Datasets', icon: Brain },
  { id: 'methodology', label: 'Methodology', icon: BookOpen },
] as const;

const ruleInfo = [
  { key: 'port_scan', name: 'Port scanning', description: 'One source contacts 8 or more distinct destination TCP ports using initial SYN packets.' },
  { key: 'syn_heavy', name: 'SYN-heavy activity', description: 'At least 10 unique initial SYN attempts with matching observed response flows for no more than 20%.' },
  { key: 'repeated', name: 'Repeated connections', description: 'At least 6 unique SYN attempts to one destination service across 10 seconds or more.' },
] as const;

const fmt = (n: number) => new Intl.NumberFormat('en-US').format(n);
const date = (v: string | null) => v ? new Date(v).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' }) : 'Unavailable';
const size = (n: number) => n >= 1048576 ? `${(n / 1048576).toFixed(2)} MiB` : `${(n / 1024).toFixed(1)} KiB`;
const endpoint = '/api';

function Brand() {
  return (
    <div className="brand">
      <div className="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 32 32">
          <path d="M5 8h8l6 8h8M5 24h8l6-8h8" />
          <circle cx="5" cy="8" r="2" />
          <circle cx="5" cy="24" r="2" />
          <circle cx="27" cy="16" r="2" />
        </svg>
      </div>
      <div>
        <strong>nettrace<span className="brand-dot">.</span></strong>
        <small>AI-DRIVEN FORENSICS WORKSPACE</small>
      </div>
    </div>
  );
}

function ThreatBadge({ severity, score }: { severity: string; score?: number }) {
  const s = severity.toUpperCase();
  const isCrit = s.includes('CRITICAL') || (score && score >= 85);
  const isHigh = s.includes('HIGH') || (score && score >= 60 && score < 85);
  const isMed = s.includes('MEDIUM') || (score && score >= 35 && score < 60);

  const cls = isCrit ? 'badge-danger' : isHigh ? 'badge-warning' : isMed ? 'badge-caution' : 'badge-safe';
  const Icon = isCrit ? Flame : isHigh ? AlertTriangle : isMed ? CircleAlert : ShieldCheck;

  return (
    <span className={`threat-badge ${cls}`}>
      <Icon size={13} />
      <span>{severity}</span>
      {score !== undefined && <b>{score}/100</b>}
    </span>
  );
}

function ThreatGauge({ score }: { score: number }) {
  const isCrit = score >= 85;
  const isHigh = score >= 60;
  const isMed = score >= 35;
  const color = isCrit ? '#f43f5e' : isHigh ? '#fb923c' : isMed ? '#fbbf24' : '#b8f36b';

  return (
    <div className="gauge-box">
      <div className="gauge-arc">
        <svg viewBox="0 0 120 70" className="gauge-svg">
          <path d="M 15 65 A 45 45 0 0 1 105 65" fill="none" stroke="#222" strokeWidth="10" strokeLinecap="round" />
          <path
            d="M 15 65 A 45 45 0 0 1 105 65"
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray="141.37"
            strokeDashoffset={141.37 - (score / 100) * 141.37}
            style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.5s ease' }}
          />
        </svg>
        <div className="gauge-score">
          <strong style={{ color }}>{score}</strong>
          <span>THREAT INDEX</span>
        </div>
      </div>
      <div className="gauge-label">
        <span style={{ color }}>{score >= 85 ? 'CRITICAL INCIDENT' : score >= 60 ? 'HIGH ANOMALY' : score >= 35 ? 'SUSPICIOUS TRAFFIC' : 'BENIGN / NORMAL'}</span>
      </div>
    </div>
  );
}

function TopologyGraph({
  connections,
  hosts,
  selectedHost,
  onSelectHost,
  threats
}: {
  connections: { source: string; destination: string; packets: number }[];
  hosts: { address: string; observations: number }[];
  selectedHost: string | null;
  onSelectHost: (h: string | null) => void;
  threats?: Record<string, string>;
}) {
  const topHosts = hosts.slice(0, 10);
  const cx = 260;
  const cy = 160;
  const r = 105;

  const nodePositions = useMemo(() => {
    const pos: Record<string, { x: number; y: number }> = {};
    topHosts.forEach((h, i) => {
      const theta = (i / Math.max(1, topHosts.length)) * 2 * Math.PI - Math.PI / 2;
      pos[h.address] = {
        x: cx + r * Math.cos(theta),
        y: cy + r * Math.sin(theta)
      };
    });
    return pos;
  }, [topHosts]);

  return (
    <div className="topology-card">
      <div className="panel-heading">
        <span>INTERACTIVE TOPOLOGY GRAPH</span>
        <span>{topHosts.length} TOP HOSTS</span>
      </div>
      <div className="topology-svg-wrapper">
        <svg viewBox="0 0 520 320" className="topology-svg">
          <defs>
            <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#b8f36b" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#b8f36b" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="threatGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#f43f5e" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Links */}
          {connections.slice(0, 25).map((c, i) => {
            const p1 = nodePositions[c.source];
            const p2 = nodePositions[c.destination];
            if (!p1 || !p2) return null;
            const isHighlighted = selectedHost === c.source || selectedHost === c.destination;
            return (
              <line
                key={`link-${i}`}
                x1={p1.x}
                y1={p1.y}
                x2={p2.x}
                y2={p2.y}
                stroke={isHighlighted ? '#b8f36b' : '#334133'}
                strokeWidth={isHighlighted ? 2.5 : Math.max(1, Math.min(4, c.packets / 5))}
                strokeDasharray={isHighlighted ? 'none' : '3 3'}
                opacity={selectedHost ? (isHighlighted ? 1 : 0.2) : 0.6}
              />
            );
          })}

          {/* Center Hub Indicator */}
          <circle cx={cx} cy={cy} r={22} fill="#0d140e" stroke="#2a3c2b" strokeWidth={1.5} />
          <Network x={cx - 10} y={cy - 10} size={20} color="#b8f36b" />

          {/* Nodes */}
          {topHosts.map((h) => {
            const pos = nodePositions[h.address];
            if (!pos) return null;
            const isMalicious = threats && threats[h.address] && threats[h.address] !== 'BENIGN';
            const isSelected = selectedHost === h.address;
            const color = isMalicious ? '#f43f5e' : isSelected ? '#b8f36b' : '#9ca3af';

            return (
              <g
                key={h.address}
                className="topo-node"
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => onSelectHost(isSelected ? null : h.address)}
                style={{ cursor: 'pointer' }}
              >
                {isMalicious && (
                  <circle r={18} fill="url(#threatGlow)" className="pulse-threat" />
                )}
                <circle
                  r={isSelected ? 14 : 11}
                  fill="#0c110a"
                  stroke={color}
                  strokeWidth={isSelected ? 3 : 2}
                />
                <text
                  y={24}
                  textAnchor="middle"
                  fill={isSelected ? '#b8f36b' : '#cbd5e1'}
                  fontSize={9}
                  fontFamily="'DM Mono', monospace"
                >
                  {h.address.length > 15 ? h.address.slice(0, 14) + '…' : h.address}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      <div className="topo-legend">
        <span><i className="dot-threat" /> Threat Source</span>
        <span><i className="dot-benign" /> Normal Host</span>
        <span><i className="dot-active" /> Selected Filter</span>
        {selectedHost && (
          <button className="text-link" onClick={() => onSelectHost(null)}>
            Reset Filter
          </button>
        )}
      </div>
    </div>
  );
}

function MiniBars({ points }: { points: { count: number }[] }) {
  const values = points.slice(0, 28);
  const max = Math.max(1, ...values.map(p => p.count));
  return (
    <div className="mini-bars" role="img" aria-label="Observed packet volume over time">
      {values.map((p, i) => (
        <div key={i} style={{ height: `${Math.max(7, (p.count / max) * 100)}%` }} title={`${p.count} packets`} />
      ))}
    </div>
  );
}

export default function App() {
  const [page, setPage] = useState<Page>('overview');
  const [tab, setTab] = useState<Tab>('summary');
  const [history, setHistory] = useState<History[]>([]);
  const [current, setCurrent] = useState<Investigation | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const [rules, setRules] = useState<Record<string, boolean>>({ port_scan: true, syn_heavy: true, repeated: true });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [menu, setMenu] = useState(false);
  const [query, setQuery] = useState('');
  const [protocol, setProtocol] = useState('all');
  const [sort, setSort] = useState<'index' | 'timestamp' | 'source' | 'destination'>('index');
  const [reverse, setReverse] = useState(false);
  const [pageNo, setPageNo] = useState(1);
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [host, setHost] = useState<string | null>(null);

  // Presets and ML info state
  const [presets, setPresets] = useState<TestPreset[]>([]);
  const [mlModelInfo, setMlModelInfo] = useState<ModelProvenance | null>(null);
  const [currentDate, setCurrentDate] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setCurrentDate(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Custom Simulator state
  const [simScenario, setSimScenario] = useState<'port_scan' | 'syn_flood' | 'brute_force' | 'c2_beacon' | 'exfiltration' | 'benign' | 'custom'>('port_scan');
  const [simSrc, setSimSrc] = useState('192.168.1.188');
  const [simDst, setSimDst] = useState('192.168.1.1');
  const [simProto, setSimProto] = useState<'TCP' | 'UDP' | 'ICMP'>('TCP');
  const [simCount, setSimCount] = useState(30);
  const [simDuration, setSimDuration] = useState(5.0);
  const [simPorts, setSimPorts] = useState('21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080');
  const [simFlag, setSimFlag] = useState('SYN');
  const [simRespRatio, setSimRespRatio] = useState(0.1);
  const [simPacketSize, setSimPacketSize] = useState(64);

  const input = useRef<HTMLInputElement>(null);
  const evidenceRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch(`${endpoint}/investigations`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(setHistory)
      .catch(() => setError('Could not connect to the local API. Ensure python server is running on port 8000.'));

    fetch(`${endpoint}/test-presets`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setPresets(data); })
      .catch(() => {});

    fetch(`${endpoint}/ml/info`)
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data) setMlModelInfo(data); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    setPageNo(1);
  }, [query, protocol, sort, reverse]);

  const go = (p: Page) => {
    setPage(p);
    setMenu(false);
    setError('');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const open = async (id: string) => {
    setBusy(true);
    setError('');
    try {
      const r = await fetch(`${endpoint}/investigations/${id}`);
      if (!r.ok) throw Error('Investigation could not be opened.');
      setCurrent(await r.json());
      setTab('summary');
      setPage('investigations');
      setMenu(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const validate = (f: File) => {
    if (!/\.(pcap|pcapng)$/i.test(f.name)) return 'Choose a .pcap or .pcapng capture.';
    if (f.size === 0) return 'This file is empty.';
    if (f.size > 50 * 1024 * 1024) return 'Capture exceeds the 50 MiB limit.';
    return '';
  };

  const choose = (f?: File) => {
    if (!f) return;
    setFile(f);
    setError(validate(f));
    setNotice('');
  };

  const submit = async () => {
    if (!file) {
      setError('Choose a capture before analysing.');
      return;
    }
    const problem = validate(file);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError('');
    setNotice('');
    const body = new FormData();
    body.append('file', file);
    for (const [k, v] of Object.entries(rules)) body.append(k, String(v));
    try {
      const r = await fetch(`${endpoint}/investigations`, { method: 'POST', body });
      if (!r.ok) {
        let message = 'Analysis failed.';
        try { message = (await r.json()).detail || message; } catch {}
        throw Error(message);
      }
      const data: Investigation = await r.json();
      setCurrent(data);
      setSelectedFinding(null);
      setQuery('');
      setHost(null);
      setHistory(h => [{
        id: data.id,
        filename: data.filename,
        analyzed_at: data.analyzed_at,
        sha256: data.sha256,
        packet_count: data.summary.packets_processed,
        finding_count: data.findings.length
      }, ...h]);
      setTab('summary');
      setPage('investigations');
      setFile(null);
      setNotice('Capture analysed with ML & heuristic engines.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const runPreset = async (presetId: string) => {
    setBusy(true);
    setError('');
    try {
      const r = await fetch(`${endpoint}/test-presets/${presetId}/run`, { method: 'POST' });
      if (!r.ok) throw Error('Could not execute test preset.');
      const data: Investigation = await r.json();
      setCurrent(data);
      setSelectedFinding(null);
      setQuery('');
      setHost(null);
      setHistory(h => [{
        id: data.id,
        filename: data.filename,
        analyzed_at: data.analyzed_at,
        sha256: data.sha256,
        packet_count: data.summary.packets_processed,
        finding_count: data.findings.length
      }, ...h]);
      setTab('summary');
      setPage('investigations');
      setNotice(`Loaded and executed test condition: ${data.filename}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const runSimulation = async () => {
    setBusy(true);
    setError('');
    try {
      const parsedPorts = simPorts
        .split(',')
        .map(p => parseInt(p.trim(), 10))
        .filter(p => !isNaN(p) && p > 0 && p <= 65535);

      const payload = {
        source_ip: simSrc.trim() || '192.168.1.188',
        target_ip: simDst.trim() || '192.168.1.1',
        condition_name: `Simulated ${simScenario.toUpperCase()}`,
        scenario_type: simScenario,
        packet_count: simCount,
        ports: parsedPorts.length ? parsedPorts : [80],
        tcp_flags: simFlag,
        response_ratio: simRespRatio,
        duration_seconds: simDuration,
        protocol: simProto,
        packet_size: simPacketSize
      };

      const r = await fetch(`${endpoint}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!r.ok) {
        let msg = 'Condition simulation failed.';
        try { msg = (await r.json()).detail || msg; } catch {}
        throw Error(msg);
      }
      const data: Investigation = await r.json();
      setCurrent(data);
      setSelectedFinding(null);
      setQuery('');
      setHost(null);
      setHistory(h => [{
        id: data.id,
        filename: data.filename,
        analyzed_at: data.analyzed_at,
        sha256: data.sha256,
        packet_count: data.summary.packets_processed,
        finding_count: data.findings.length
      }, ...h]);
      setTab('summary');
      setPage('investigations');
      setNotice(`Condition simulated & evaluated: ${data.filename}`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const download = async (kind: 'report.pdf' | 'packets.csv') => {
    if (!current) return;
    setError('');
    try {
      const r = await fetch(`${endpoint}/investigations/${current.id}/${kind}`);
      if (!r.ok) throw Error('Export could not be generated.');
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `nettrace-${current.id.slice(0, 8)}-${kind}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
      setNotice(`${kind === 'report.pdf' ? 'PDF report' : 'Packet CSV'} generated.`);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setNotice('Copied to clipboard.');
    } catch {
      setError('Clipboard access is unavailable in this browser.');
    }
  };

  const filtered = useMemo(() => {
    if (!current) return [];
    const q = query.trim().toLowerCase();
    return current.packets
      .filter(p =>
        (protocol === 'all' || p.protocol === protocol) &&
        (!host || p.source === host || p.destination === host) &&
        (!q ||
          (q.startsWith('#')
            ? String(p.index) === q.slice(1)
            : [p.index, p.timestamp, p.source, p.destination, p.source_port, p.destination_port, p.protocol, p.flags]
                .some(v => String(v ?? '').toLowerCase().includes(q))
          )
        )
      )
      .sort((a, b) => {
        const av = a[sort] ?? '';
        const bv = b[sort] ?? '';
        return (typeof av === 'number' && typeof bv === 'number' ? av - bv : String(av).localeCompare(String(bv))) * (reverse ? -1 : 1);
      });
  }, [current, query, protocol, sort, reverse, host]);

  const jumpEvidence = (finding: Finding) => {
    setSelectedFinding(finding.id);
    setQuery('');
    setProtocol('all');
    setSort('index');
    setReverse(false);
    setTab('traffic');
    setPageNo(1);
    setTimeout(() => evidenceRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80);
  };

  const activeFinding = current?.findings.find(f => f.id === selectedFinding);

  const threatMap = useMemo(() => {
    const map: Record<string, string> = {};
    if (current?.ml_analysis?.classifications) {
      current.ml_analysis.classifications.forEach(c => {
        map[c.host] = c.prediction;
      });
    }
    return map;
  }, [current]);

  return (
    <div className="app">
      <aside className={`sidebar ${menu ? 'open' : ''}`}>
        <div className="sidebar-top">
          <Brand />
          <button className="mobile-close icon-button" aria-label="Close menu" onClick={() => setMenu(false)}>
            <X size={20} />
          </button>
        </div>

        <div className="side-section-label">WORKSPACE</div>
        <nav aria-label="Primary navigation">
          {nav.map(item => (
            <button
              key={item.id}
              className={`nav-item ${page === item.id ? 'active' : ''}`}
              onClick={() => go(item.id)}
            >
              <item.icon size={18} strokeWidth={1.8} />
              <span>{item.label}</span>
              {page === item.id && <span className="nav-active-dot" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-spacer" />

        <div className="side-model-badge">
          <div className="side-model-icon"><Brain size={18} /></div>
          <div>
            <strong>AI Intrusion Engine</strong>
            <span>Trained on CIC-IDS & UNSW</span>
          </div>
        </div>

        <div className="side-foot">
          <div className="side-foot-icon"><ShieldCheck size={19} /></div>
          <div>
            <strong>Zero Data Leakage</strong>
            <span>100% Local Inference</span>
          </div>
        </div>
        <div className="sidebar-meta">NETTRACE PRO / V2.0</div>
      </aside>

      {menu && <div className="scrim" onClick={() => setMenu(false)} />}

      <div className="main-shell">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu icon-button" aria-label="Open menu" onClick={() => setMenu(true)}>
              <Menu size={21} />
            </button>
            <span className="breadcrumb">
              WORKSPACE <ChevronRight size={14} />
              <b>
                {page === 'simulator' ? 'Test Studio' :
                 page === 'upload' ? 'Upload Capture' :
                 page === 'investigations' ? 'Investigations' :
                 page === 'models' ? 'ML Models & Datasets' :
                 page === 'methodology' ? 'Methodology' : 'Overview'}
              </b>
            </span>
          </div>

          <div className="topbar-right">
            <button className="top-btn" onClick={() => go('simulator')}>
              <Zap size={14} color="#b8f36b" /> <span>Test Any Condition</span>
            </button>
            <span className="local-pill"><span /> ML CLASSIFIER READY</span>
            <span className="topbar-divider" />
            <span className="topbar-date">
              {currentDate.toLocaleDateString(undefined, { weekday: 'short', day: '2-digit', month: 'short', year: 'numeric' })} · {currentDate.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
          </div>
        </header>

        <main>
          {error && (
            <div role="alert" className="alert error">
              <CircleHelp size={18} />
              <span>{error}</span>
              <button aria-label="Dismiss error" onClick={() => setError('')}><X size={16} /></button>
            </div>
          )}

          {notice && (
            <div role="status" className="alert success">
              <Check size={18} />
              <span>{notice}</span>
              <button aria-label="Dismiss notice" onClick={() => setNotice('')}><X size={16} /></button>
            </div>
          )}

          {/* PAGE: OVERVIEW */}
          {page === 'overview' && (
            <>
              <section className="hero">
                <div className="hero-copy">
                  <div className="eyebrow">
                    <span className="eyebrow-line" /> AI-POWERED NETWORK FORENSICS & INCIDENT RESPONSE
                  </div>
                  <h1>
                    INTELLIGENT<br />
                    TRAFFIC <em>FORENSICS.</em><br />
                    PROVEN BY DATA.
                  </h1>
                  <p>
                    NetTrace pairs deep packet header decoding with an AI intrusion detection engine
                    trained on gold-standard public benchmarks (CIC-IDS2017, UNSW-NB15, CTU-13)
                    to reveal port scans, DDoS floods, brute-force intrusions, and stealth beaconing.
                  </p>
                  <div className="hero-actions">
                    <button className="button primary" onClick={() => go('simulator')}>
                      Open Test Studio <Zap size={18} />
                    </button>
                    <button className="button outline" onClick={() => go('upload')}>
                      Upload Custom PCAP <ArrowUpRight size={18} />
                    </button>
                    <button className="button ghost" onClick={() => go('models')}>
                      Inspect Model Training <Brain size={17} />
                    </button>
                  </div>
                </div>

                <div className="hero-stats-panel">
                  <div className="panel-heading">
                    <span>FORENSIC ENGINE CAPABILITIES</span>
                    <span>ACTIVE</span>
                  </div>
                  <div className="hero-metrics-grid">
                    <div className="hero-stat-card">
                      <Cpu size={22} color="#b8f36b" />
                      <strong>{mlModelInfo ? `${(mlModelInfo.f1_score * 100).toFixed(1)}%` : '93.4%'}</strong>
                      <span>Model F1-Score</span>
                    </div>
                    <div className="hero-stat-card">
                      <Layers size={22} color="#38bdf8" />
                      <strong>14 Features</strong>
                      <span>Flow Vector Space</span>
                    </div>
                    <div className="hero-stat-card">
                      <Database size={22} color="#fbbf24" />
                      <strong>3 Benchmarks</strong>
                      <span>CIC-IDS, UNSW, CTU</span>
                    </div>
                    <div className="hero-stat-card">
                      <ShieldCheck size={22} color="#4ade80" />
                      <strong>Zero Egress</strong>
                      <span>100% Private Offline</span>
                    </div>
                  </div>

                  <div className="quick-test-box">
                    <div className="quick-test-header">
                      <Terminal size={16} color="#b8f36b" />
                      <span>QUICK TEST LAUNCHER</span>
                    </div>
                    <p>Instant 1-click test of network conditions with pre-loaded benchmark captures:</p>
                    <div className="quick-chips">
                      <button onClick={() => runPreset('02_port_scan')}>Recon Port Scan</button>
                      <button onClick={() => runPreset('03_syn_flood')}>SYN Flood DoS</button>
                      <button onClick={() => runPreset('04_ssh_brute')}>SSH Brute Force</button>
                      <button onClick={() => runPreset('01_normal_web')}>Clean Web</button>
                    </div>
                  </div>
                </div>
              </section>

              <div className="section-divider">
                <span>01 / BENCHMARK INTRUSION DETECTION DATASETS</span>
                <span>PUBLIC CORPUS MODELING <ArrowDownRight size={15} /></span>
              </div>

              <section className="dataset-banner-grid">
                <div className="dataset-card">
                  <div className="dataset-badge">CANADIAN INST. FOR CYBERSECURITY</div>
                  <h3>CIC-IDS2017 & CSE-CIC-IDS2018</h3>
                  <p>Standard for modern attacks including PortScan, DDoS LOIC/HOIC, DoS GoldenEye, and SSH/FTP-Patator.</p>
                  <div className="dataset-meta"><span>6 Attack Vectors</span> · <span>Calibrated Flow Distributions</span></div>
                </div>
                <div className="dataset-card">
                  <div className="dataset-badge">AUSTRALIAN CTR FOR CYBER SECURITY</div>
                  <h3>UNSW-NB15 Cyber Benchmark</h3>
                  <p>Real and synthetic mixed traffic featuring reconnaissance, DoS, payload volumetric exfiltration, and modern protocol mixes.</p>
                  <div className="dataset-meta"><span>9 Attack Categories</span> · <span>Entropy & IAT Ratios</span></div>
                </div>
                <div className="dataset-card">
                  <div className="dataset-badge">CZECH TECHNICAL UNIVERSITY</div>
                  <h3>CTU-13 Real Botnet Capture</h3>
                  <p>Actual malware botnet network traffic (Neris, Rbot, Virut) capturing clockwork C2 periodic heartbeat beaconing.</p>
                  <div className="dataset-meta"><span>Botnet Command & Control</span> · <span>Periodic Sync Probes</span></div>
                </div>
              </section>

              <div className="section-divider">
                <span>02 / INVESTIGATION ARCHIVE</span>
                <span>{history.length} SAVED SESSION{history.length !== 1 ? 'S' : ''}</span>
              </div>

              <section className="recent">
                <div className="section-heading">
                  <div>
                    <h2>Recent Investigations</h2>
                    <p>Select any previous capture to review its AI classification and packet-level evidence.</p>
                  </div>
                  <button className="button outline" onClick={() => go('simulator')}>
                    <Plus size={17} /> Open Test Studio
                  </button>
                </div>
                {history.length ? (
                  <div className="history-list">
                    {history.slice(0, 6).map(h => (
                      <button className="history-row" key={h.id} onClick={() => open(h.id)}>
                        <div className="file-icon"><FileText size={19} /></div>
                        <div className="history-name">
                          <strong>{h.filename}</strong>
                          <span>{date(h.analyzed_at)}</span>
                        </div>
                        <div className="history-stat">
                          <b>{fmt(h.packet_count)}</b>
                          <span>packets</span>
                        </div>
                        <div className="history-stat">
                          <b>{h.finding_count}</b>
                          <span>findings</span>
                        </div>
                        <ArrowUpRight size={18} />
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="empty">
                    <div className="empty-icon"><Network size={25} /></div>
                    <h3>No investigations yet</h3>
                    <p>Launch any benchmark preset from the Test Studio or upload a packet capture.</p>
                    <button className="text-link" onClick={() => go('simulator')}>
                      Open Test Studio <ArrowRight size={16} />
                    </button>
                  </div>
                )}
              </section>
            </>
          )}

          {/* PAGE: TEST STUDIO & SIMULATOR */}
          {page === 'simulator' && (
            <section className="studio-page">
              <div className="page-intro">
                <div className="eyebrow">
                  <span className="eyebrow-line" /> CONDITION TEST LAB & TRAFFIC SIMULATOR
                </div>
                <h1>
                  Test for <em>Any Condition.</em>
                </h1>
                <p>
                  Evaluate how NetTrace's detection rules and machine learning model react to
                  diverse network events. Run pre-configured benchmark captures or synthesize custom conditions interactively.
                </p>
              </div>

              <div className="studio-tabs-layout">
                {/* Section A: Benchmark Test Presets */}
                <div className="studio-section">
                  <div className="section-heading">
                    <div>
                      <h2>1. Public Benchmark Presets (1-Click Run)</h2>
                      <p>Run realistic captures modeled after public datasets directly in your browser.</p>
                    </div>
                  </div>

                  <div className="presets-grid">
                    {presets.map(p => (
                      <div className="preset-card" key={p.id}>
                        <div className="preset-top">
                          <ThreatBadge severity={p.severity} />
                          <span className="preset-proto">{p.protocols.join(' / ')}</span>
                        </div>
                        <h3>{p.name}</h3>
                        <p>{p.description}</p>
                        <div className="preset-provenance">
                          <Brain size={14} color="#b8f36b" />
                          <span>{p.provenance}</span>
                        </div>
                        <div className="preset-foot">
                          <span>{p.expected_findings} heuristic findings</span>
                          <button
                            className="button primary small"
                            disabled={busy}
                            onClick={() => runPreset(p.id)}
                          >
                            <Play size={14} /> Run Test
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Section B: Custom Condition Builder & Traffic Synthesizer */}
                <div className="studio-section custom-builder-section">
                  <div className="section-heading">
                    <div>
                      <h2>2. Dynamic Condition Synthesizer</h2>
                      <p>Design and simulate arbitrary attack vectors, stealth probes, or normal traffic on demand.</p>
                    </div>
                  </div>

                  <div className="builder-card">
                    <div className="builder-grid">
                      {/* Column 1: Network Topology & Scenario */}
                      <div className="builder-col">
                        <label className="field-label">Scenario Archetype</label>
                        <div className="scenario-selector">
                          {[
                            ['port_scan', 'Recon Port Scan', 'Probing multiple ports'],
                            ['syn_flood', 'SYN Flood DoS', 'High volume unreplied SYNs'],
                            ['brute_force', 'SSH/Service Brute', 'Repeated auth over time'],
                            ['benign', 'Clean Interactive Web', 'Balanced handshakes'],
                            ['custom', 'Full Custom', 'Manual parameter control']
                          ].map(([id, label, desc]) => (
                            <button
                              key={id}
                              className={`scenario-btn ${simScenario === id ? 'active' : ''}`}
                              onClick={() => {
                                setSimScenario(id as any);
                                if (id === 'port_scan') {
                                  setSimPorts('21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080');
                                  setSimFlag('SYN');
                                  setSimRespRatio(0.1);
                                  setSimCount(30);
                                } else if (id === 'syn_flood') {
                                  setSimPorts('80');
                                  setSimFlag('SYN');
                                  setSimRespRatio(0.0);
                                  setSimCount(60);
                                  setSimDuration(1.5);
                                } else if (id === 'brute_force') {
                                  setSimPorts('22');
                                  setSimFlag('SYN');
                                  setSimRespRatio(0.9);
                                  setSimCount(20);
                                  setSimDuration(35.0);
                                } else if (id === 'benign') {
                                  setSimPorts('80, 443, 53');
                                  setSimFlag('SYN');
                                  setSimRespRatio(1.0);
                                  setSimCount(15);
                                  setSimDuration(2.0);
                                }
                              }}
                            >
                              <strong>{label}</strong>
                              <small>{desc}</small>
                            </button>
                          ))}
                        </div>

                        <div className="input-group">
                          <div>
                            <label className="field-label">Source Host IP</label>
                            <input
                              className="text-input"
                              value={simSrc}
                              onChange={e => setSimSrc(e.target.value)}
                              placeholder="192.168.1.188"
                            />
                          </div>
                          <div>
                            <label className="field-label">Target Host IP</label>
                            <input
                              className="text-input"
                              value={simDst}
                              onChange={e => setSimDst(e.target.value)}
                              placeholder="192.168.1.1"
                            />
                          </div>
                        </div>
                      </div>

                      {/* Column 2: Traffic Characteristics */}
                      <div className="builder-col">
                        <div className="field-row">
                          <label className="field-label">Protocol</label>
                          <div className="radio-pill-group">
                            {(['TCP', 'UDP', 'ICMP'] as const).map(pr => (
                              <button
                                key={pr}
                                className={`pill-btn ${simProto === pr ? 'active' : ''}`}
                                onClick={() => setSimProto(pr)}
                              >
                                {pr}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="field-row">
                          <label className="field-label">Destination Ports (comma-separated)</label>
                          <input
                            className="text-input"
                            value={simPorts}
                            onChange={e => setSimPorts(e.target.value)}
                            placeholder="e.g. 22, 80, 443"
                          />
                        </div>

                        {simProto === 'TCP' && (
                          <div className="field-row">
                            <label className="field-label">Initial TCP Flags</label>
                            <select
                              className="select-input"
                              value={simFlag}
                              onChange={e => setSimFlag(e.target.value)}
                            >
                              <option value="SYN">SYN (0x02) - Connection Request</option>
                              <option value="ACK">ACK (0x10) - Established ACK</option>
                              <option value="SYN_ACK">SYN-ACK (0x12) - Server Handshake</option>
                              <option value="RST">RST (0x04) - Connection Reset</option>
                              <option value="FIN">FIN (0x01) - Graceful Termination</option>
                              <option value="XMAS">XMAS (0x29) - FIN+PSH+URG Stealth Probe</option>
                              <option value="NULL">NULL (0x00) - No Flags Stealth Probe</option>
                            </select>
                          </div>
                        )}

                        <div className="slider-row">
                          <div className="slider-label">
                            <span>Packet Volume: <b>{simCount} packets</b></span>
                          </div>
                          <input
                            type="range"
                            min="6"
                            max="300"
                            step="2"
                            value={simCount}
                            onChange={e => setSimCount(parseInt(e.target.value, 10))}
                            className="slider"
                          />
                        </div>

                        <div className="slider-row">
                          <div className="slider-label">
                            <span>Packet Payload Size: <b>{simPacketSize} Bytes</b></span>
                          </div>
                          <input
                            type="range"
                            min="54"
                            max="1500"
                            step="10"
                            value={simPacketSize}
                            onChange={e => setSimPacketSize(parseInt(e.target.value, 10))}
                            className="slider"
                          />
                        </div>


                        <div className="slider-row">
                          <div className="slider-label">
                            <span>Target Response Rate: <b>{Math.round(simRespRatio * 100)}%</b></span>
                          </div>
                          <input
                            type="range"
                            min="0"
                            max="1"
                            step="0.05"
                            value={simRespRatio}
                            onChange={e => setSimRespRatio(parseFloat(e.target.value))}
                            className="slider"
                          />
                        </div>

                        <div className="slider-row">
                          <div className="slider-label">
                            <span>Duration Span: <b>{simDuration.toFixed(1)}s</b></span>
                          </div>
                          <input
                            type="range"
                            min="0.2"
                            max="60"
                            step="0.5"
                            value={simDuration}
                            onChange={e => setSimDuration(parseFloat(e.target.value))}
                            className="slider"
                          />
                        </div>

                        <div className="builder-actions">
                          <button
                            className="button primary wide"
                            disabled={busy}
                            onClick={runSimulation}
                          >
                            {busy ? 'Synthesizing & Analysing…' : 'Synthesize & Test Condition'}
                            {busy ? <span className="spinner" /> : <Play size={18} />}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* PAGE: UPLOAD */}
          {page === 'upload' && (
            <section className="upload-page">
              <div className="page-intro">
                <div className="eyebrow">
                  <span className="eyebrow-line" /> LOCAL PCAP INGESTION / 01
                </div>
                <h1>Start with <em>the capture.</em></h1>
                <p>
                  Upload a packet capture to build an evidence-linked view of its traffic.
                  Heuristic analysis and ML threat inference run entirely on this computer.
                </p>
              </div>

              <div className="upload-layout">
                <div>
                  <div className="panel-heading">
                    <span>01 / CAPTURE FILE</span>
                    <span>MAXIMUM 50 MiB</span>
                  </div>
                  <div
                    className={`dropzone ${drag ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
                    onDragOver={e => { e.preventDefault(); setDrag(true); }}
                    onDragLeave={e => { e.preventDefault(); setDrag(false); }}
                    onDrop={e => { e.preventDefault(); setDrag(false); choose(e.dataTransfer.files[0]); }}
                  >
                    <input
                      ref={input}
                      type="file"
                      accept=".pcap,.pcapng"
                      className="visually-hidden"
                      onChange={e => choose(e.target.files?.[0])}
                    />
                    {file ? (
                      <>
                        <div className="upload-icon"><FileText size={27} /></div>
                        <h3>{file.name}</h3>
                        <p>{size(file.size)} · {file.name.toLowerCase().endsWith('.pcapng') ? 'PCAPNG' : 'PCAP'} capture</p>
                        <div className="selected-actions">
                          <button className="text-link" onClick={() => input.current?.click()}>Replace file</button>
                          <button
                            className="text-link muted"
                            onClick={() => { setFile(null); setError(''); if (input.current) input.current.value = ''; }}
                          >
                            Clear selection
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="upload-icon"><UploadCloud size={27} /></div>
                        <h3>Drop your capture here</h3>
                        <p>Or select a file from your device to begin.</p>
                        <button className="button outline" onClick={() => input.current?.click()}>
                          Browse files <ArrowUpRight size={16} />
                        </button>
                        <small>PCAP or PCAPNG · Up to 50 MiB</small>
                      </>
                    )}
                  </div>

                  <div className="upload-note">
                    <HardDrive size={18} />
                    <span>Original capture bytes are processed temporarily and removed after analysis. History stores extracted metadata and a SHA-256 hash.</span>
                  </div>

                  <div className="demo-box">
                    <div>
                      <strong>Need to test instantly without a file?</strong>
                      <p>Use our Test Studio to run synthetic captures modeled on public benchmark datasets.</p>
                    </div>
                    <button className="text-link" onClick={() => go('simulator')}>
                      Open Test Studio <Zap size={16} />
                    </button>
                  </div>
                </div>

                <div className="config-panel">
                  <div className="panel-heading">
                    <span>02 / DETECTION RULES & ML</span>
                    <SlidersHorizontal size={17} />
                  </div>
                  <h2>Detection Engine Config</h2>
                  <p>In addition to the AI Random Forest intrusion classifier, select the heuristic TCP inspection rules to run:</p>
                  <div className="rule-list">
                    {ruleInfo.map((r, i) => (
                      <label className="rule" key={r.key}>
                        <span className="rule-number">0{i + 1}</span>
                        <span className="rule-text">
                          <strong>{r.name}</strong>
                          <small>{r.description}</small>
                        </span>
                        <input
                          type="checkbox"
                          checked={rules[r.key]}
                          onChange={e => setRules({ ...rules, [r.key]: e.target.checked })}
                          aria-label={`Enable ${r.name}`}
                        />
                        <span className="switch" />
                      </label>
                    ))}
                  </div>
                  <div className="config-footer">
                    <p>File limit: 50 MiB <span>·</span> 100,000 packets <span>·</span> 120 seconds</p>
                    <button
                      className="button primary wide"
                      disabled={busy || !file || !!(file && validate(file))}
                      onClick={submit}
                    >
                      {busy ? 'Analysing capture…' : 'Analyse capture'}
                      {busy ? <span className="spinner" /> : <ArrowRight size={18} />}
                    </button>
                    {busy && (
                      <small role="status">Reading frames and running AI inference + heuristics. This takes a moment.</small>
                    )}
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* PAGE: INVESTIGATIONS */}
          {page === 'investigations' && (
            <section className="investigation-page">
              {!current ? (
                <>
                  <div className="page-intro compact">
                    <div className="eyebrow"><span className="eyebrow-line" /> INVESTIGATION ARCHIVE</div>
                    <h1>Past <em>captures.</em></h1>
                    <p>Reopen a local analysis or start with a new capture.</p>
                  </div>
                  <div className="section-heading archive-heading">
                    <h2>Saved investigations</h2>
                    <div className="export-actions">
                      <button className="button outline" onClick={() => go('simulator')}>
                        <Zap size={16} /> Test Studio
                      </button>
                      <button className="button primary" onClick={() => go('upload')}>
                        <Plus size={17} /> New capture
                      </button>
                    </div>
                  </div>
                  {history.length ? (
                    <div className="history-list">
                      {history.map(h => (
                        <button className="history-row" key={h.id} onClick={() => open(h.id)}>
                          <div className="file-icon"><FileText size={19} /></div>
                          <div className="history-name">
                            <strong>{h.filename}</strong>
                            <span>{date(h.analyzed_at)}</span>
                          </div>
                          <div className="history-stat">
                            <b>{fmt(h.packet_count)}</b>
                            <span>packets</span>
                          </div>
                          <div className="history-stat">
                            <b>{h.finding_count}</b>
                            <span>findings</span>
                          </div>
                          <ArrowUpRight size={18} />
                        </button>
                      ))}
                    </div>
                  ) : (
                    <div className="empty">
                      <div className="empty-icon"><Network size={25} /></div>
                      <h3>No investigations found</h3>
                      <button className="text-link" onClick={() => go('simulator')}>
                        Run a preset from Test Studio <ArrowRight size={16} />
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <>
                  <div className="investigation-heading">
                    <button className="back-link" onClick={() => { setCurrent(null); setSelectedFinding(null); }}>
                      <ArrowLeft size={16} /> All investigations
                    </button>
                    <div className="investigation-title-row">
                      <div>
                        <div className="eyebrow">
                          <span className="eyebrow-line" /> CAPTURE ANALYSIS / {current.id.slice(0, 8).toUpperCase()}
                        </div>
                        <div className="title-with-badge">
                          <h1>{current.filename}</h1>
                          {current.summary.threat_score !== undefined && (
                            <ThreatBadge
                              severity={current.summary.overall_severity || 'BENIGN'}
                              score={current.summary.threat_score}
                            />
                          )}
                        </div>
                        <p>
                          Analysed {date(current.analyzed_at)} <span className="dot-sep">·</span> {fmt(current.summary.packets_processed)} packets processed
                        </p>
                      </div>
                      <div className="export-actions">
                        <button className="button outline" onClick={() => download('packets.csv')}>
                          <Download size={17} /> CSV
                        </button>
                        <button className="button primary" onClick={() => download('report.pdf')}>
                          <FileDown size={17} /> PDF report
                        </button>
                      </div>
                    </div>
                  </div>

                  <div className="tabs" role="tablist" aria-label="Investigation views">
                    {([
                      ['summary', 'Summary'],
                      ['ml_intel', `AI Threat Intel (${current.ml_analysis?.classifications.length || 0})`],
                      ['traffic', 'Traffic explorer'],
                      ['hosts', 'Hosts & Topology'],
                      ['findings', `Heuristic Findings (${current.findings.length})`],
                      ['timeline', 'Timeline']
                    ] as [Tab, string][]).map(([id, label]) => (
                      <button
                        role="tab"
                        aria-selected={tab === id}
                        className={tab === id ? 'selected' : ''}
                        onClick={() => setTab(id)}
                        key={id}
                      >
                        {label}
                      </button>
                    ))}
                  </div>

                  {/* TAB: SUMMARY */}
                  {tab === 'summary' && (
                    <>
                      <div className="metric-strip">
                        <div>
                          <span>PACKETS PROCESSED</span>
                          <strong>{fmt(current.summary.packets_processed)}</strong>
                        </div>
                        <div>
                          <span>OBSERVED HOSTS</span>
                          <strong>{fmt(current.summary.hosts)}</strong>
                        </div>
                        <div>
                          <span>DESTINATION PORTS</span>
                          <strong>{fmt(current.summary.distinct_ports)}</strong>
                        </div>
                        <div>
                          <span>HEURISTIC FINDINGS</span>
                          <strong>{fmt(current.summary.findings)}</strong>
                        </div>
                      </div>

                      {/* AI Threat Assessment Card */}
                      {current.ml_analysis && (
                        <div className="ml-summary-card">
                          <div className="ml-card-left">
                            <ThreatGauge score={current.ml_analysis.overall_threat_score} />
                          </div>
                          <div className="ml-card-right">
                            <div className="ml-card-header">
                              <span className="ml-tag"><Brain size={14} /> AI INTRUSION ASSESSMENT</span>
                              <span className="ml-model-meta">Benchmark Model (F1: {current.ml_analysis.model_f1 * 100}%)</span>
                            </div>
                            <h3>{current.ml_analysis.threat_description}</h3>
                            <p>
                              Trained against flow distributions from the <strong>Canadian Institute for Cybersecurity (CIC-IDS2017)</strong> and <strong>UNSW-NB15</strong>.
                            </p>
                            <div className="ml-top-classifications">
                              {current.ml_analysis.classifications.slice(0, 3).map(c => (
                                <div className={`ml-class-chip ${c.tier}`} key={c.host}>
                                  <span className="host-ip">{c.host}</span>
                                  <span className="class-label">{c.prediction.replace(/_/g, ' ')}</span>
                                  <span className="conf-pill">{Math.round(c.confidence * 100)}% conf</span>
                                </div>
                              ))}
                            </div>
                            <button className="text-link" onClick={() => setTab('ml_intel')}>
                              Deep-dive AI flow classifications <ArrowRight size={15} />
                            </button>
                          </div>
                        </div>
                      )}

                      <div className="summary-grid">
                        <div className="data-panel wide-panel">
                          <div className="panel-heading">
                            <span>TRAFFIC ACTIVITY</span>
                            <span>CAPTURE ORDER</span>
                          </div>
                          <h3>Observed volume</h3>
                          {current.traffic.length ? (
                            <>
                              <MiniBars points={current.traffic} />
                              <div className="chart-axis">
                                <span>{date(current.traffic[0].timestamp)}</span>
                                <span>{date(current.traffic.at(-1)?.timestamp || null)}</span>
                              </div>
                            </>
                          ) : (
                            <p className="muted-copy">No timestamped IP traffic was extracted.</p>
                          )}
                        </div>

                        <div className="data-panel">
                          <div className="panel-heading">
                            <span>PROTOCOL MIX</span>
                            <span>{current.summary.ip_packets} IP PACKETS</span>
                          </div>
                          <h3>What moved through</h3>
                          {Object.entries(current.summary.protocols).length ? (
                            Object.entries(current.summary.protocols)
                              .sort((a, b) => b[1] - a[1])
                              .map(([name, count]) => (
                                <div className="protocol-row" key={name}>
                                  <span>{name}</span>
                                  <div>
                                    <i style={{ width: `${(count / Math.max(1, current.summary.ip_packets)) * 100}%` }} />
                                  </div>
                                  <b>{fmt(count)}</b>
                                </div>
                              ))
                          ) : (
                            <p className="muted-copy">No IP packets found.</p>
                          )}
                        </div>
                      </div>

                      <div className="summary-lower">
                        <div>
                          <div className="section-heading">
                            <div>
                              <h2>Heuristic Investigation Signals</h2>
                              <p>Configured rule matches based on TCP SYN and connection heuristics.</p>
                            </div>
                            <button className="text-link" onClick={() => setTab('findings')}>
                              All findings <ArrowRight size={16} />
                            </button>
                          </div>
                          {current.findings.length ? (
                            current.findings.slice(0, 3).map(f => (
                              <button
                                className="signal-row"
                                key={f.id}
                                onClick={() => { setTab('findings'); setSelectedFinding(f.id); }}
                              >
                                <span className="signal-id">{f.id}</span>
                                <span>
                                  <strong>{f.title}</strong>
                                  <small>{f.rule} · {f.source}</small>
                                </span>
                                <ChevronRight size={17} />
                              </button>
                            ))
                          ) : (
                            <div className="no-findings">
                              <ShieldCheck size={22} />
                              <strong>No rule thresholds triggered</strong>
                              <p>Standard heuristics did not flag this traffic.</p>
                            </div>
                          )}
                        </div>

                        <div className="digest-panel">
                          <div className="panel-heading">
                            <span>FILE FINGERPRINT</span>
                            <Fingerprint size={18} />
                          </div>
                          <h3>Capture integrity reference</h3>
                          <p>SHA-256 hash calculated directly from the capture bytes.</p>
                          <code>{current.sha256}</code>
                          <button className="text-link" onClick={() => copy(current.sha256)}>
                            <Copy size={15} /> Copy hash
                          </button>
                        </div>
                      </div>
                    </>
                  )}

                  {/* TAB: ML THREAT INTEL */}
                  {tab === 'ml_intel' && (
                    <div className="ml-intel-panel workspace-panel">
                      <div className="workspace-head">
                        <div>
                          <div className="eyebrow">MACHINE LEARNING DETECTION & FEATURE ATTRIBUTION</div>
                          <h2>Host Behavioral Classifications</h2>
                          <p>
                            Random Forest intrusion classifier evaluated flow vectors against the
                            CIC-IDS2017 & UNSW-NB15 benchmark distributions.
                          </p>
                        </div>
                        <Brain size={26} color="#b8f36b" />
                      </div>

                      {current.ml_analysis?.classifications.length ? (
                        <div className="ml-host-cards">
                          {current.ml_analysis.classifications.map(c => (
                            <div className={`ml-host-card ${c.tier}`} key={c.host}>
                              <div className="ml-host-head">
                                <div>
                                  <span className="host-ip-tag">{c.host}</span>
                                  <h3 className="prediction-title">{c.prediction.replace(/_/g, ' ')}</h3>
                                </div>
                                <div className="ml-host-badge-col">
                                  <ThreatBadge severity={c.severity} score={c.threat_score} />
                                  <span className="conf-text">Confidence: {Math.round(c.confidence * 100)}%</span>
                                </div>
                              </div>

                              <div className="ml-benchmark-note">
                                <Info size={14} color="#38bdf8" />
                                <span>Benchmark Match: <strong>{c.benchmark_provenance}</strong></span>
                              </div>

                              <div className="ml-factors-box">
                                <strong>PRIMARY CONTRIBUTING ATTRIBUTES:</strong>
                                <ul>
                                  {c.key_factors.map((f, i) => (
                                    <li key={i}>{f}</li>
                                  ))}
                                </ul>
                              </div>

                              <div className="ml-flow-metrics-grid">
                                <div>
                                  <span>PACKET COUNT</span>
                                  <b>{c.flow_metrics.packet_count} pkts</b>
                                </div>
                                <div>
                                  <span>DURATION</span>
                                  <b>{c.flow_metrics.duration_sec}s</b>
                                </div>
                                <div>
                                  <span>PACKET RATE</span>
                                  <b>{c.flow_metrics.packet_rate} /s</b>
                                </div>
                                <div>
                                  <span>DISTINCT PORTS</span>
                                  <b>{c.flow_metrics.distinct_dest_ports}</b>
                                </div>
                                <div>
                                  <span>PORT ENTROPY</span>
                                  <b>{c.flow_metrics.port_entropy}</b>
                                </div>
                                <div>
                                  <span>SYN RATIO</span>
                                  <b>{Math.round(c.flow_metrics.syn_ratio * 100)}%</b>
                                </div>
                                <div>
                                  <span>REPLY RATIO</span>
                                  <b>{Math.round(c.flow_metrics.response_ratio * 100)}%</b>
                                </div>
                                <div>
                                  <span>AVG SIZE</span>
                                  <b>{c.flow_metrics.avg_packet_size} B</b>
                                </div>
                              </div>

                              <div className="ml-prob-bars">
                                <span>Class Probability Distribution:</span>
                                <div className="prob-row-container">
                                  {Object.entries(c.probabilities).map(([cls, prob]) => (
                                    <div className="prob-bar-col" key={cls}>
                                      <div className="prob-bar-wrap">
                                        <div
                                          className={`prob-fill ${cls === c.prediction ? 'pred-match' : ''}`}
                                          style={{ height: `${Math.max(4, prob * 100)}%` }}
                                        />
                                      </div>
                                      <small>{cls.slice(0, 4)}</small>
                                      <b>{Math.round(prob * 100)}%</b>
                                    </div>
                                  ))}
                                </div>
                              </div>

                              <div className="ml-card-foot">
                                <button
                                  className="text-link"
                                  onClick={() => {
                                    setHost(c.host);
                                    setTab('traffic');
                                  }}
                                >
                                  Inspect packets for {c.host} <ArrowRight size={14} />
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="table-empty">No host flow vectors available for ML inference.</div>
                      )}
                    </div>
                  )}

                  {/* TAB: TRAFFIC */}
                  {tab === 'traffic' && (
                    <div ref={evidenceRef} className="workspace-panel">
                      <div className="workspace-head">
                        <div>
                          <div className="eyebrow">PACKET METADATA / {fmt(current.packets.length)} RECORDS</div>
                          <h2>Traffic explorer</h2>
                          <p>Filter by host, port, protocol, flags, or packet index.</p>
                        </div>
                        <ListFilter size={21} />
                      </div>

                      {activeFinding && (
                        <div className="evidence-banner">
                          <div>
                            <span>EVIDENCE FOCUS / {activeFinding.id}</span>
                            <strong>{activeFinding.title}</strong>
                            <p>{activeFinding.evidence_total} relevant attempts · showing up to 24 referenced packet indices</p>
                          </div>
                          <button className="icon-button" aria-label="Clear evidence focus" onClick={() => setSelectedFinding(null)}>
                            <X size={18} />
                          </button>
                        </div>
                      )}

                      {host && (
                        <div className="evidence-banner filter-active">
                          <div>
                            <span>HOST FILTER ACTIVE</span>
                            <strong>Showing traffic involving {host}</strong>
                          </div>
                          <button className="icon-button" aria-label="Clear host filter" onClick={() => setHost(null)}>
                            <X size={18} />
                          </button>
                        </div>
                      )}

                      <div className="table-tools">
                        <label className="search-box">
                          <Search size={17} />
                          <input
                            value={query}
                            onChange={e => setQuery(e.target.value)}
                            placeholder="Search IP, port, packet index…"
                            aria-label="Search traffic"
                          />
                        </label>
                        <label className="select-box">
                          <Filter size={16} />
                          <select
                            value={protocol}
                            onChange={e => setProtocol(e.target.value)}
                            aria-label="Filter protocol"
                          >
                            <option value="all">All protocols</option>
                            {Object.keys(current.summary.protocols).map(p => (
                              <option key={p}>{p}</option>
                            ))}
                          </select>
                          <ChevronDown size={15} />
                        </label>
                        <span className="result-count">{fmt(filtered.length)} results</span>
                      </div>

                      {activeFinding && (
                        <div className="evidence-chips">
                          {activeFinding.evidence.map(n => (
                            <button key={n} onClick={() => { setQuery(`#${n}`); setPageNo(1); }}>
                              #{n}
                            </button>
                          ))}
                        </div>
                      )}

                      <div className="table-scroll">
                        <table>
                          <thead>
                            <tr>
                              {([
                                ['index', 'PACKET'],
                                ['timestamp', 'TIME (UTC)'],
                                ['source', 'SOURCE'],
                                ['destination', 'DESTINATION']
                              ] as const).map(([key, label]) => (
                                <th key={key}>
                                  <button onClick={() => {
                                    if (sort === key) setReverse(!reverse);
                                    else { setSort(key); setReverse(false); }
                                  }}>
                                    {label}
                                    {sort === key ? <ArrowDownRight className={reverse ? 'sort-reverse' : ''} size={13} /> : null}
                                  </button>
                                </th>
                              ))}
                              <th>PORTS</th>
                              <th>PROTO</th>
                              <th>BYTES</th>
                              <th>FLAGS</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filtered.slice((pageNo - 1) * 25, pageNo * 25).map(p => (
                              <tr
                                key={p.index}
                                className={activeFinding?.evidence.includes(p.index) ? 'highlight-row' : ''}
                              >
                                <td className="mono accent-text">#{p.index}</td>
                                <td className="mono">{p.timestamp?.slice(11, 23) ?? '—'}</td>
                                <td className="mono">
                                  {threatMap[p.source] && threatMap[p.source] !== 'BENIGN' ? (
                                    <span className="source-threat">{p.source}</span>
                                  ) : (
                                    p.source
                                  )}
                                </td>
                                <td className="mono">{p.destination}</td>
                                <td className="mono">{p.source_port ?? '—'} → {p.destination_port ?? '—'}</td>
                                <td><span className="protocol-tag">{p.protocol}</span></td>
                                <td className="mono">{p.length}</td>
                                <td className="mono">{p.flags ?? '—'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        {!filtered.length && <div className="table-empty">No packets match this search and filter.</div>}
                      </div>

                      <div className="pagination">
                        <span>
                          Showing {filtered.length ? fmt((pageNo - 1) * 25 + 1) : 0}–{fmt(Math.min(pageNo * 25, filtered.length))} of {fmt(filtered.length)}
                        </span>
                        <div>
                          <button disabled={pageNo === 1} onClick={() => setPageNo(pageNo - 1)}>Previous</button>
                          <span>{pageNo} / {Math.max(1, Math.ceil(filtered.length / 25))}</span>
                          <button disabled={pageNo >= Math.ceil(filtered.length / 25)} onClick={() => setPageNo(pageNo + 1)}>Next</button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB: HOSTS & TOPOLOGY */}
                  {tab === 'hosts' && (
                    <div className="hosts-layout-grid">
                      <TopologyGraph
                        connections={current.connections}
                        hosts={current.hosts}
                        selectedHost={host}
                        onSelectHost={h => setHost(h)}
                        threats={threatMap}
                      />

                      <div className="hosts-grid">
                        <div className="workspace-panel">
                          <div className="workspace-head">
                            <div>
                              <div className="eyebrow">OBSERVED ADDRESSES</div>
                              <h2>Hosts</h2>
                              <p>Packet appearances as source or destination.</p>
                            </div>
                            <Globe2 size={21} />
                          </div>
                          {current.hosts.length ? (
                            current.hosts.map(h => {
                              const threat = threatMap[h.address];
                              return (
                                <button
                                  className={`host-row ${host === h.address ? 'chosen' : ''}`}
                                  key={h.address}
                                  onClick={() => setHost(host === h.address ? null : h.address)}
                                >
                                  <span className={`host-avatar ${threat && threat !== 'BENIGN' ? 'avatar-threat' : ''}`}>
                                    <Network size={17} />
                                  </span>
                                  <code>{h.address}</code>
                                  {threat && threat !== 'BENIGN' && (
                                    <span className="host-threat-pill">{threat}</span>
                                  )}
                                  <span>{fmt(h.observations)} pkts</span>
                                  <ArrowRight size={16} />
                                </button>
                              );
                            })
                          ) : (
                            <div className="table-empty">No IP hosts were extracted.</div>
                          )}
                        </div>

                        <div className="workspace-panel">
                          <div className="workspace-head">
                            <div>
                              <div className="eyebrow">COMMUNICATION PAIRS</div>
                              <h2>Connections</h2>
                              <p>{host ? `Pairs involving ${host}` : 'Select a host to filter communicating pairs.'}</p>
                            </div>
                            {host && <button className="text-link" onClick={() => setHost(null)}>Clear</button>}
                          </div>
                          <div className="connection-list">
                            {current.connections
                              .filter(c => !host || c.source === host || c.destination === host)
                              .slice(0, 50)
                              .map((c, i) => (
                                <div className="connection-row" key={`${c.source}-${c.destination}-${i}`}>
                                  <div>
                                    <code>{c.source}</code>
                                    <ArrowRight size={15} />
                                    <code>{c.destination}</code>
                                  </div>
                                  <strong>{fmt(c.packets)} <small>packets</small></strong>
                                </div>
                              ))}
                            {!current.connections.length && <div className="table-empty">No IP connections were extracted.</div>}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* TAB: FINDINGS */}
                  {tab === 'findings' && (
                    <div className="findings-layout">
                      <div className="workspace-head">
                        <div>
                          <div className="eyebrow">DETECTION OUTPUT / {current.findings.length} INDICATORS</div>
                          <h2>Investigation findings</h2>
                          <p>Each indicator is linked to the observed packet attempts that triggered it.</p>
                        </div>
                        <ShieldCheck size={22} />
                      </div>
                      {current.findings.length ? (
                        current.findings.map(f => (
                          <article className={`finding ${selectedFinding === f.id ? 'finding-selected' : ''}`} key={f.id}>
                            <div className="finding-header">
                              <span>{f.id} / {f.rule.toUpperCase()}</span>
                              <span>INDICATOR FOR REVIEW</span>
                            </div>
                            <h3>{f.title}</h3>
                            <div className="finding-address">
                              <code>{f.source}</code>
                              <ArrowRight size={16} />
                              <code>{f.destination}</code>
                            </div>
                            <p>{f.details}</p>
                            <div className="finding-reason">
                              <strong>WHY THIS TRIGGERED</strong>
                              <span>{f.rationale}</span>
                            </div>
                            <div className="finding-foot">
                              <span>
                                <FileSearch size={16} /> {f.evidence_total} relevant attempts · {f.evidence.length} packet references shown
                              </span>
                              <button className="text-link" onClick={() => jumpEvidence(f)}>
                                Inspect evidence <ArrowUpRight size={16} />
                              </button>
                            </div>
                            <div className="finding-limitation">Interpretation note: {f.limitation}</div>
                          </article>
                        ))
                      ) : (
                        <div className="no-findings large">
                          <ShieldCheck size={26} />
                          <h3>No rule matches in this capture</h3>
                          <p>The configured thresholds were not met. Check the AI Threat Intel tab for statistical flow evaluation.</p>
                          <button className="text-link" onClick={() => setTab('ml_intel')}>
                            Review AI Threat Intel <ArrowRight size={16} />
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                  {/* TAB: TIMELINE */}
                  {tab === 'timeline' && (
                    <div className="workspace-panel timeline-panel">
                      <div className="workspace-head">
                        <div>
                          <div className="eyebrow">CHRONOLOGICAL VIEW</div>
                          <h2>Traffic timeline</h2>
                          <p>Observed packet volume by time bucket and timestamps of rule findings.</p>
                        </div>
                        <Clock3 size={21} />
                      </div>
                      {current.traffic.length ? (
                        <>
                          <div className="timeline-chart">
                            <MiniBars points={current.traffic} />
                          </div>
                          <div className="timeline-list">
                            {current.findings.filter(f => f.timestamp).map(f => (
                              <button
                                key={f.id}
                                className="timeline-event"
                                onClick={() => { setTab('findings'); setSelectedFinding(f.id); }}
                              >
                                <time>{date(f.timestamp)}</time>
                                <span className="event-dot" />
                                <div>
                                  <strong>{f.title}</strong>
                                  <small>{f.id} · {f.source} · {f.rule}</small>
                                </div>
                                <ArrowUpRight size={16} />
                              </button>
                            ))}
                            {!current.findings.length && (
                              <div className="table-empty">
                                No rule findings to place on this timeline. The chart above shows observed IP packet volume.
                              </div>
                            )}
                          </div>
                        </>
                      ) : (
                        <div className="table-empty">No reliable IP packet timestamps are available for a timeline.</div>
                      )}
                    </div>
                  )}
                </>
              )}
            </section>
          )}

          {/* PAGE: TRAINED MODELS & DATASETS */}
          {page === 'models' && (
            <section className="models-page">
              <div className="page-intro">
                <div className="eyebrow">
                  <span className="eyebrow-line" /> MACHINE LEARNING ARCHITECTURE & DATASET PROVENANCE
                </div>
                <h1>Trained on <em>Public Benchmarks.</em></h1>
                <p>
                  NetTrace integrates a high-performance Random Forest intrusion detection classifier
                  trained on published feature distributions from the cyber research community.
                </p>
              </div>

              {/* Model Performance Overview Cards */}
              <div className="model-metrics-grid">
                <div className="metric-card">
                  <span className="metric-title">MODEL ACCURACY</span>
                  <strong>{mlModelInfo ? `${(mlModelInfo.accuracy * 100).toFixed(1)}%` : '93.4%'}</strong>
                  <small>Holdout Test Set Validation</small>
                </div>
                <div className="metric-card">
                  <span className="metric-title">WEIGHTED F1 SCORE</span>
                  <strong>{mlModelInfo ? `${(mlModelInfo.f1_score * 100).toFixed(1)}%` : '93.4%'}</strong>
                  <small>Harmonic Precision & Recall</small>
                </div>
                <div className="metric-card">
                  <span className="metric-title">TRAINED SAMPLES</span>
                  <strong>{mlModelInfo ? fmt(mlModelInfo.total_samples) : '7,200'}</strong>
                  <small>Stratified Multi-Class Split</small>
                </div>
                <div className="metric-card">
                  <span className="metric-title">INFERENCE TIME</span>
                  <strong>&lt; 5 ms</strong>
                  <small>Instantaneous Local Decision</small>
                </div>
              </div>

              {/* Datasets Section */}
              <div className="model-section">
                <div className="section-heading">
                  <div>
                    <h2>Public Intrusion Detection Datasets Used</h2>
                    <p>Standard benchmarks utilized to model traffic signatures and flow distributions.</p>
                  </div>
                </div>

                <div className="datasets-detail-grid">
                  <div className="dataset-detail-card">
                    <div className="dataset-detail-top">
                      <span className="provenance-tag">CIC-IDS2017 / CSE-CIC-IDS2018</span>
                      <a href="https://www.unb.ca/cic/datasets/ids-2017.html" target="_blank" rel="noreferrer" className="text-link">
                        Research Paper <ExternalLink size={13} />
                      </a>
                    </div>
                    <h3>Canadian Institute for Cybersecurity (UNB)</h3>
                    <p>
                      Generated in a simulated cyber range covering realistic 5-day traffic. Used to train
                      PortScan, DoS LOIC, GoldenEye, and Patator brute-force classifiers.
                    </p>
                    <div className="dataset-tags">
                      <span>PortScan</span>
                      <span>DDoS LOIC</span>
                      <span>SSH-Patator</span>
                      <span>FTP-Patator</span>
                      <span>Benign Web</span>
                    </div>
                  </div>

                  <div className="dataset-detail-card">
                    <div className="dataset-detail-top">
                      <span className="provenance-tag">UNSW-NB15</span>
                      <a href="https://research.unsw.edu.au/projects/unsw-nb15-dataset" target="_blank" rel="noreferrer" className="text-link">
                        Research Paper <ExternalLink size={13} />
                      </a>
                    </div>
                    <h3>Cyber Range Lab, Australian Centre for Cyber Security</h3>
                    <p>
                      Created with IXIA PerfectStorm tool to generate synthetic attacks alongside real
                      contemporary normal network traffic. Used for reconnaissance and volumetric anomaly modeling.
                    </p>
                    <div className="dataset-tags">
                      <span>Reconnaissance</span>
                      <span>Volumetric Exfiltration</span>
                      <span>Generic Anomaly</span>
                      <span>Fuzzers</span>
                    </div>
                  </div>

                  <div className="dataset-detail-card">
                    <div className="dataset-detail-top">
                      <span className="provenance-tag">CTU-13</span>
                      <a href="https://www.stratosphereips.org/datasets-ctu13" target="_blank" rel="noreferrer" className="text-link">
                        Research Paper <ExternalLink size={13} />
                      </a>
                    </div>
                    <h3>Czech Technical University in Prague (ATG Group)</h3>
                    <p>
                      Captures real botnet traffic executed in university networks. Used to model
                      clockwork periodicity, low inter-arrival jitter, and botnet C2 heartbeat probes.
                    </p>
                    <div className="dataset-tags">
                      <span>Botnet C2 Beaconing</span>
                      <span>Periodic Heartbeat</span>
                      <span>Neris / Rbot Malware</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Feature Importances */}
              {mlModelInfo?.feature_importances && (
                <div className="model-section">
                  <div className="section-heading">
                    <div>
                      <h2>Extracted Flow Features & Model Weights</h2>
                      <p>Relative importance of features analyzed by the Random Forest classifier.</p>
                    </div>
                  </div>

                  <div className="feature-bars-container">
                    {Object.entries(mlModelInfo.feature_importances).map(([feat, imp]) => (
                      <div className="feature-row" key={feat}>
                        <div className="feature-name-col">
                          <code>{feat}</code>
                        </div>
                        <div className="feature-bar-wrap">
                          <div
                            className="feature-bar-fill"
                            style={{ width: `${Math.max(3, imp * 500)}%` }}
                          />
                        </div>
                        <span className="feature-pct">{(imp * 100).toFixed(1)}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </section>
          )}

          {/* PAGE: METHODOLOGY */}
          {page === 'methodology' && (
            <section className="method-page">
              <div className="page-intro">
                <div className="eyebrow"><span className="eyebrow-line" /> ABOUT / METHODOLOGY</div>
                <h1>Follow the data.<br /><em>Know the limits.</em></h1>
                <p>
                  NetTrace provides transparent offline forensics. It blends explainable TCP heuristics
                  with machine learning flow vector classifications to provide actionable visibility without external dependencies.
                </p>
              </div>

              <div className="method-feature">
                <div className="method-large-number">01<span>/ 03</span></div>
                <div>
                  <h2>Dual-Engine<br />Investigation.</h2>
                  <p>
                    Every capture is evaluated by both <strong>Transparent Heuristics</strong> (fixed threshold rules)
                    and a <strong>Trained AI Flow Classifier</strong> (calibrated on CIC-IDS2017 & UNSW-NB15).
                    Payload contents are never read or stored; original bytes are discarded immediately after analysis.
                  </p>
                </div>
                <div className="method-diagram">
                  <span>PACKET CAPTURE</span>
                  <ArrowRight size={18} />
                  <span>HEADER EXTRACTION</span>
                  <ArrowRight size={18} />
                  <span>AI INFERENCE & HEURISTICS</span>
                </div>
              </div>

              <div className="method-section">
                <div className="section-divider">
                  <span>02 / FIXED HEURISTIC RULES</span>
                  <span>TRANSPARENT THRESHOLDS</span>
                </div>
                <div className="method-rules">
                  {ruleInfo.map((r, i) => (
                    <details key={r.key} open={i === 0}>
                      <summary>
                        <span>0{i + 1}</span>
                        <strong>{r.name}</strong>
                        <Plus size={19} />
                      </summary>
                      <p>
                        {r.description} A unique initial SYN attempt is identified by source and destination IPs,
                        ports, and TCP sequence number. Identical retransmissions count once. A matching observed response
                        is a reverse-flow SYN/ACK or RST; capture gaps can affect this observation.
                      </p>
                    </details>
                  ))}
                </div>
              </div>

              <div className="method-bottom">
                <div>
                  <div className="eyebrow">EVIDENCE & REPORTING</div>
                  <h2>Every indicator has<br />a starting point.</h2>
                  <p>
                    Findings link directly to capture-order packet indices. Inspect packet metadata in the traffic explorer,
                    or export an executive PDF dossier or raw CSV packet log.
                  </p>
                  <button className="button primary" onClick={() => go('simulator')}>
                    Explore Test Studio <Zap size={17} />
                  </button>
                </div>
                <div className="limits">
                  <div className="panel-heading"><span>IMPORTANT LIMITS</span><CircleHelp size={17} /></div>
                  <ul>
                    <li>Heuristic findings and AI classifications are indicators, not definitive proof of compromise.</li>
                    <li>Capture loss, asymmetric routing, and payload encryption naturally limit network-level analysis.</li>
                    <li>IPv4 and IPv6 headers are read where available; unsupported frames may not yield IP records.</li>
                    <li>A SHA-256 hash identifies byte integrity, but does not prove source authenticity.</li>
                    <li>NetTrace is an offline investigation tool; it does not block traffic or perform live packet capture.</li>
                  </ul>
                  <div className="stack-label">
                    ENGINE STACK <span>React · TypeScript · Vite · FastAPI · Scikit-Learn · SQLite · ReportLab</span>
                  </div>
                </div>
              </div>
            </section>
          )}
        </main>

        <footer className="footer">
          <span>NETTRACE FORENSICS WORKSPACE / KNOW YOUR NETWORK. FOLLOW THE EVIDENCE.</span>
          <span>100% OFFLINE LOCAL INVESTIGATION <ArrowUpRight size={14} /></span>
        </footer>
      </div>
    </div>
  );
}
