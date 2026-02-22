'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Plus, X, Shield, Loader2, AlertTriangle, Bug, Server, Globe, Cloud, ChevronRight } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Finding, AttackChain, Asset } from '@/types';
import Image from 'next/image';

type Stage = 'search' | 'form' | 'loading' | 'results';
type ResultTab = 'recon' | 'exploit';

const API_BASE = process.env.NEXT_PUBLIC_API || 'http://localhost:8000';
const WS_BASE = process.env.NEXT_PUBLIC_WS || API_BASE.replace(/^http/, 'ws');

const LOCUST_COUNT = 22;
const SWARM = Array.from({ length: LOCUST_COUNT }, (_, i) => ({
  id: i,
  yPct: 5 + Math.random() * 85,
  delay: Math.pow(Math.random(), 0.5) * 3,
  duration: 1.8 + Math.random() * 2,
  scale: 0.85 + Math.random() * 0.7,
  flipY: Math.random() > 0.5,
}));

const FORBIDDEN_ACTION_OPTIONS = [
  'destructive_payloads',
  'dos_testing',
  'social_engineering',
  'physical_access',
];

const TYPEWRITER_PHRASES = [
  'Target Acquisition',
  'Release the Swarm',
  'Initialize Recon',
  'Breach Protocol',
  'Unleash the Horde',
];

const LOADING_PHASES = [
  { label: 'Initializing recon agents...', icon: Globe },
  { label: 'Scanning target surfaces...', icon: Server },
  { label: 'Running exploit analysis...', icon: Bug },
  { label: 'Executing lateral movement...', icon: Shield },
  { label: 'Compiling vulnerability report...', icon: AlertTriangle },
];

const EVENT_PHASE_MAP: Record<string, number> = {
  cycle_started: 1,
  recon_complete: 2,
  exploit_complete: 3,
  lateral_complete: 4,
  cycle_complete: 4,
};

function formatLogEntry(msg: Record<string, unknown>): string | null {
  if ('ping' in msg) return null;
  const event = String(msg.event ?? '');
  switch (event) {
    case 'cycle_started':
      return `ENGAGEMENT STARTED ── id: ${String(msg.engagement_id).slice(0, 12)}`;
    case 'recon_complete':
      return `RECON COMPLETE ── ${msg.asset_count} assets discovered`;
    case 'exploit_complete':
      return `EXPLOIT COMPLETE ── ${msg.finding_count} vulnerabilities identified`;
    case 'lateral_complete':
      return `LATERAL MOVEMENT COMPLETE ── ${msg.chain_count} attack chains forged`;
    case 'demo_seeded':
      return `DEMO SEED PLANTED ── ${msg.affected_url} (id: ${String(msg.finding_id ?? '').slice(0, 8)})`;
    case 'github_issues_created':
      return `GITHUB ISSUES FILED ── ${Array.isArray(msg.issue_urls) ? msg.issue_urls.length : 0} reports`;
    case 'cycle_complete':
      return `CYCLE COMPLETE ── compiling intelligence report`;
    default: {
      if (!event) return null;
      const extras = Object.entries(msg)
        .filter(([k]) => k !== 'event')
        .map(([k, v]) => `${k}: ${String(v)}`)
        .join(' · ');
      return `${event.toUpperCase()}${extras ? ` ── ${extras}` : ''}`;
    }
  }
}

function parseCloudAccount(str: string): { provider: 'aws' | 'gcp' | 'azure'; account_id?: string; project_id?: string } | null {
  const colonIdx = str.indexOf(':');
  if (colonIdx === -1) return null;
  const providerRaw = str.slice(0, colonIdx).toLowerCase().trim();
  const id = str.slice(colonIdx + 1).trim();
  if (!['aws', 'gcp', 'azure'].includes(providerRaw)) return null;
  const provider = providerRaw as 'aws' | 'gcp' | 'azure';
  if (provider === 'gcp') return { provider, project_id: id };
  return { provider, account_id: id };
}

function blastStyle(score: number) {
  if (score >= 0.75) return { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/25', label: 'CRITICAL' };
  if (score >= 0.5)  return { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/25', label: 'HIGH' };
  if (score >= 0.25) return { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/25', label: 'MEDIUM' };
  return { text: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/25', label: 'LOW' };
}

function surfaceScoreStyle(score: number) {
  if (score >= 0.75) return 'text-red-400';
  if (score >= 0.5)  return 'text-orange-400';
  if (score >= 0.25) return 'text-yellow-400';
  return 'text-green-400';
}

const severityColor: Record<string, { badge: string; row: string }> = {
  critical: { badge: 'bg-red-500/20 text-red-400 border-red-500/30', row: 'bg-red-500/[0.06]' },
  high:     { badge: 'bg-orange-500/20 text-orange-400 border-orange-500/30', row: 'bg-orange-500/[0.06]' },
  medium:   { badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', row: 'bg-yellow-500/[0.06]' },
  low:      { badge: 'bg-blue-500/20 text-blue-400 border-blue-500/30', row: 'bg-blue-500/[0.06]' },
  info:     { badge: 'bg-muted text-muted-foreground border-border', row: 'bg-muted/30' },
};

// ── Attack Chain Card ─────────────────────────────────────────────────────────

const AttackChainCard = ({ chain, index }: { chain: AttackChain; index: number }) => {
  const [expanded, setExpanded] = useState(index === 0);
  const bs = blastStyle(chain.blast_radius_score);

  return (
    <motion.div
      className={`border rounded-xl overflow-hidden ${bs.border} ${bs.bg}`}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.08 }}
    >
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-6 py-4 flex items-start justify-between text-left gap-4"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <span className={`font-mono text-[10px] uppercase tracking-[0.2em] ${bs.text}`}>
              Chain {String(index + 1).padStart(2, '0')}
            </span>
            <Badge variant="outline" className={`font-mono text-[10px] px-1.5 py-0 ${bs.text} border-current`}>
              {bs.label}
            </Badge>
          </div>
          <div className="font-mono text-sm text-foreground truncate">{chain.entry_point}</div>
          <div className="font-mono text-xs text-muted-foreground mt-1">{chain.blast_radius_summary}</div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <div className="text-right">
            <div className="font-mono text-[10px] text-muted-foreground uppercase tracking-widest">Blast Radius</div>
            <div className={`font-mono text-3xl font-bold tabular-nums leading-none mt-0.5 ${bs.text}`}>
              {Math.round(chain.blast_radius_score * 100)}%
            </div>
          </div>
          <ChevronRight className={`w-4 h-4 text-muted-foreground/50 transition-transform duration-200 ${expanded ? 'rotate-90' : ''}`} />
        </div>
      </button>

      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            {/* Pivot path */}
            {chain.pivot_path.length > 0 && (
              <div className="px-6 py-5 border-t border-border/40">
                <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground mb-4">
                  ── Attack Path ──────────────────────────
                </div>
                <div>
                  {chain.pivot_path.map((step, i) => (
                    <div key={i} className="flex gap-3">
                      <div className="flex flex-col items-center">
                        <div className={`w-5 h-5 rounded-full flex items-center justify-center font-mono text-[10px] font-bold shrink-0 border ${bs.border} ${bs.text} bg-background`}>
                          {step.step}
                        </div>
                        {i < chain.pivot_path.length - 1 && (
                          <div className="w-px bg-border/40 my-1 flex-1" style={{ minHeight: 12 }} />
                        )}
                      </div>
                      <div className={`${i < chain.pivot_path.length - 1 ? 'pb-4' : 'pb-0'} min-w-0`}>
                        <div className="font-mono text-sm text-foreground font-medium">{step.asset}</div>
                        <div className={`font-mono text-xs mt-0.5 ${bs.text}`}>{step.action}</div>
                        <div className="font-mono text-xs text-muted-foreground mt-0.5 leading-relaxed">{step.detail}</div>
                        {step.mitre && (
                          <span className="inline-block mt-1 px-1.5 py-0.5 rounded bg-muted/50 border border-border/40 font-mono text-[10px] text-muted-foreground">
                            {step.mitre}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Sensitive stores */}
            {chain.reachable_sensitive_stores.length > 0 && (
              <div className="px-6 py-5 border-t border-border/40">
                <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground mb-3">
                  ── Sensitive Stores Reached ─────────────
                </div>
                <div className="space-y-2">
                  {chain.reachable_sensitive_stores.map((store, i) => (
                    <div key={i} className="flex gap-3 items-start p-3 rounded-lg bg-black/20 border border-border/30">
                      <Badge variant="outline" className="font-mono text-[10px] shrink-0 mt-px">{store.type}</Badge>
                      <div className="min-w-0">
                        <div className="font-mono text-xs text-foreground font-medium">{store.asset}</div>
                        <div className="font-mono text-xs text-muted-foreground mt-0.5">{store.contents}</div>
                        {store.credentials_used && (
                          <div className="font-mono text-[10px] text-muted-foreground/50 mt-0.5">via: {store.credentials_used}</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE + reasoning row */}
            <div className="border-t border-border/40">
              {chain.mitre_techniques.length > 0 && (
                <div className="px-6 py-3 flex flex-wrap gap-1.5 items-center border-b border-border/40">
                  <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground mr-1">MITRE</span>
                  {chain.mitre_techniques.map((t) => (
                    <Badge key={t} variant="outline" className="font-mono text-[10px] text-muted-foreground px-1.5 py-0">{t}</Badge>
                  ))}
                </div>
              )}
              {chain.gemini_reasoning && (
                <div className="px-6 py-4">
                  <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground mb-2">
                    ── AI Analysis ──────────────────────────
                  </div>
                  <p className="font-mono text-xs text-foreground/55 leading-relaxed">{chain.gemini_reasoning}</p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

// ── Tag Input ─────────────────────────────────────────────────────────────────

const TagInput = ({
  label,
  icon: Icon,
  items,
  onAdd,
  onRemove,
  placeholder,
}: {
  label: string;
  icon: React.ElementType;
  items: string[];
  onAdd: (v: string) => void;
  onRemove: (v: string) => void;
  placeholder: string;
}) => {
  const [val, setVal] = useState('');
  const add = () => {
    if (val.trim()) { onAdd(val.trim()); setVal(''); }
  };
  return (
    <div className="space-y-2">
      <label className="text-xs font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-2">
        <Icon className="w-3.5 h-3.5" /> {label}
      </label>
      <div className="flex gap-2">
        <Input
          value={val}
          onChange={(e) => setVal(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), add())}
          placeholder={placeholder}
          className="bg-background border-border text-foreground placeholder:text-muted-foreground font-mono text-sm"
        />
        <Button type="button" size="icon" variant="outline" onClick={add}
          className="shrink-0 border-border hover:bg-primary hover:text-primary-foreground">
          <Plus className="w-4 h-4" />
        </Button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {items.map((item) => (
            <Badge key={item} variant="secondary" className="font-mono text-xs bg-secondary text-secondary-foreground gap-1 pr-1">
              {item}
              <button onClick={() => onRemove(item)} className="hover:text-destructive ml-1">
                <X className="w-3 h-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
};

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function Home() {
  const [stage, setStage] = useState<Stage>('search');
  const [url, setUrl] = useState('');
  const [domains, setDomains] = useState<string[]>([]);
  const [ipRanges, setIpRanges] = useState<string[]>([]);
  const [cloudAccounts, setCloudAccounts] = useState<string[]>([]);
  const [forbiddenHosts, setForbiddenHosts] = useState<string[]>([]);
  const [forbiddenActions, setForbiddenActions] = useState<string[]>([]);
  const [loadingPhase, setLoadingPhase] = useState(0);
  const [vulnerabilities, setVulnerabilities] = useState<Finding[]>([]);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [activeTab, setActiveTab] = useState<ResultTab>('recon');
  const [showSwarm, setShowSwarm] = useState(false);
  const [logEntries, setLogEntries] = useState<string[]>([]);
  const [scanError, setScanError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const hasTransitioned = useRef(false);
  const logEndRef = useRef<HTMLDivElement | null>(null);

  const [twText, setTwText] = useState('');
  const [twPhrase, setTwPhrase] = useState(0);
  const [twPhase, setTwPhase] = useState<'typing' | 'pausing' | 'deleting'>('typing');

  useEffect(() => {
    const current = TYPEWRITER_PHRASES[twPhrase];
    if (twPhase === 'typing') {
      if (twText.length < current.length) {
        const t = setTimeout(() => setTwText(current.slice(0, twText.length + 1)), 75);
        return () => clearTimeout(t);
      } else {
        const t = setTimeout(() => setTwPhase('deleting'), 2000);
        return () => clearTimeout(t);
      }
    } else {
      if (twText.length > 0) {
        const t = setTimeout(() => setTwText(twText.slice(0, -1)), 40);
        return () => clearTimeout(t);
      } else {
        setTwPhrase((p) => (p + 1) % TYPEWRITER_PHRASES.length);
        setTwPhase('typing');
      }
    }
  }, [twText, twPhrase, twPhase]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logEntries]);

  const fetchResults = useCallback(async (eid: string) => {
    if (hasTransitioned.current) return;
    hasTransitioned.current = true;
    wsRef.current?.close();
    wsRef.current = null;
    try {
      await new Promise((r) => setTimeout(r, 600));
      const [fRes, cRes, aRes] = await Promise.all([
        fetch(`${API_BASE}/api/findings/${eid}`),
        fetch(`${API_BASE}/api/chains/${eid}`),
        fetch(`${API_BASE}/api/assets/${eid}`),
      ]);
      const [fData, cData, aData] = await Promise.all([fRes.json(), cRes.json(), aRes.json()]);
      setVulnerabilities(fData.findings ?? []);
      setChains(cData.chains ?? []);
      setAssets(aData.assets ?? []);
      setStage('results');
    } catch (err) {
      setScanError(`Failed to retrieve results: ${err}`);
      setStage('form');
    }
  }, []);

  const handleUrlSubmit = () => { if (url.trim()) setStage('form'); };

  const handleRun = async () => {
    if (!url.trim()) return;
    setScanError(null);
    hasTransitioned.current = false;

    const eid = crypto.randomUUID();

    let hostname = url;
    try { hostname = new URL(url.startsWith('http') ? url : `https://${url}`).hostname; } catch { hostname = url; }

    const scope = {
      engagement_id: eid,
      customer: hostname,
      targets: {
        domains: Array.from(new Set([hostname, ...domains])),
        ip_ranges: ipRanges,
        cloud_accounts: cloudAccounts.map(parseCloudAccount).filter(Boolean),
      },
      forbidden_spec: { forbidden_hosts: forbiddenHosts, forbidden_actions: forbiddenActions, tier_limit: 2 },
      constraints: {
        active_hours: { timezone: 'UTC', windows: [{ days: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], start: '00:00', end: '23:59' }] },
        cycle_interval_hours: 24,
        expires_at: new Date(Date.now() + 86400000).toISOString(),
        monthly_fee_usdc: 0.0,
      },
      github_repo_url: null,
    };

    setShowSwarm(true);
    setTimeout(() => setShowSwarm(false), 8000);
    setStage('loading');
    setLoadingPhase(0);
    setLogEntries([]);

    const ws = new WebSocket(`${WS_BASE}/ws/live`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      let msg: Record<string, unknown>;
      try { msg = JSON.parse(event.data); } catch { return; }
      if ('ping' in msg) return;

      const phase = EVENT_PHASE_MAP[msg.event as string];
      if (phase !== undefined) setLoadingPhase((prev) => Math.max(prev, phase));

      const entry = formatLogEntry(msg);
      if (entry) setLogEntries((prev) => [...prev, entry]);

      if (msg.event === 'cycle_complete') fetchResults(eid);
    };

    ws.onerror = () => { /* non-fatal, POST response is fallback */ };

    try {
      const res = await fetch(`${API_BASE}/api/orchestrator/run-once`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scope),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({})) as Record<string, string>;
        throw new Error(err.detail || `Server error ${res.status}`);
      }
      const data = await res.json() as { engagement_id: string };
      fetchResults(data.engagement_id);
    } catch (err) {
      if (!hasTransitioned.current) { setScanError(String(err)); setStage('form'); }
      wsRef.current?.close();
      wsRef.current = null;
    }
  };

  const handleReset = () => {
    wsRef.current?.close();
    wsRef.current = null;
    hasTransitioned.current = false;
    setStage('search');
    setUrl('');
    setDomains([]); setIpRanges([]); setCloudAccounts([]);
    setForbiddenHosts([]); setForbiddenActions([]);
    setVulnerabilities([]); setChains([]); setAssets([]);
    setLogEntries([]); setScanError(null);
  };

  const toggleForbiddenAction = (action: string) => {
    setForbiddenActions((prev) => prev.includes(action) ? prev.filter((a) => a !== action) : [...prev, action]);
  };

  return (
    <div className="min-h-screen bg-transparent flex flex-col">
      {/* Header */}
      <header className="p-6 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Image src="/locust.png" alt="Locust" width={48} height={48} className="w-12 h-12" />
          <span className="font-display font-semibold text-2xl tracking-[0.35em] text-foreground uppercase">LOCUST</span>
        </div>
        {stage !== 'search' && (
          <Button variant="ghost" size="sm" onClick={handleReset}
            className="font-mono text-xs text-muted-foreground hover:text-foreground">
            New Scan
          </Button>
        )}
      </header>

      {/* Main */}
      <main className="flex-1 flex flex-col items-center justify-center px-4">
        <AnimatePresence mode="wait">

          {/* ── Search ── */}
          {stage === 'search' && (
            <motion.div key="search" className="flex flex-col items-center justify-center w-full max-w-2xl"
              initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -60 }} transition={{ duration: 0.4, ease: 'easeOut' }}>
              <motion.div className="mb-6 text-center">
                <div className="inline-block text-left">
                  <h1 className="font-display font-semibold text-6xl text-foreground tracking-wide whitespace-nowrap">
                    {twText}<span className="cursor-blink text-primary ml-0.5">|</span>
                  </h1>
                  <div className="w-64" />
                </div>
              </motion.div>
              <p className="font-sans text-muted-foreground text-base font-normal mb-12">Enter the primary target URL to begin</p>
              <div className="w-full relative group">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input value={url} onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleUrlSubmit()}
                  placeholder="Insert URL..."
                  className="w-full h-14 pl-12 pr-4 bg-card/50 border-border text-foreground text-lg font-mono placeholder:text-muted-foreground focus:placeholder:opacity-0 rounded-full focus-visible:ring-0 focus-visible:ring-offset-0" />
              </div>
            </motion.div>
          )}

          {/* ── Form ── */}
          {stage === 'form' && (
            <motion.div key="form" className="w-full max-w-2xl mt-4"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              exit={{ opacity: 0, scale: 0.98 }} transition={{ duration: 0.3 }}>
              <motion.div className="relative group mb-8 rounded-full"
                initial={{ y: 200 }} animate={{ y: 0 }} transition={{ duration: 0.5, ease: 'easeOut' }}>
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-primary" />
                <Input value={url} onChange={(e) => setUrl(e.target.value)}
                  className="w-full h-12 pl-12 pr-4 bg-card/50 border-primary/30 text-foreground font-mono rounded-full focus-visible:ring-0 focus-visible:ring-offset-0" />
              </motion.div>

              {scanError && (
                <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
                  className="mb-4 px-4 py-3 rounded-lg bg-destructive/10 border border-destructive/30 font-mono text-xs text-destructive">
                  <span className="opacity-60">ERROR ── </span>{scanError}
                </motion.div>
              )}

              <motion.div className="bg-card/50 border border-border rounded-xl p-8 space-y-8"
                initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2, duration: 0.4 }}>
                <h2 className="font-display font-medium text-xs uppercase tracking-[0.2em] text-muted-foreground border-b border-border pb-3">
                  Scope Configuration
                </h2>
                <TagInput label="Additional Target Domains" icon={Globe} items={domains}
                  onAdd={(v) => setDomains((p) => [...p, v])} onRemove={(v) => setDomains((p) => p.filter((x) => x !== v))}
                  placeholder="e.g. sub.target.com" />
                <TagInput label="Target IP Ranges" icon={Server} items={ipRanges}
                  onAdd={(v) => setIpRanges((p) => [...p, v])} onRemove={(v) => setIpRanges((p) => p.filter((x) => x !== v))}
                  placeholder="e.g. 10.0.0.0/24" />
                <TagInput label="Target Cloud Accounts" icon={Cloud} items={cloudAccounts}
                  onAdd={(v) => setCloudAccounts((p) => [...p, v])} onRemove={(v) => setCloudAccounts((p) => p.filter((x) => x !== v))}
                  placeholder="e.g. aws:123456789 or gcp:my-project" />

                <div className="border-t border-border pt-8 space-y-8">
                  <h2 className="font-display font-medium text-xs uppercase tracking-[0.2em] text-destructive/80">Exclusions</h2>
                  <TagInput label="Forbidden Hosts" icon={Shield} items={forbiddenHosts}
                    onAdd={(v) => setForbiddenHosts((p) => [...p, v])} onRemove={(v) => setForbiddenHosts((p) => p.filter((x) => x !== v))}
                    placeholder="e.g. payments.acmecorp.com" />
                  <div className="space-y-2">
                    <label className="text-xs font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                      <Shield className="w-3.5 h-3.5" /> Forbidden Actions
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {FORBIDDEN_ACTION_OPTIONS.map((action) => (
                        <button key={action} onClick={() => toggleForbiddenAction(action)}
                          className={`px-3 py-1.5 rounded-lg font-mono text-xs border transition-all ${forbiddenActions.includes(action)
                            ? 'bg-destructive/20 text-destructive border-destructive/30'
                            : 'bg-secondary text-secondary-foreground border-border hover:border-muted-foreground'}`}>
                          {action}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <Button onClick={handleRun}
                  className="w-full h-12 font-mono text-sm tracking-wider uppercase bg-primary text-primary-foreground hover:bg-primary/90 rounded-xl">
                  Execute Scan
                </Button>
              </motion.div>
            </motion.div>
          )}

          {/* ── Loading ── */}
          {stage === 'loading' && (
            <motion.div key="loading" className="flex-1 flex flex-col items-center justify-center w-full max-w-lg"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <div className="w-full max-w-2xl absolute top-20 left-1/2 -translate-x-1/2 px-4">
                <div className="relative">
                  <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-primary" />
                  <Input value={url} readOnly
                    className="w-full h-12 pl-12 pr-4 bg-card border-primary/30 text-foreground font-mono rounded-xl opacity-50" />
                </div>
              </div>

              <div className="text-center space-y-8 w-full">
                <motion.div animate={{ rotate: 360 }} transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}>
                  <Loader2 className="w-12 h-12 text-primary mx-auto" />
                </motion.div>

                {/* Phase tracker */}
                <div className="space-y-4">
                  {LOADING_PHASES.map((phase, i) => {
                    const Icon = phase.icon;
                    return (
                      <motion.div key={phase.label}
                        className={`flex items-center gap-3 font-mono text-sm transition-all duration-300 ${i < loadingPhase ? 'text-primary' : i === loadingPhase ? 'text-foreground' : 'text-muted-foreground/40'}`}
                        initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.1 }}>
                        <Icon className="w-4 h-4" />
                        <span>{phase.label}</span>
                        {i < loadingPhase && <span className="text-primary ml-auto">✓</span>}
                        {i === loadingPhase && (
                          <motion.span className="ml-auto text-primary"
                            animate={{ opacity: [1, 0.3] }} transition={{ duration: 0.8, repeat: Infinity }}>●</motion.span>
                        )}
                      </motion.div>
                    );
                  })}
                </div>

                {/* Live activity log — shows every WS event */}
                <AnimatePresence>
                  {logEntries.length > 0 && (
                    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      className="w-full bg-black/50 border border-primary/15 rounded-lg p-4 text-left">
                      <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-primary/40 mb-2">
                        ── live output ──────────────────────────────
                      </div>
                      <div className="space-y-1.5 max-h-40 overflow-y-auto scrollbar-none">
                        {logEntries.map((entry, i) => (
                          <motion.div key={i} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }}
                            className="font-mono text-[11px] text-foreground/55 flex gap-2">
                            <span className="text-primary/30 shrink-0">›</span>
                            <span>{entry}</span>
                          </motion.div>
                        ))}
                        <div ref={logEndRef} />
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>
          )}

          {/* ── Results ── */}
          {stage === 'results' && (
            <motion.div key="results" className="w-full max-w-5xl mt-4 pb-16"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }}>

              {/* URL bar */}
              <motion.div className="relative mb-8" initial={{ y: 200 }} animate={{ y: 0 }}
                transition={{ duration: 0.5, ease: 'easeOut' }}>
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-primary" />
                <Input value={url} readOnly
                  className="w-full h-12 pl-12 pr-4 bg-card border-primary/30 text-foreground font-mono rounded-xl opacity-50" />
              </motion.div>

              {/* ── Attack Chains ── */}
              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
                <div className="flex items-center gap-3 mb-4">
                  <h2 className="font-display font-semibold text-lg text-foreground uppercase tracking-wide">
                    Attack Chains
                  </h2>
                  <Badge variant="outline" className="font-mono text-xs">{chains.length}</Badge>
                </div>

                {chains.length === 0 ? (
                  <div className="bg-card/50 border border-border rounded-xl px-6 py-10 text-center font-mono text-sm text-muted-foreground mb-8">
                    No attack chains mapped.
                  </div>
                ) : (
                  <div className="space-y-3 mb-8">
                    {chains.map((chain, i) => (
                      <AttackChainCard key={chain.chain_id} chain={chain} index={i} />
                    ))}
                  </div>
                )}
              </motion.div>

              {/* ── Intelligence Breakdown (tabbed) ── */}
              <motion.div className="bg-card border border-border rounded-xl overflow-hidden"
                initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>

                {/* Tab header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-border">
                  <h2 className="font-display font-semibold text-lg text-foreground uppercase tracking-wide">
                    Intelligence Breakdown
                  </h2>
                  <div className="flex gap-1 bg-muted/50 rounded-lg p-1">
                    {(['recon', 'exploit'] as const).map((tab) => (
                      <button key={tab} onClick={() => setActiveTab(tab)}
                        className={`px-3 py-1 rounded-md font-mono text-xs uppercase tracking-wider transition-all ${activeTab === tab
                          ? 'bg-background text-foreground shadow-sm'
                          : 'text-muted-foreground hover:text-foreground'}`}>
                        {tab}
                        <span className="ml-1.5 opacity-50">
                          {tab === 'recon' ? assets.length : vulnerabilities.length}
                        </span>
                      </button>
                    ))}
                  </div>
                </div>

                {/* RECON tab — assets */}
                {activeTab === 'recon' && (
                  assets.length === 0 ? (
                    <div className="px-6 py-10 text-center font-mono text-sm text-muted-foreground">No assets discovered.</div>
                  ) : (
                    <div className="overflow-auto max-h-125">
                      <table className="w-full">
                        <thead className="bg-muted sticky top-0">
                          <tr>
                            {['Type', 'Target', 'Open Ports', 'Surface Score', 'Tech Stack'].map((h) => (
                              <th key={h} className="px-4 py-3 text-left text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {assets.map((asset) => (
                            <tr key={asset.asset_id} className="border-t border-border hover:bg-muted/20 transition-colors">
                              <td className="px-4 py-3">
                                <Badge variant="outline" className="font-mono text-[10px] uppercase">
                                  {asset.asset_type.replace('_', ' ')}
                                </Badge>
                              </td>
                              <td className="px-4 py-3 font-mono text-xs text-primary max-w-50 truncate">
                                {asset.url ?? asset.ip ?? '—'}
                              </td>
                              <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                                {asset.open_ports?.length > 0 ? asset.open_ports.join(', ') : '—'}
                              </td>
                              <td className="px-4 py-3">
                                <span className={`font-mono text-sm font-bold tabular-nums ${surfaceScoreStyle(asset.attack_surface_score)}`}>
                                  {Math.round(asset.attack_surface_score * 100)}%
                                </span>
                              </td>
                              <td className="px-4 py-3">
                                <div className="flex flex-wrap gap-1">
                                  {(asset.tech_stack ?? []).slice(0, 4).map((t) => (
                                    <Badge key={t} variant="secondary" className="font-mono text-[10px]">{t}</Badge>
                                  ))}
                                  {(asset.tech_stack ?? []).length > 4 && (
                                    <span className="font-mono text-[10px] text-muted-foreground">
                                      +{asset.tech_stack.length - 4}
                                    </span>
                                  )}
                                  {(asset.tech_stack ?? []).length === 0 && (
                                    <span className="font-mono text-xs text-muted-foreground">—</span>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )
                )}

                {/* EXPLOIT tab — findings */}
                {activeTab === 'exploit' && (
                  vulnerabilities.length === 0 ? (
                    <div className="px-6 py-10 text-center font-mono text-sm text-muted-foreground">No vulnerabilities found.</div>
                  ) : (
                    <div className="overflow-auto max-h-125">
                      <table className="w-full">
                        <thead className="bg-muted sticky top-0">
                          <tr>
                            {['Severity', 'Title', 'Class', 'Host', 'Exploitable'].map((h) => (
                              <th key={h} className="px-4 py-3 text-left text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                                {h}
                              </th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {vulnerabilities.map((vuln) => (
                            <tr key={vuln.finding_id} className={`border-t border-border transition-all ${severityColor[vuln.severity]?.row ?? ''}`}>
                              <td className="px-4 py-3">
                                <Badge variant="outline" className={`font-mono text-xs uppercase ${severityColor[vuln.severity]?.badge ?? ''}`}>
                                  {vuln.severity}
                                </Badge>
                              </td>
                              <td className="px-4 py-3">
                                <div className="font-mono text-sm text-foreground font-medium">{vuln.title}</div>
                                {vuln.gemini_reasoning && (
                                  <div className="text-xs text-muted-foreground mt-1 font-mono">{vuln.gemini_reasoning}</div>
                                )}
                              </td>
                              <td className="px-4 py-3 font-mono text-sm text-foreground">{vuln.vulnerability_class}</td>
                              <td className="px-4 py-3 font-mono text-xs text-primary max-w-45 truncate">{vuln.affected_url}</td>
                              <td className="px-4 py-3">
                                {vuln.exploitable ? (
                                  <Badge className="bg-red-500/20 text-red-400 border-red-500/30 font-mono text-xs">YES</Badge>
                                ) : (
                                  <Badge className="bg-green-500/20 text-green-400 border-green-500/30 font-mono text-xs">NO</Badge>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )
                )}
              </motion.div>
            </motion.div>
          )}

        </AnimatePresence>
      </main>

      {/* Locust swarm */}
      <AnimatePresence>
        {showSwarm && (
          <div className="fixed inset-0 pointer-events-none z-50 overflow-hidden">
            {SWARM.map((locust) => (
              <motion.div key={locust.id} className="absolute" style={{ top: `${locust.yPct}%` }}
                initial={{ x: '-80px' }}
                animate={{ x: 'calc(100vw + 80px)', y: [0, -8, 0, 8, 0] }}
                transition={{
                  x: { duration: locust.duration, delay: locust.delay, ease: 'linear' },
                  y: { duration: 1.2, repeat: Infinity, ease: 'easeInOut', repeatType: 'mirror' },
                }}>
                <Image src="/locust_right.png" alt="" width={80} height={80}
                  style={{ transform: `scale(${locust.scale})`, imageRendering: 'pixelated' }} />
              </motion.div>
            ))}
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
