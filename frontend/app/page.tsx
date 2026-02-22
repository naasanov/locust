'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Plus, X, Shield, Loader2, AlertTriangle, Bug, Server, Globe, Cloud } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Finding } from '@/types';
import Image from 'next/image';

type Stage = 'search' | 'form' | 'loading' | 'results';

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

// Map backend WebSocket events to loading phase indices
const EVENT_PHASE_MAP: Record<string, number> = {
  cycle_started: 1,
  recon_complete: 2,
  exploit_complete: 3,
  lateral_complete: 4,
  cycle_complete: 4,
};

function formatLogEntry(msg: Record<string, unknown>): string | null {
  switch (msg.event) {
    case 'cycle_started':
      return `SWARM DEPLOYED ── engagement ${String(msg.engagement_id).slice(0, 8)}...`;
    case 'recon_complete':
      return `RECON COMPLETE ── ${msg.asset_count} target surfaces mapped`;
    case 'exploit_complete':
      return `EXPLOIT SCAN COMPLETE ── ${msg.finding_count} vulnerabilities confirmed`;
    case 'lateral_complete':
      return `LATERAL MOVEMENT COMPLETE ── ${msg.chain_count} attack chains forged`;
    case 'demo_seeded':
      return `SEED FINDING PLANTED ── ${msg.affected_url}`;
    case 'github_issues_created':
      return `GITHUB ISSUES FILED ── ${Array.isArray(msg.issue_urls) ? msg.issue_urls.length : 0} reports`;
    case 'cycle_complete':
      return `CYCLE COMPLETE ── retrieving intelligence...`;
    default:
      return null;
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

const severityColor: Record<string, { badge: string; row: string }> = {
  critical: { badge: 'bg-red-500/20 text-red-400 border-red-500/30', row: 'bg-red-500/[0.06]' },
  high: { badge: 'bg-orange-500/20 text-orange-400 border-orange-500/30', row: 'bg-orange-500/[0.06]' },
  medium: { badge: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', row: 'bg-yellow-500/[0.06]' },
  low: { badge: 'bg-blue-500/20 text-blue-400 border-blue-500/30', row: 'bg-blue-500/[0.06]' },
  info: { badge: 'bg-muted text-muted-foreground border-border', row: 'bg-muted/30' },
};

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
    if (val.trim()) {
      onAdd(val.trim());
      setVal('');
    }
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
        <Button
          type="button"
          size="icon"
          variant="outline"
          onClick={add}
          className="shrink-0 border-border hover:bg-primary hover:text-primary-foreground"
        >
          <Plus className="w-4 h-4" />
        </Button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {items.map((item) => (
            <Badge
              key={item}
              variant="secondary"
              className="font-mono text-xs bg-secondary text-secondary-foreground gap-1 pr-1"
            >
              {item}
              <button
                onClick={() => onRemove(item)}
                className="hover:text-destructive ml-1"
              >
                <X className="w-3 h-3" />
              </button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
};

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
      await new Promise((resolve) => setTimeout(resolve, 600));
      const res = await fetch(`${API_BASE}/api/findings/${eid}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setVulnerabilities(data.findings ?? []);
      setStage('results');
    } catch (err) {
      setScanError(`Failed to retrieve results: ${err}`);
      setStage('form');
    }
  }, []);

  const handleUrlSubmit = () => {
    if (!url.trim()) return;
    setStage('form');
  };

  const handleRun = async () => {
    if (!url.trim()) return;
    setScanError(null);
    hasTransitioned.current = false;

    const eid = crypto.randomUUID();

    // Extract hostname from URL for use as customer/domain
    let hostname = url;
    try {
      hostname = new URL(url.startsWith('http') ? url : `https://${url}`).hostname;
    } catch {
      hostname = url;
    }

    const scope = {
      engagement_id: eid,
      customer: hostname,
      targets: {
        domains: Array.from(new Set([hostname, ...domains])),
        ip_ranges: ipRanges,
        cloud_accounts: cloudAccounts.map(parseCloudAccount).filter(Boolean),
      },
      forbidden_spec: {
        forbidden_hosts: forbiddenHosts,
        forbidden_actions: forbiddenActions,
        tier_limit: 2,
      },
      constraints: {
        active_hours: {
          timezone: 'UTC',
          windows: [
            { days: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], start: '00:00', end: '23:59' },
          ],
        },
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

    // Open WebSocket for real-time progress events
    const ws = new WebSocket(`${WS_BASE}/ws/live`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(event.data);
      } catch {
        return;
      }
      if ('ping' in msg) return;

      const phase = EVENT_PHASE_MAP[msg.event as string];
      if (phase !== undefined) {
        setLoadingPhase((prev) => Math.max(prev, phase));
      }

      const entry = formatLogEntry(msg);
      if (entry) setLogEntries((prev) => [...prev, entry]);

      if (msg.event === 'cycle_complete') {
        fetchResults(eid);
      }
    };

    ws.onerror = () => {
      // Non-fatal — POST response will trigger fetchResults as fallback
    };

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
      // Fallback: WS cycle_complete may have already triggered this
      fetchResults(data.engagement_id);
    } catch (err) {
      if (!hasTransitioned.current) {
        setScanError(String(err));
        setStage('form');
      }
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
    setDomains([]);
    setIpRanges([]);
    setCloudAccounts([]);
    setForbiddenHosts([]);
    setForbiddenActions([]);
    setVulnerabilities([]);
    setLogEntries([]);
    setScanError(null);
  };

  const toggleForbiddenAction = (action: string) => {
    setForbiddenActions((prev) =>
      prev.includes(action) ? prev.filter((a) => a !== action) : [...prev, action]
    );
  };

  return (
    <div className="min-h-screen bg-transparent flex flex-col">
      {/* Header */}
      <header className="p-6 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Image
            src="/locust.png"
            alt="Locust"
            width={48}
            height={48}
            className="w-12 h-12"
          />
          <span className="font-display font-semibold text-2xl tracking-[0.35em] text-foreground uppercase">
            LOCUST
          </span>
        </div>
        {stage !== 'search' && (
          <Button
            variant="ghost"
            size="sm"
            onClick={handleReset}
            className="font-mono text-xs text-muted-foreground hover:text-foreground"
          >
            New Scan
          </Button>
        )}
      </header>

      {/* Main */}
      <main className="flex-1 flex flex-col items-center justify-center px-4">
        <AnimatePresence mode="wait">
          {stage === 'search' && (
            <motion.div
              key="search-center"
              className="flex flex-col items-center justify-center w-full max-w-2xl"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -60 }}
              transition={{ duration: 0.4, ease: 'easeOut' }}
            >
              <motion.div className="mb-6 text-center">
                <div className="inline-block text-left">
                  <h1 className="font-display font-semibold text-6xl text-foreground tracking-wide whitespace-nowrap">
                    {twText}
                    <span className="cursor-blink text-primary ml-0.5">|</span>
                  </h1>
                  <div className='w-64' />
                </div>
              </motion.div>
              <p className="font-sans text-muted-foreground text-base font-normal mb-12">Enter the primary target URL to begin</p>
              <div className="w-full relative group">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleUrlSubmit()}
                  placeholder="Insert URL..."
                  className="w-full h-14 pl-12 pr-4 bg-card/50 border-border text-foreground text-lg font-mono placeholder:text-muted-foreground focus:placeholder:opacity-0 rounded-full focus-visible:ring-0 focus-visible:ring-offset-0"
                />
              </div>
            </motion.div>
          )}

          {stage === 'form' && (
            <motion.div
              key="form"
              className="w-full max-w-2xl mt-4"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0, scale: 0.98 }}
              transition={{ duration: 0.3 }}
            >
              {/* URL bar at top */}
              <motion.div
                className="relative group mb-8 rounded-full"
                initial={{ y: 200 }}
                animate={{ y: 0 }}
                transition={{ duration: 0.5, ease: 'easeOut' }}
              >
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-primary" />
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full h-12 pl-12 pr-4 bg-card/50 border-primary/30 text-foreground font-mono rounded-full focus-visible:ring-0 focus-visible:ring-offset-0"
                />
              </motion.div>

              {/* Error banner */}
              {scanError && (
                <motion.div
                  initial={{ opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="mb-4 px-4 py-3 rounded-lg bg-destructive/10 border border-destructive/30 font-mono text-xs text-destructive"
                >
                  <span className="opacity-60">ERROR ── </span>{scanError}
                </motion.div>
              )}

              {/* Form fields */}
              <motion.div
                className="bg-card/50 border border-border rounded-xl p-8 space-y-8"
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2, duration: 0.4 }}
              >
                <h2 className="font-display font-medium text-xs uppercase tracking-[0.2em] text-muted-foreground border-b border-border pb-3">
                  Scope Configuration
                </h2>

                <TagInput
                  label="Additional Target Domains"
                  icon={Globe}
                  items={domains}
                  onAdd={(v) => setDomains((p) => [...p, v])}
                  onRemove={(v) => setDomains((p) => p.filter((x) => x !== v))}
                  placeholder="e.g. sub.target.com"
                />

                <TagInput
                  label="Target IP Ranges"
                  icon={Server}
                  items={ipRanges}
                  onAdd={(v) => setIpRanges((p) => [...p, v])}
                  onRemove={(v) => setIpRanges((p) => p.filter((x) => x !== v))}
                  placeholder="e.g. 10.0.0.0/24"
                />

                <TagInput
                  label="Target Cloud Accounts"
                  icon={Cloud}
                  items={cloudAccounts}
                  onAdd={(v) => setCloudAccounts((p) => [...p, v])}
                  onRemove={(v) => setCloudAccounts((p) => p.filter((x) => x !== v))}
                  placeholder="e.g. aws:123456789 or gcp:my-project"
                />

                <div className="border-t border-border pt-8 space-y-8">
                  <h2 className="font-display font-medium text-xs uppercase tracking-[0.2em] text-destructive/80">
                    Exclusions
                  </h2>

                  <TagInput
                    label="Forbidden Hosts"
                    icon={Shield}
                    items={forbiddenHosts}
                    onAdd={(v) => setForbiddenHosts((p) => [...p, v])}
                    onRemove={(v) => setForbiddenHosts((p) => p.filter((x) => x !== v))}
                    placeholder="e.g. payments.acmecorp.com"
                  />

                  <div className="space-y-2">
                    <label className="text-xs font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                      <Shield className="w-3.5 h-3.5" /> Forbidden Actions
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {FORBIDDEN_ACTION_OPTIONS.map((action) => (
                        <button
                          key={action}
                          onClick={() => toggleForbiddenAction(action)}
                          className={`px-3 py-1.5 rounded-lg font-mono text-xs border transition-all ${forbiddenActions.includes(action)
                            ? 'bg-destructive/20 text-destructive border-destructive/30'
                            : 'bg-secondary text-secondary-foreground border-border hover:border-muted-foreground'
                            }`}
                        >
                          {action}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <Button
                  onClick={handleRun}
                  className="w-full h-12 font-mono text-sm tracking-wider uppercase bg-primary text-primary-foreground hover:bg-primary/90 rounded-xl"
                >
                  Execute Scan
                </Button>
              </motion.div>
            </motion.div>
          )}

          {stage === 'loading' && (
            <motion.div
              key="loading"
              className="flex-1 flex flex-col items-center justify-center w-full max-w-lg"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              {/* URL bar at top */}
              <div className="w-full max-w-2xl absolute top-20 left-1/2 -translate-x-1/2 px-4">
                <div className="relative">
                  <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-primary" />
                  <Input
                    value={url}
                    readOnly
                    className="w-full h-12 pl-12 pr-4 bg-card border-primary/30 text-foreground font-mono rounded-xl opacity-50"
                  />
                </div>
              </div>

              <div className="text-center space-y-8 w-full">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
                >
                  <Loader2 className="w-12 h-12 text-primary mx-auto" />
                </motion.div>

                <div className="space-y-4">
                  {LOADING_PHASES.map((phase, i) => {
                    const Icon = phase.icon;
                    return (
                      <motion.div
                        key={phase.label}
                        className={`flex items-center gap-3 font-mono text-sm transition-all duration-300 ${i < loadingPhase
                          ? 'text-primary'
                          : i === loadingPhase
                            ? 'text-foreground'
                            : 'text-muted-foreground/40'
                          }`}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.1 }}
                      >
                        <Icon className="w-4 h-4" />
                        <span>{phase.label}</span>
                        {i < loadingPhase && <span className="text-primary ml-auto">✓</span>}
                        {i === loadingPhase && (
                          <motion.span
                            className="ml-auto text-primary"
                            animate={{ opacity: [1, 0.3] }}
                            transition={{ duration: 0.8, repeat: Infinity }}
                          >
                            ●
                          </motion.span>
                        )}
                      </motion.div>
                    );
                  })}
                </div>

                {/* Live activity log */}
                <AnimatePresence>
                  {logEntries.length > 0 && (
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="w-full bg-black/40 border border-primary/20 rounded-lg p-4 text-left"
                    >
                      <div className="font-mono text-xs text-primary/50 mb-2 uppercase tracking-widest">
                        ── activity log ──
                      </div>
                      <div className="space-y-1.5 max-h-36 overflow-y-auto">
                        {logEntries.map((entry, i) => (
                          <motion.div
                            key={i}
                            initial={{ opacity: 0, x: -6 }}
                            animate={{ opacity: 1, x: 0 }}
                            className="font-mono text-xs text-foreground/60 flex gap-2"
                          >
                            <span className="text-primary/40 shrink-0">→</span>
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

          {stage === 'results' && (
            <motion.div
              key="results"
              className="w-full max-w-6xl mt-4"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              {/* URL bar at top */}
              <motion.div
                className="relative group mb-8"
                initial={{ y: 200 }}
                animate={{ y: 0 }}
                transition={{ duration: 0.5, ease: 'easeOut' }}
              >
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-primary" />
                <Input
                  value={url}
                  readOnly
                  className="w-full h-12 pl-12 pr-4 bg-card border-primary/30 text-foreground font-mono rounded-xl opacity-50"
                />
              </motion.div>

              {/* Results table */}
              <motion.div
                className="bg-card border border-border rounded-xl overflow-hidden"
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2, duration: 0.4 }}
              >
                <div className="px-6 py-4 border-b border-border">
                  <h2 className="font-display font-semibold text-xl text-foreground uppercase tracking-wide">
                    Vulnerability Report
                  </h2>
                  <p className="font-sans text-muted-foreground text-sm font-normal mt-1">
                    {vulnerabilities.length} findings detected
                  </p>
                </div>

                {vulnerabilities.length === 0 ? (
                  <div className="px-6 py-12 text-center font-mono text-sm text-muted-foreground">
                    No vulnerabilities found.
                  </div>
                ) : (
                  <div className="overflow-auto max-h-150">
                    <table className="w-full">
                      <thead className="bg-muted sticky top-0">
                        <tr>
                          <th className="px-4 py-3 text-left text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                            Severity
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                            Title
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                            Class
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                            Host
                          </th>
                          <th className="px-4 py-3 text-left text-xs font-mono uppercase tracking-wider text-muted-foreground font-semibold">
                            Exploitable
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {vulnerabilities.map((vuln) => (
                          <tr
                            key={vuln.finding_id}
                            className={`border-t border-border transition-all ${severityColor[vuln.severity]?.row ?? ''}`}
                          >
                            <td className="px-4 py-3">
                              <Badge
                                variant="outline"
                                className={`font-mono text-xs uppercase ${severityColor[vuln.severity]?.badge ?? ''}`}
                              >
                                {vuln.severity}
                              </Badge>
                            </td>
                            <td className="px-4 py-3">
                              <div className="font-mono text-sm text-foreground font-medium">
                                {vuln.title}
                              </div>
                              {vuln.gemini_reasoning && (
                                <div className="text-xs text-muted-foreground mt-1 font-mono">
                                  {vuln.gemini_reasoning}
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-3 font-mono text-sm text-foreground">
                              {vuln.vulnerability_class}
                            </td>
                            <td className="px-4 py-3 font-mono text-xs text-primary">
                              {vuln.affected_url}
                            </td>
                            <td className="px-4 py-3">
                              {vuln.exploitable ? (
                                <Badge className="bg-red-500/20 text-red-400 border-red-500/30 font-mono text-xs">
                                  YES
                                </Badge>
                              ) : (
                                <Badge className="bg-green-500/20 text-green-400 border-green-500/30 font-mono text-xs">
                                  NO
                                </Badge>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Locust swarm overlay */}
      <AnimatePresence>
        {showSwarm && (
          <div className="fixed inset-0 pointer-events-none z-50 overflow-hidden">
            {SWARM.map((locust) => (
              <motion.div
                key={locust.id}
                className="absolute"
                style={{ top: `${locust.yPct}%` }}
                initial={{ x: '-80px' }}
                animate={{
                  x: 'calc(100vw + 80px)',
                  y: [0, -8, 0, 8, 0],
                }}
                transition={{
                  x: { duration: locust.duration, delay: locust.delay, ease: 'linear' },
                  y: { duration: 1.2, repeat: Infinity, ease: 'easeInOut', repeatType: 'mirror' },
                }}
              >
                <Image
                  src="/locust_right.png"
                  alt=""
                  width={80}
                  height={80}
                  style={{
                    transform: `scale(${locust.scale})`,
                    imageRendering: 'pixelated',
                  }}
                />
              </motion.div>
            ))}
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
