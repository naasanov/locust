export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type BlastRadius = 'single_asset' | 'multi_asset';
export type AgentPhase = 'RECON' | 'EXPLOIT' | 'LATERAL' | 'IDLE';

export interface Evidence {
  request: string;
  response_snippet: string;
  status_code: number;
}

export interface CredentialFound {
  type: string;
  value: string;
}

export interface Finding {
  finding_id: string;
  engagement_id: string;
  asset_id: string;
  vulnerability_class: string;
  title: string;
  severity: Severity;
  exploitable: boolean;
  affected_url: string;
  evidence: Evidence;
  credentials_found: CredentialFound[];
  gemini_reasoning: string | null;
  blast_radius: BlastRadius;
  on_chain_tx: string | null;
  remediation: string | null;
  mitre_technique: string | null;
  discovered_at: string;
}

export interface PivotStep {
  step: number;
  asset: string;
  action: string;
  detail: string;
  mitre: string | null;
}

export interface SensitiveStore {
  type: string;
  asset: string;
  contents: string;
  credentials_used: string;
}

export interface AttackChain {
  chain_id: string;
  engagement_id: string;
  entry_point_finding_id: string;
  entry_point: string;
  pivot_path: PivotStep[];
  reachable_sensitive_stores: SensitiveStore[];
  blast_radius_score: number;
  blast_radius_summary: string;
  /** Full attacker narrative written by the lateral agent */
  gemini_reasoning: string;
  on_chain_tx: string | null;
  mitre_techniques: string[];
  discovered_at: string;
}

export interface ServiceInfo {
  port: number;
  service: string;
  version: string | null;
}

export interface Asset {
  asset_id: string;
  engagement_id: string;
  asset_type: 'host' | 'web_app' | 'subdomain';
  ip: string | null;
  url: string | null;
  open_ports: number[];
  services: ServiceInfo[];
  tech_stack: string[];
  endpoints: string[];
  attack_surface_score: number;
  score_reasoning: string | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
