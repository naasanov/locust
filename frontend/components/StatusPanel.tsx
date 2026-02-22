import { AgentPhase, SeverityCounts } from '@/types';

const PHASE_CONFIG: Record<
  AgentPhase,
  { label: string; color: string; code: string }
> = {
  RECON: { label: 'RECONNAISSANCE', color: 'bg-[#41accc]', code: 'OP-PH-01' },
  EXPLOIT: { label: 'EXPLOITATION', color: 'bg-amber-500', code: 'OP-PH-02' },
  LATERAL: { label: 'LATERAL MOVEMENT', color: 'bg-purple-600', code: 'OP-PH-03' },
  IDLE: { label: 'STANDBY / READY', color: 'bg-slate-400', code: 'OP-PH-00' },
};

const SEVERITY_CONFIG = [
  { key: 'critical' as const, label: 'CRIT', color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-200' },
  { key: 'high' as const, label: 'HIGH', color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200' },
  { key: 'medium' as const, label: 'MED', color: 'text-amber-700', bg: 'bg-amber-50', border: 'border-amber-200' },
  { key: 'low' as const, label: 'LOW', color: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-200' },
  { key: 'info' as const, label: 'INFO', color: 'text-slate-600', bg: 'bg-slate-50', border: 'border-slate-200' },
];

interface StatusPanelProps {
  phase: AgentPhase;
  counts: SeverityCounts;
  assetCount: number;
  latestNarrative: string | null;
  isMock: boolean;
}

export default function StatusPanel({
  phase,
  counts,
  assetCount,
  latestNarrative,
  isMock,
}: StatusPanelProps) {
  const phaseConfig = PHASE_CONFIG[phase];
  const totalFindings = Object.values(counts).reduce((a, b) => a + b, 0);

  return (
    <div className="flex flex-col gap-5">
      <div className="panel-card p-5">
        <div className="flex items-center justify-between mb-4">
          <p className="text-[11px] font-bold text-slate-700 uppercase tracking-widest">
            System Status
          </p>
          <span className={`text-[9px] font-bold px-2 py-1 border uppercase tracking-wider ${isMock ? 'bg-amber-50 border-amber-400 text-amber-800' : 'bg-[#41accc]/10 border-[#41accc]/40 text-[#41accc]'}`}>
            {isMock ? 'Simulation' : 'Live'}
          </span>
        </div>

        <div className="flex items-center gap-3 bg-gradient-to-br from-slate-50 to-slate-100/50 border border-slate-200 p-4 shadow-sm">
          <div className={`w-3 h-3 ${phaseConfig.color} shadow-sm`} />
          <div className="flex-1">
            <p className="text-xs font-bold text-slate-900 tracking-wide">{phaseConfig.label}</p>
            <p className="text-[9px] font-mono text-slate-500 mt-0.5 font-semibold">{phaseConfig.code}</p>
          </div>
        </div>
      </div>

      <div className="panel-card p-5">
        <p className="text-[11px] font-bold text-slate-700 uppercase tracking-widest mb-4">
          Threat Inventory
        </p>
        <div className="grid grid-cols-5 gap-1.5">
          {SEVERITY_CONFIG.map(({ key, label, color, bg, border }) => (
            <div key={key} className={`text-center border ${border} ${bg} py-3 shadow-sm transition-all hover:shadow`}>
              <p className={`text-xl font-black tabular-nums ${color}`}>
                {counts[key]}
              </p>
              <p className="text-[8px] font-bold text-slate-500 uppercase mt-1 tracking-wider">{label}</p>
            </div>
          ))}
        </div>

        <div className="mt-5 pt-4 border-t border-slate-200 grid grid-cols-2 gap-5">
          <div className="text-center">
            <p className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-1.5">Total Findings</p>
            <p className="text-3xl font-black text-slate-900 tabular-nums">{totalFindings}</p>
          </div>
          <div className="text-center">
            <p className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-1.5">Target Assets</p>
            <p className="text-3xl font-black text-slate-900 tabular-nums">{assetCount}</p>
          </div>
        </div>
      </div>

      <div className="panel-card p-5 bg-gradient-to-br from-white to-slate-50/50">
        <p className="text-[11px] font-bold text-slate-700 uppercase tracking-widest mb-4">
          Attack Analysis
        </p>
        {latestNarrative ? (
          <p className="text-xs text-slate-700 leading-relaxed font-medium">
            {latestNarrative}
          </p>
        ) : (
          <p className="text-xs text-slate-400 italic">No active attack chains detected.</p>
        )}
      </div>
    </div>
  );
}