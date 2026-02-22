import { Finding } from '@/types';
import FindingCard from './FindingCard';

interface FindingsFeedProps {
  findings: Finding[];
  newFindingIds: Set<string>;
}

export default function FindingsFeed({
  findings,
  newFindingIds,
}: FindingsFeedProps) {
  if (findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-72 border-2 border-dashed border-slate-300 bg-white/60">
        <div className="w-8 h-8 border-3 border-slate-200 border-t-[#41accc] animate-spin mb-4" />
        <p className="text-[11px] font-bold text-slate-600 uppercase tracking-widest">
          Establishing Connection
        </p>
        <p className="text-[10px] text-slate-400 mt-2 tracking-wider">
          Awaiting operational data stream
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {findings.map((finding) => (
        <FindingCard
          key={finding.finding_id}
          finding={finding}
          isNew={newFindingIds.has(finding.finding_id)}
        />
      ))}
    </div>
  );
}