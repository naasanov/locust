import { Finding } from '@/types';

const SEVERITY_STYLES: Record<
  Finding['severity'],
  { border: string; bg: string; badge: string; text: string }
> = {
  critical: {
    border: 'border-l-red-600',
    bg: 'bg-white',
    badge: 'bg-red-100 text-red-700 border-red-200',
    text: 'text-red-900',
  },
  high: {
    border: 'border-l-orange-500',
    bg: 'bg-white',
    badge: 'bg-orange-100 text-orange-700 border-orange-200',
    text: 'text-orange-900',
  },
  medium: {
    border: 'border-l-amber-500',
    bg: 'bg-white',
    badge: 'bg-amber-100 text-amber-700 border-amber-200',
    text: 'text-amber-900',
  },
  low: {
    border: 'border-l-blue-600',
    bg: 'bg-white',
    badge: 'bg-blue-100 text-blue-700 border-blue-200',
    text: 'text-blue-900',
  },
  info: {
    border: 'border-l-slate-400',
    bg: 'bg-white',
    badge: 'bg-slate-100 text-slate-700 border-slate-200',
    text: 'text-slate-900',
  },
};

interface FindingCardProps {
  finding: Finding;
  isNew: boolean;
}

export default function FindingCard({ finding, isNew }: FindingCardProps) {
  const styles = SEVERITY_STYLES[finding.severity];
  const confirmedByGemini = finding.gemini_reasoning !== null;
  const time = new Date(finding.discovered_at).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });

  return (
    <article
      className={[
        'bg-white/90 border border-slate-200 p-5 relative',
        'border-l-4 transition-all duration-200',
        styles.border,
        'shadow-sm hover:shadow-md hover:border-slate-300',
      ].join(' ')}
      style={isNew ? { animation: 'fadeSlideIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards' } : {}}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <span className={`text-[9px] font-bold uppercase px-2.5 py-1 border tracking-wider ${styles.badge}`}>
              {finding.severity}
            </span>

            <span className={`text-[9px] font-semibold px-2.5 py-1 border uppercase tracking-wider ${confirmedByGemini ? 'bg-[#41accc]/10 border-[#41accc]/30 text-[#41accc]' : 'bg-slate-50 border-slate-200 text-slate-600'}`}>
              {confirmedByGemini ? 'AI Verified' : 'System'}
            </span>

            {finding.mitre_technique && (
              <span className="text-[9px] font-mono font-semibold text-slate-600 bg-slate-50 px-2 py-1 border border-slate-200">
                {finding.mitre_technique}
              </span>
            )}
          </div>

          <h3 className="text-sm font-bold text-slate-900 leading-snug">
            {finding.title}
          </h3>
          <p className="mt-1.5 text-[11px] font-mono text-slate-500 truncate">
            {finding.affected_url}
          </p>
        </div>

        <span className="shrink-0 text-[10px] font-mono text-slate-400 font-medium">
          {time}
        </span>
      </div>

      {finding.gemini_reasoning && (
        <div className="mt-4 pt-4 border-t border-slate-200 bg-slate-50/40 -mx-5 px-5 pb-2">
          <p className="text-[10px] font-bold text-slate-600 mb-2 uppercase tracking-widest">
            Intelligence Analysis
          </p>
          <p className="text-xs text-slate-700 leading-relaxed font-medium">
            {finding.gemini_reasoning}
          </p>
        </div>
      )}
    </article>
  );
}