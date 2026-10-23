import { CATEGORIES, SEVERITIES, SEVERITY_BAR } from "../lib/lib.js";

export default function SeverityBreakdown({ summary }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => summary.by_severity[s] || 0));
  return (
    <div className="grid gap-6 sm:grid-cols-2">
      <div>
        <h3 className="mb-3 text-sm font-semibold text-slate-700">By severity</h3>
        <ul className="space-y-2">
          {SEVERITIES.map((s) => {
            const n = summary.by_severity[s] || 0;
            return (
              <li key={s} className="flex items-center gap-3 text-sm" data-testid={`sev-${s}`}>
                <span className="w-20 text-slate-600">{s}</span>
                <div className="h-2.5 flex-1 rounded-full bg-slate-100">
                  <div className={`h-2.5 rounded-full ${SEVERITY_BAR[s]}`} style={{ width: `${(n / max) * 100}%` }} />
                </div>
                <span className="w-8 text-right font-semibold text-slate-900">{n}</span>
              </li>
            );
          })}
        </ul>
      </div>
      <div>
        <h3 className="mb-3 text-sm font-semibold text-slate-700">By category</h3>
        <ul className="space-y-2">
          {CATEGORIES.map((c) => (
            <li key={c} className="flex justify-between rounded-md bg-slate-50 px-3 py-2 text-sm" data-testid={`cat-${c}`}>
              <span className="text-slate-600">{c}</span>
              <span className="font-semibold text-slate-900">{summary.by_category[c] || 0}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
