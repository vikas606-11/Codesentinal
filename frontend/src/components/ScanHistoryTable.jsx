import { formatDate, scoreColor } from "../lib/lib.js";
import { navigate } from "../lib/router.js";
import { GateBadge } from "./Badges.jsx";

export default function ScanHistoryTable({ scans }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
      <table className="w-full text-left text-sm">
        <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-3">File</th>
            <th className="px-4 py-3">Date</th>
            <th className="px-4 py-3">Score</th>
            <th className="px-4 py-3">Rating</th>
            <th className="px-4 py-3">Gate</th>
            <th className="px-4 py-3 text-right">Findings</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {scans.map((s) => (
            <tr key={s.scan_id} data-testid="scan-row" onClick={() => navigate(`/scans/${s.scan_id}`)} className="cursor-pointer hover:bg-slate-50">
              <td className="px-4 py-3 font-medium text-slate-900">
                <a href={`#/scans/${s.scan_id}`} onClick={(e) => e.stopPropagation()} className="hover:underline">{s.filename}</a>
              </td>
              <td className="px-4 py-3 text-slate-600">{formatDate(s.created_at)}</td>
              <td className="px-4 py-3 font-semibold" style={{ color: scoreColor(s.score) }}>{s.score}</td>
              <td className="px-4 py-3 text-slate-700">{s.rating}</td>
              <td className="px-4 py-3"><GateBadge gate={s.gate} /></td>
              <td className="px-4 py-3 text-right text-slate-700">{s.summary.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
