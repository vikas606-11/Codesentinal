import { useMemo, useState } from "react";
import { CATEGORIES, SEVERITIES } from "../lib/lib.js";
import { CategoryBadge, SeverityBadge } from "./Badges.jsx";

const PAGE = 50;
const selectClass = "rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700";

export default function FindingsTable({ findings, onSelect, selectedId }) {
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [tool, setTool] = useState("");
  const [query, setQuery] = useState("");
  const [visible, setVisible] = useState(PAGE);

  const tools = useMemo(() => [...new Set(findings.map((f) => f.tool))], [findings]);
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return findings.filter(
      (f) =>
        (!severity || f.severity === severity) &&
        (!category || f.category === category) &&
        (!tool || f.tool === tool) &&
        (!q || `${f.title} ${f.file} ${f.rule_id}`.toLowerCase().includes(q))
    );
  }, [findings, severity, category, tool, query]);

  const change = (setter) => (e) => {
    setter(e.target.value);
    setVisible(PAGE);
  };
  const shown = filtered.slice(0, visible);

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <input
          type="search" value={query} onChange={change(setQuery)} placeholder="Search title, file or rule"
          aria-label="Search findings" className={`${selectClass} min-w-[14rem] flex-1`}
        />
        <select value={severity} onChange={change(setSeverity)} aria-label="Filter by severity" className={selectClass}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={category} onChange={change(setCategory)} aria-label="Filter by category" className={selectClass}>
          <option value="">All categories</option>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={tool} onChange={change(setTool)} aria-label="Filter by tool" className={selectClass}>
          <option value="">All tools</option>
          {tools.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      <p className="mb-2 text-sm text-slate-500" data-testid="findings-count">
        Showing {shown.length} of {filtered.length} findings
        {filtered.length !== findings.length ? ` (${findings.length} total)` : ""}
      </p>

      {filtered.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-300 p-8 text-center text-sm text-slate-500">
          {findings.length === 0 ? "No findings. This code is clean." : "No findings match these filters."}
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Finding</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Tool</th>
                <th className="px-4 py-3">Location</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {shown.map((f) => (
                <tr
                  key={f.id} data-testid="finding-row" onClick={() => onSelect(f)}
                  className={`cursor-pointer hover:bg-slate-50 ${selectedId === f.id ? "bg-slate-50" : ""}`}
                >
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3">
                    <button
                      type="button" onClick={(e) => { e.stopPropagation(); onSelect(f); }}
                      className="text-left font-medium text-slate-900 hover:underline"
                    >
                      {f.title}
                    </button>
                    <div className="text-xs text-slate-500">{f.rule_id}</div>
                  </td>
                  <td className="px-4 py-3"><CategoryBadge category={f.category} /></td>
                  <td className="px-4 py-3 text-slate-600">{f.tool}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-600">{f.file}:{f.line}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {filtered.length > visible && (
        <button
          type="button" onClick={() => setVisible(visible + PAGE)}
          className="mt-4 rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          Show more ({filtered.length - visible} remaining)
        </button>
      )}
    </div>
  );
}
