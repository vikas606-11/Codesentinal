import { useEffect } from "react";
import { cweNumber } from "../lib/lib.js";
import AiExplanation from "./AiExplanation.jsx";
import { CategoryBadge, SeverityBadge } from "./Badges.jsx";

function Field({ label, children }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm text-slate-800">{children}</dd>
    </div>
  );
}

export default function FindingDrawer({ finding, onClose }) {
  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!finding) return null;
  const isCve = /^CVE-/i.test(finding.rule_id);

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-slate-900/40" onClick={onClose} data-testid="drawer-overlay" />
      <aside role="dialog" aria-label="Finding details" className="relative z-10 h-full w-full max-w-xl overflow-y-auto bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between gap-4">
          <h2 className="text-lg font-semibold leading-snug text-slate-900">{finding.title}</h2>
          <button type="button" onClick={onClose} aria-label="Close details" className="rounded-md p-1 text-slate-500 hover:bg-slate-100">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 5l10 10M15 5L5 15" /></svg>
          </button>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <SeverityBadge severity={finding.severity} />
          <CategoryBadge category={finding.category} />
        </div>

        <dl className="mt-6 space-y-5">
          <Field label="What was found">{finding.message}</Field>
          <Field label="Location">
            <span className="font-mono text-xs">{finding.file}</span>, line {finding.line}
            {finding.end_line !== finding.line ? ` to ${finding.end_line}` : ""}
          </Field>
          <Field label="Detected by">{finding.tool} (rule {finding.rule_id})</Field>

          {finding.code_snippet && (
            <Field label="Code">
              <pre className="overflow-x-auto rounded-md bg-slate-900 p-4 text-xs leading-relaxed text-slate-100">
                <code>{finding.code_snippet}</code>
              </pre>
            </Field>
          )}

          {(finding.cwe.length > 0 || isCve) && (
            <Field label="References">
              <div className="flex flex-wrap gap-2">
                {finding.cwe.map((c) =>
                  cweNumber(c) ? (
                    <a key={c} href={`https://cwe.mitre.org/data/definitions/${cweNumber(c)}.html`} target="_blank" rel="noopener noreferrer"
                      className="rounded bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700 hover:bg-slate-200">{c}</a>
                  ) : null
                )}
                {isCve && (
                  <a href={`https://nvd.nist.gov/vuln/detail/${finding.rule_id}`} target="_blank" rel="noopener noreferrer"
                    className="rounded bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700 hover:bg-slate-200">{finding.rule_id} (NVD)</a>
                )}
              </div>
            </Field>
          )}
        </dl>

        <div className="mt-8 border-t border-slate-200 pt-6">
          <AiExplanation key={finding.id} findingId={finding.id} />
        </div>
      </aside>
    </div>
  );
}
