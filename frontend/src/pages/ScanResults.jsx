import { useCallback, useEffect, useState } from "react";
import { getScan } from "../api.js";
import { GateBadge } from "../components/Badges.jsx";
import FindingDrawer from "../components/FindingDrawer.jsx";
import FindingsTable from "../components/FindingsTable.jsx";
import ScoreGauge from "../components/ScoreGauge.jsx";
import SeverityBreakdown from "../components/SeverityBreakdown.jsx";
import { formatDate } from "../lib/lib.js";

function downloadJson(scan) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `codesentinel-${scan.filename}-${scan.scan_id.slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ScanResults({ scanId }) {
  const [state, setState] = useState({ status: "loading", scan: null, error: "" });
  const [selected, setSelected] = useState(null);
  const close = useCallback(() => setSelected(null), []);

  useEffect(() => {
    let active = true;
    getScan(scanId)
      .then((scan) => active && setState({ status: "ready", scan, error: "" }))
      .catch((e) => active && setState({ status: "error", scan: null, error: e.message }));
    return () => { active = false; };
  }, [scanId]);

  if (state.status === "loading") return <p className="text-sm text-slate-500">Loading scan...</p>;
  if (state.status === "error") {
    return (
      <div>
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">{state.error}</div>
        <a href="#/" className="mt-4 inline-block text-sm font-medium text-slate-700 hover:underline">Back to dashboard</a>
      </div>
    );
  }

  const { scan } = state;
  return (
    <div>
      <a href="#/" className="text-sm text-slate-500 hover:underline">&larr; Dashboard</a>
      <div className="mb-6 mt-2 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">{scan.filename}</h1>
          <p className="text-sm text-slate-500">
            {formatDate(scan.created_at)} &middot; {scan.files_scanned} file{scan.files_scanned === 1 ? "" : "s"} scanned &middot; {scan.duration_seconds}s
          </p>
          <p className="mt-2 flex flex-wrap gap-2">
            {scan.scanners_run.map((t) => (
              <span key={t} className="rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">{t}</span>
            ))}
          </p>
        </div>
        <div className="flex gap-2">
          <button type="button" onClick={() => downloadJson(scan)} className="rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50">
            Download JSON
          </button>
          <a href="#/scan" className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700">New scan</a>
        </div>
      </div>

      {scan.scanner_errors.length > 0 && (
        <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900" role="alert" data-testid="scanner-errors">
          <p className="font-semibold">Some scanners did not run, so this result may be incomplete.</p>
          <ul className="mt-1 list-disc pl-5">
            {scan.scanner_errors.map((e) => <li key={e.tool}><b>{e.tool}</b>: {e.message}</li>)}
          </ul>
        </div>
      )}
      {scan.warnings.length > 0 && (
        <div className="mb-4 rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
          <ul className="list-disc pl-5">{scan.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <section className="flex flex-col items-center justify-center rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
          <ScoreGauge score={scan.score} rating={scan.rating} />
          <div className="mt-4 flex items-center gap-2 text-sm text-slate-600" data-testid="gate">
            Quality gate <GateBadge gate={scan.gate} />
          </div>
          <p className="mt-1 text-xs text-slate-500">Passes at {scan.threshold} or higher</p>
        </section>
        <section className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm lg:col-span-2">
          <h2 className="mb-4 text-lg font-semibold text-slate-900">
            {scan.summary.total} finding{scan.summary.total === 1 ? "" : "s"}
          </h2>
          <SeverityBreakdown summary={scan.summary} />
        </section>
      </div>

      <h2 className="mb-3 mt-8 text-lg font-semibold text-slate-900">Findings</h2>
      <FindingsTable findings={scan.findings} onSelect={setSelected} selectedId={selected && selected.id} />
      <FindingDrawer finding={selected} onClose={close} />
    </div>
  );
}
