import { useEffect, useState } from "react";
import { listScans } from "../api.js";
import ScanHistoryTable from "../components/ScanHistoryTable.jsx";
import StatCard from "../components/StatCard.jsx";
import { scoreColor } from "../lib/lib.js";

function Trend({ scans }) {
  const recent = scans.slice(0, 10).reverse(); // oldest to newest
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm">
      <p className="text-sm text-slate-500">Score trend (last {recent.length} scans)</p>
      <div className="mt-3 flex h-24 items-end gap-2" role="img" aria-label="Score trend">
        {recent.map((s) => (
          <div key={s.scan_id} title={`${s.filename}: ${s.score}`} className="flex-1 rounded-t"
            style={{ height: `${Math.max(s.score, 2)}%`, backgroundColor: scoreColor(s.score) }} />
        ))}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [state, setState] = useState({ status: "loading", scans: [], error: "" });

  useEffect(() => {
    let active = true;
    listScans(100)
      .then((scans) => active && setState({ status: "ready", scans, error: "" }))
      .catch((e) => active && setState({ status: "error", scans: [], error: e.message }));
    return () => { active = false; };
  }, []);

  const { status, scans, error } = state;
  const passed = scans.filter((s) => s.gate === "PASS").length;
  const average = scans.length ? Math.round(scans.reduce((n, s) => n + s.score, 0) / scans.length) : 0;

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Dashboard</h1>
          <p className="text-sm text-slate-500">Security and quality scans of your code.</p>
        </div>
        <a href="#/scan" className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700">New scan</a>
      </div>

      {status === "loading" && <p className="text-sm text-slate-500">Loading scans...</p>}
      {status === "error" && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">{error}</div>
      )}

      {status === "ready" && scans.length === 0 && (
        <div className="rounded-lg border border-dashed border-slate-300 bg-white p-10 text-center">
          <p className="font-medium text-slate-900">No scans yet</p>
          <p className="mt-1 text-sm text-slate-500">Upload a Python file or a zip of a project to get started.</p>
          <a href="#/scan" className="mt-4 inline-block rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700">Run your first scan</a>
        </div>
      )}

      {status === "ready" && scans.length > 0 && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Total scans" value={scans.length} />
            <StatCard label="Pass rate" value={`${Math.round((passed / scans.length) * 100)}%`} hint={`${passed} of ${scans.length} passed the gate`} />
            <StatCard label="Average score" value={average} hint="out of 100" />
            <StatCard label="Latest score" value={scans[0].score} hint={`${scans[0].filename} (${scans[0].gate})`} />
          </div>
          <div className="mt-4"><Trend scans={scans} /></div>
          <h2 className="mb-3 mt-8 text-lg font-semibold text-slate-900">Recent scans</h2>
          <ScanHistoryTable scans={scans} />
        </>
      )}
    </div>
  );
}
