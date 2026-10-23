import { useEffect, useState } from "react";
import { API_URL, getHealth } from "./api.js";
import { useRoute } from "./lib/router.js";
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import ScanResults from "./pages/ScanResults.jsx";

function ApiStatus() {
  const [status, setStatus] = useState("loading");
  useEffect(() => {
    let active = true;
    getHealth().then(() => active && setStatus("online")).catch(() => active && setStatus("offline"));
    return () => { active = false; };
  }, []);
  const dot = { loading: "bg-amber-400", online: "bg-emerald-400", offline: "bg-red-500" }[status];
  return (
    <span className="flex items-center gap-2 text-xs text-slate-300" title={API_URL}>
      <span className={`h-2 w-2 rounded-full ${dot}`} />
      API {status}
    </span>
  );
}

function NavLink({ href, active, children }) {
  return (
    <a href={href} className={`rounded-md px-3 py-1.5 text-sm font-medium ${active ? "bg-slate-700 text-white" : "text-slate-300 hover:text-white"}`}>
      {children}
    </a>
  );
}

export default function App() {
  const path = useRoute();
  const results = path.match(/^\/scans\/([A-Za-z0-9]+)$/);

  let page;
  if (path === "/") page = <Dashboard />;
  else if (path === "/scan") page = <NewScan />;
  else if (results) page = <ScanResults key={results[1]} scanId={results[1]} />;
  else page = (
    <div className="text-center">
      <h1 className="text-xl font-semibold text-slate-900">Page not found</h1>
      <a href="#/" className="mt-3 inline-block text-sm text-slate-700 hover:underline">Back to dashboard</a>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="bg-slate-900">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-6">
            <a href="#/" className="flex items-center gap-2 text-lg font-semibold tracking-tight text-white">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z" /><path d="M9 12l2 2 4-4" />
              </svg>
              CodeSentinel
            </a>
            <nav className="flex gap-1">
              <NavLink href="#/" active={path === "/" || path.startsWith("/scans/")}>Dashboard</NavLink>
              <NavLink href="#/scan" active={path === "/scan"}>New scan</NavLink>
            </nav>
          </div>
          <ApiStatus />
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">{page}</main>
    </div>
  );
}
