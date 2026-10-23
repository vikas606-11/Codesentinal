import { useEffect, useRef, useState } from "react";
import { createScan } from "../api.js";
import { navigate } from "../lib/router.js";

const MAX_MB = 20;
const SLOW_AFTER_SECONDS = 45;

function validate(file) {
  const name = file.name.toLowerCase();
  if (!name.endsWith(".py") && !name.endsWith(".zip")) return "Only a .py file or a .zip archive is supported.";
  if (file.size === 0) return "The file is empty.";
  if (file.size > MAX_MB * 1024 * 1024) return `The file is larger than ${MAX_MB} MB.`;
  return "";
}

function formatSize(bytes) {
  return bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function NewScan() {
  const [file, setFile] = useState(null);
  const [error, setError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [dragging, setDragging] = useState(false);
  const mounted = useRef(true);
  const input = useRef(null);
  const controller = useRef(null);

  // Set to true on every mount: React StrictMode runs the cleanup once during development, which
  // would otherwise leave this false for good and stop the page from ever leaving the scanning screen.
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  useEffect(() => {
    if (!scanning) return undefined;
    const id = setInterval(() => setElapsed((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [scanning]);

  const choose = (f) => {
    if (!f) return;
    const problem = validate(f);
    setError(problem);
    setFile(problem ? null : f);
  };

  const start = async () => {
    if (!file) return;
    setError("");
    setElapsed(0);
    setScanning(true);
    controller.current = new AbortController();
    try {
      const result = await createScan(file, controller.current.signal);
      if (mounted.current) navigate(`/scans/${result.scan_id}`);
    } catch (e) {
      if (mounted.current) {
        setError(e.message);
        setScanning(false);
      }
    }
  };

  const stopWaiting = () => controller.current && controller.current.abort();

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="text-2xl font-semibold tracking-tight text-slate-900">New scan</h1>
      <p className="mb-6 text-sm text-slate-500">Upload a Python file or a zip of a project. It is scanned for vulnerabilities, secrets, and risky dependencies.</p>

      {scanning ? (
        <div className="rounded-lg border border-slate-200 bg-white p-8 text-center shadow-sm" role="status" aria-live="polite">
          <p className="font-medium text-slate-900">Scanning {file && file.name}</p>
          <p className="mt-1 text-sm text-slate-500">Semgrep (code), Gitleaks (secrets) and Trivy (dependencies) are running.</p>
          <div className="relative mx-auto mt-5 h-2 w-full max-w-sm overflow-hidden rounded-full bg-slate-100">
            <div className="absolute inset-y-0 w-1/3 animate-pulse rounded-full bg-slate-900" />
          </div>
          <p className="mt-3 text-sm text-slate-500">{elapsed}s elapsed. Larger projects take longer.</p>
          {elapsed >= SLOW_AFTER_SECONDS && (
            <p className="mx-auto mt-3 max-w-md rounded-md bg-amber-50 p-3 text-sm text-amber-900" data-testid="slow-hint">
              This is taking longer than usual. You can stop waiting and try again, or check the backend logs
              with <code>docker compose logs backend</code>.
            </p>
          )}
          <button type="button" onClick={stopWaiting}
            className="mt-5 rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50">
            Stop waiting
          </button>
        </div>
      ) : (
        <>
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); choose(e.dataTransfer.files[0]); }}
            className={`rounded-lg border-2 border-dashed p-10 text-center transition ${dragging ? "border-slate-900 bg-slate-100" : "border-slate-300 bg-white"}`}
          >
            <p className="text-sm text-slate-600">Drag a file here, or</p>
            <button type="button" onClick={() => input.current.click()}
              className="mt-3 rounded-md border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-800 hover:bg-slate-50">
              Choose a file
            </button>
            <input ref={input} type="file" accept=".py,.zip" data-testid="file-input" className="hidden" onChange={(e) => choose(e.target.files[0])} />
            <p className="mt-3 text-xs text-slate-500">.py or .zip, up to {MAX_MB} MB</p>
          </div>

          {file && (
            <div className="mt-4 flex items-center justify-between rounded-lg border border-slate-200 bg-white px-4 py-3 text-sm">
              <span className="font-medium text-slate-900">{file.name}</span>
              <span className="text-slate-500">{formatSize(file.size)}</span>
            </div>
          )}

          {error && <div className="mt-4 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800" role="alert">{error}</div>}

          <button type="button" onClick={start} disabled={!file}
            className="mt-6 rounded-md bg-slate-900 px-5 py-2.5 text-sm font-medium text-white hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40">
            Start scan
          </button>
        </>
      )}
    </div>
  );
}
