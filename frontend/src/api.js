export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

function errorMessage(body, status) {
  const d = body && body.detail;
  if (typeof d === "string") return d;
  if (d && d.message) {
    const extra = (d.scanner_errors || []).map((e) => `${e.tool}: ${e.message}`).join(" | ");
    return extra ? `${d.message} ${extra}` : d.message;
  }
  if (Array.isArray(d) && d[0] && d[0].msg) return d[0].msg;
  return `Request failed (${status})`;
}

async function request(path, options = {}) {
  let res;
  try {
    res = await fetch(`${API_URL}${path}`, options);
  } catch (e) {
    if (e && e.name === "AbortError") throw new Error("Stopped waiting. The scan may still finish on the server and appear on the dashboard.");
    throw new Error(`Cannot reach the backend at ${API_URL}. Is it running?`);
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* no JSON body */
  }
  if (!res.ok) {
    const err = new Error(errorMessage(body, res.status));
    err.status = res.status;
    throw err;
  }
  return body;
}

export const getHealth = () => request("/api/v1/health");
export const listScans = (limit = 100) => request(`/api/v1/scans?limit=${limit}`);
export const getScan = (id) => request(`/api/v1/scans/${encodeURIComponent(id)}`);

export function createScan(file, signal) {
  const form = new FormData();
  form.append("file", file);
  return request("/api/v1/scan", { method: "POST", body: form, signal });
}

export const explainFinding = (findingId, refresh = false) =>
  request(`/api/v1/findings/${encodeURIComponent(findingId)}/explain${refresh ? "?refresh=true" : ""}`, { method: "POST" });

// The saved explanation, or null when there is none yet
export async function getExplanation(findingId) {
  try {
    return await request(`/api/v1/findings/${encodeURIComponent(findingId)}/explanation`);
  } catch (e) {
    if (e.status === 404) return null;
    throw e;
  }
}
