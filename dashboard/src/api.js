// API client for the CodeSentinal. v2 portal. Same-origin via Nginx. Carries the
// signed superadmin session token on every call (Authorization header only).

const TOKEN_KEY = 'CodeSentinal._token'
export function getToken() { try { return localStorage.getItem(TOKEN_KEY) || '' } catch { return '' } }
export function setToken(t) { try { localStorage.setItem(TOKEN_KEY, t) } catch {} }
export function clearToken() { try { localStorage.removeItem(TOKEN_KEY) } catch {} }

async function req(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  const tok = getToken()
  if (tok) headers['Authorization'] = 'Bearer ' + tok
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined })
  if (res.status === 401) { clearToken(); const e = new Error('unauthorized'); e.unauthorized = true; throw e }
  if (res.status === 429) { const e = new Error('Too many attempts, try again shortly'); e.throttled = true; throw e }
  if (!res.ok) {
    let msg = `${method} ${path} -> ${res.status}`
    try { const j = await res.json(); if (j.error) msg = j.error } catch {}
    throw new Error(msg)
  }
  const ct = res.headers.get('content-type') || ''
  return ct.includes('application/json') ? res.json() : res.text()
}

// Download a report/export as a Blob using the Authorization header.
export async function download(path, filename) {
  const headers = {}
  const tok = getToken()
  if (tok) headers['Authorization'] = 'Bearer ' + tok
  const res = await fetch(path, { headers })
  if (!res.ok) throw new Error('download failed: ' + res.status)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click(); a.remove()
  URL.revokeObjectURL(url)
}

export const api = {
  meta: () => req('GET', '/api/v1/meta'),
  authStatus: () => req('GET', '/api/v1/auth/status'),
  login: (password) => req('POST', '/api/v1/auth/login', { password }),

  overview: () => req('GET', '/api/v1/overview'),
  review: () => req('POST', '/api/v1/review'),
  reviews: () => req('GET', '/api/v1/reviews'),
  services: () => req('GET', '/api/v1/services'),
  regions: () => req('GET', '/api/v1/regions'),
  resources: (service, region, type) => {
    const q = new URLSearchParams()
    if (service) q.set('service', service)
    if (region) q.set('region', region)
    if (type) q.set('type', type)
    return req('GET', '/api/v1/resources?' + q.toString())
  },
  resource: (id) => req('GET', '/api/v1/resource?id=' + encodeURIComponent(id)),
  findings: (params = {}) => {
    const q = new URLSearchParams(params)
    return req('GET', '/api/v1/findings?' + q.toString())
  },
  finding: (id) => req('GET', '/api/v1/finding?id=' + encodeURIComponent(id)),
  savePlan: (id, owner, effort, due_date) => req('PUT', '/api/v1/finding/plan', { id, owner, effort, due_date }),
  paths: () => req('GET', '/api/v1/paths'),
  history: () => req('GET', '/api/v1/history'),
  risks: () => req('GET', '/api/v1/risks'),
  acceptRisk: (fingerprint, reason, owner, expires_at) => req('POST', '/api/v1/risks', { fingerprint, reason, owner, expires_at }),
  revokeRisk: (fp) => req('DELETE', '/api/v1/risks?fingerprint=' + encodeURIComponent(fp)),
  audit: (service, resource) => {
    const q = new URLSearchParams()
    if (service) q.set('service', service)
    if (resource) q.set('resource', resource)
    return req('POST', '/api/v1/audit?' + q.toString())
  },
  deepScan: () => req('POST', '/api/v1/scans/deep'),
  deepScanStatus: (id) => req('GET', '/api/v1/scans/' + encodeURIComponent(id)),
  reportsList: () => req('GET', '/api/v1/reports'),
  createReport: (scope, service, resource) => req('POST', '/api/v1/reports', { scope, service, resource }),
  report: (id) => req('GET', '/api/v1/reports/' + encodeURIComponent(id)),
  reportTransition: (id, action, note, reviewer) => req('POST', `/api/v1/reports/${encodeURIComponent(id)}/${action}`, { note, reviewer }),
  activity: () => req('GET', '/api/v1/activity'),
  settings: () => req('GET', '/api/v1/settings'),
  saveSettings: (s) => req('PUT', '/api/v1/settings', s),
  integrations: () => req('GET', '/api/v1/integrations'),
}
