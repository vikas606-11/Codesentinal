import React, { useEffect, useState } from 'react'
import { api, getToken, setToken, clearToken } from './api.js'
import * as I from './icons.jsx'
import Login from './views/Login.jsx'
import Overview from './views/Overview.jsx'
import Findings from './views/Findings.jsx'
import Paths from './views/Paths.jsx'
import Inventory from './views/Inventory.jsx'
import ServicePage from './views/ServicePage.jsx'
import ResourcePage from './views/ResourcePage.jsx'
import Risks from './views/Risks.jsx'
import Reports from './views/Reports.jsx'
import Activity from './views/Activity.jsx'
import Settings from './views/Settings.jsx'

function parseHash() {
  const h = (window.location.hash || '#/').replace(/^#/, '')
  const parts = h.split('/').filter(Boolean)
  if (parts[0] === 'findings') return { view: 'findings' }
  if (parts[0] === 'paths') return { view: 'paths' }
  if (parts[0] === 'inventory') return { view: 'inventory' }
  if (parts[0] === 'service') return { view: 'service', key: decodeURIComponent(parts[1] || '') }
  if (parts[0] === 'resource') return { view: 'resource', id: decodeURIComponent(parts.slice(1).join('/')) }
  if (parts[0] === 'risks') return { view: 'risks' }
  if (parts[0] === 'reports') return { view: 'reports' }
  if (parts[0] === 'activity') return { view: 'activity' }
  if (parts[0] === 'settings') return { view: 'settings' }
  return { view: 'overview' }
}
export function navigate(h) { window.location.hash = h }

const NAV = [
  ['overview', 'Overview', I.IconOverview, '#/'],
  ['findings', 'Findings', I.IconFindings, '#/findings'],
  ['paths', 'Attack paths', I.IconPath, '#/paths'],
  ['inventory', 'Inventory', I.IconInventory, '#/inventory'],
  ['risks', 'Risks', I.IconShield, '#/risks'],
  ['reports', 'Reports', I.IconFile, '#/reports'],
  ['activity', 'Activity', I.IconClock, '#/activity'],
  ['settings', 'Settings', I.IconSettings, '#/settings'],
]

export default function App() {
  const [meta, setMeta] = useState(null)
  const [authed, setAuthed] = useState(!!getToken())
  const [route, setRoute] = useState(parseHash())
  const [booting, setBooting] = useState(true)
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('CodeSentinal._theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') } catch { return 'light' }
  })
  const [branding, setBranding] = useState({ msp_name: '', client_name: '' })

  useEffect(() => { document.documentElement.setAttribute('data-theme', theme); try { localStorage.setItem('CodeSentinal._theme', theme) } catch {} }, [theme])
  useEffect(() => { const f = () => setRoute(parseHash()); addEventListener('hashchange', f); return () => removeEventListener('hashchange', f) }, [])
  useEffect(() => {
    api.meta().then(m => { setMeta(m); if (!m.auth_required) setAuthed(true) }).catch(() => {}).finally(() => setBooting(false))
  }, [])
  useEffect(() => { if (authed) api.settings().then(s => setBranding(s.branding || {})).catch(() => {}) }, [authed])

  if (booting) return <div className="empty">Loading CodeSentinal.…</div>
  if (meta?.auth_required && !authed) return <Login onLogin={t => { setToken(t); setAuthed(true) }} />

  const active = route.view === 'service' || route.view === 'resource' ? 'inventory' : route.view
  const insecure = meta && !meta.demo && !meta.auth_required

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="logo">◆</span> CodeSentinal.</div>
        <nav className="nav">
          {NAV.map(([key, label, Icon, href]) => (
            <a key={key} className={active === key ? 'active' : ''} onClick={() => navigate(href)} aria-current={active === key ? 'page' : undefined}>
              <Icon /> {label}
            </a>
          ))}
        </nav>
      </aside>
      <div className="main">
        <header className="topbar">
          <div>
            <span className="org">{branding.msp_name || 'CodeSentinal.'}</span>
            {branding.client_name && <span className="client">· {branding.client_name}</span>}
          </div>
          <div className="spacer" />
          <button className="btn ghost" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle theme">
            {theme === 'dark' ? '☀' : '☾'}
          </button>
          {meta?.auth_required && <button className="btn ghost" onClick={() => { clearToken(); setAuthed(false); navigate('#/') }}>Sign out</button>}
        </header>
        <main className="content">
          {meta?.demo && <div className="banner demo">Demo data — not a real account</div>}
          {insecure && <div className="banner warn">Portal is running without authentication or HTTPS. Set a superadmin password and a certificate for production.</div>}
          {route.view === 'overview' && <Overview meta={meta} />}
          {route.view === 'findings' && <Findings />}
          {route.view === 'paths' && <Paths />}
          {route.view === 'inventory' && <Inventory />}
          {route.view === 'service' && <ServicePage serviceKey={route.key} />}
          {route.view === 'resource' && <ResourcePage resourceId={route.id} />}
          {route.view === 'risks' && <Risks />}
          {route.view === 'reports' && <Reports />}
          {route.view === 'activity' && <Activity />}
          {route.view === 'settings' && <Settings meta={meta} />}
        </main>
      </div>
    </div>
  )
}
