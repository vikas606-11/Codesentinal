import React, { useState } from 'react'
import { api } from '../api.js'

export default function Login({ onLogin }) {
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e) {
    e.preventDefault(); setBusy(true); setErr('')
    try { const { token } = await api.login(password); onLogin(token) }
    catch (e) { setErr(e.throttled ? e.message : 'Invalid password') }
    finally { setBusy(false) }
  }

  return (
    <div className="login-wrap">
      <form className="login" onSubmit={submit}>
        <div className="brand" style={{ fontSize: 26, padding: 0, marginBottom: 8 }}><span className="logo">◆</span> CodeSentinal.</div>
        <p className="muted">Sign in as superadmin.</p>
        <input type="password" placeholder="Superadmin password" value={password} autoFocus onChange={e => setPassword(e.target.value)} aria-label="Superadmin password" />
        {err && <div className="banner error">{err}</div>}
        <button className="btn primary" type="submit" disabled={busy || !password}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </div>
  )
}
